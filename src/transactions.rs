use base64::Engine;
use goose::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::debug;
use uuid::Uuid;

use crate::dto::{ClearanceResponse, QrVerifyRequest, UserSessionData};
use crate::generator::{generate_random_qr_data, generate_signed_ubl_invoice, CREDENTIALS_POOL};

static USER_INDEX_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn der_base64_to_pem(der_b64: &str) -> Option<String> {
    use openssl::x509::X509;

    if der_b64.contains("-----BEGIN") {
        return Some(der_b64.to_string());
    }

    let der = base64::engine::general_purpose::STANDARD.decode(der_b64).ok()?;
    let cert = X509::from_der(&der).ok()?;
    let pem = cert.to_pem().ok()?;
    String::from_utf8(pem).ok()
}

fn get_customer_tin(supplier_tin: &str) -> String {
    if supplier_tin == "100011" {
        "100021".to_string()
    } else {
        "100011".to_string()
    }
}

pub async fn health_check(user: &mut GooseUser) -> TransactionResult {
    let _goose_metrics = user.get("/health_check").await?;
    Ok(())
}

pub async fn onboard_and_enroll(user: &mut GooseUser) -> TransactionResult {
    if user.get_session_data::<UserSessionData>().is_some() {
        return Ok(());
    }

    let user_index = USER_INDEX_COUNTER.fetch_add(1, Ordering::SeqCst);
    
    let (private_key_pem, device_uuid, tin, certificate) = {
        let pool = CREDENTIALS_POOL.lock().unwrap();
        let cred = pool.get_entry(user_index);
        
        if let (Some(cert), Some(dev_uuid), Some(t)) = (&cred.certificate, &cred.device_uuid, &cred.tin) {
            debug!(user_index, tin = %t, "Using pre-enrolled credential");
            let cert_pem = der_base64_to_pem(cert);
            (cred.private_key_pem.clone(), dev_uuid.clone(), t.clone(), cert_pem)
        } else {
            debug!(user_index, "No pre-enrolled credential found");
            (String::new(), String::new(), String::new(), None)
        }
    };

    let session_data = UserSessionData {
        token: format!("{}:{}", tin, device_uuid),
        device_uuid,
        tin,
        certificate,
        private_key_pem: Some(private_key_pem),
        credential_index: Some(user_index),
        icv: 0,
        last_pih: None,
    };

    user.set_session_data(session_data);
    Ok(())
}

pub async fn submit_clearance(user: &mut GooseUser) -> TransactionResult {
    let sess_opt = user.get_session_data::<UserSessionData>().cloned();

    if sess_opt.is_none() {
        onboard_and_enroll(user).await?;
    }

    let sess = user.get_session_data::<UserSessionData>().cloned().unwrap();

    let (key, cert) = (
        sess.private_key_pem.clone().unwrap_or_default(),
        sess.certificate.clone(),
    );

    let icv = sess.icv;
    let pih = sess.last_pih.clone();

    let supplier_tin = sess.tin.clone();
    let customer_tin = get_customer_tin(&supplier_tin);

    let (invoice_xml, invoice_hash, next_icv) = generate_signed_ubl_invoice(
        &supplier_tin,
        &customer_tin,
        true,
        cert.as_deref(),
        Some(&key),
        icv,
        pih.as_deref(),
    );

    let invoice_b64 = base64::engine::general_purpose::STANDARD.encode(invoice_xml.as_bytes());

    let request_body = serde_json::json!({
        "uuid": Uuid::new_v4().to_string(),
        "invoice_hash": invoice_hash.clone(),
        "invoice": invoice_b64
    });

    let goose_request = GooseRequest::builder()
        .method(GooseMethod::Post)
        .path("/clear")
        .set_request_builder(
            user.get_request_builder(&GooseMethod::Post, "/clear")?
                .header("X-Sandbox-Mode", "true")
                .json(&request_body)
        )
        .build();

    let goose_metrics = user.request(goose_request).await?;

    let mut new_pih: Option<Vec<u8>> = None;
    let clearance_success = if let Ok(response) = goose_metrics.response {
        if response.status().as_u16() == 200 {
            if let Ok(json) = response.json::<ClearanceResponse>().await {
                json.success
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    if clearance_success {
        new_pih = Some(base64::engine::general_purpose::STANDARD.decode(&invoice_hash).ok().unwrap_or_default());
    }

    let sess = user.get_session_data::<UserSessionData>().cloned().unwrap();
    let mut updated = sess;
    updated.icv = next_icv;
    if let Some(pih) = new_pih {
        updated.last_pih = Some(pih);
    }
    user.set_session_data(updated);

    Ok(())
}

pub async fn submit_reporting(user: &mut GooseUser) -> TransactionResult {
    let sess_opt = user.get_session_data::<UserSessionData>().cloned();

    if sess_opt.is_none() {
        onboard_and_enroll(user).await?;
    }

    let sess = user.get_session_data::<UserSessionData>().cloned().unwrap();

    let (key, cert) = (
        sess.private_key_pem.clone().unwrap_or_default(),
        sess.certificate.clone(),
    );

    let icv = sess.icv;
    let pih = sess.last_pih.clone();

    let supplier_tin = sess.tin.clone();
    let customer_tin = get_customer_tin(&supplier_tin);

    let (invoice_xml, invoice_hash, next_icv) = generate_signed_ubl_invoice(
        &supplier_tin,
        &customer_tin,
        false,
        cert.as_deref(),
        Some(&key),
        icv,
        pih.as_deref(),
    );

    let invoice_b64 = base64::engine::general_purpose::STANDARD.encode(invoice_xml.as_bytes());

    let request_body = serde_json::json!({
        "uuid": Uuid::new_v4().to_string(),
        "invoice_hash": invoice_hash.clone(),
        "invoice": invoice_b64
    });

    let goose_request = GooseRequest::builder()
        .method(GooseMethod::Post)
        .path("/report")
        .set_request_builder(
            user.get_request_builder(&GooseMethod::Post, "/report")?
                .header("X-Sandbox-Mode", "true")
                .json(&request_body)
        )
        .build();

    let _goose_metrics = user.request(goose_request).await?;

    let sess = user.get_session_data::<UserSessionData>().cloned().unwrap();
    let mut updated = sess;
    updated.icv = next_icv;
    user.set_session_data(updated);

    Ok(())
}

pub async fn verify_qr(user: &mut GooseUser) -> TransactionResult {
    let qr_b64 = generate_random_qr_data();

    let request = QrVerifyRequest { qr_b64 };

    let _goose_metrics = user.post_json("/verify_qr", &request).await?;

    Ok(())
}
