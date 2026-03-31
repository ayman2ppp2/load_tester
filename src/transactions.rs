use base64::Engine;
use goose::prelude::*;
use rand::Rng;
use uuid::Uuid;

use crate::constants::VALID_TINS;
use crate::dto::{ClearanceResponse, EnrollRequest, EnrollResponse, OnboardRequest, OnboardResponse, QrVerifyRequest, UserSessionData};
use crate::generator::{generate_csr_for_pool_entry, generate_random_qr_data, generate_signed_ubl_invoice, get_credential_index, store_certificate, CREDENTIALS_POOL};

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

    let cred_index = get_credential_index();
    let private_key_pem = {
        let pool = CREDENTIALS_POOL.lock().unwrap();
        let cred = pool.get_entry(cred_index);
        cred.private_key_pem.clone()
    };

    let device_uuid = Uuid::new_v4().to_string();
    let tin = {
        let mut rng = rand::rng();
        VALID_TINS[rng.random_range(0..VALID_TINS.len())].to_string()
    };

    let csr_der_b64 = generate_csr_for_pool_entry(&device_uuid, &tin, &private_key_pem);

    let onboard_request = OnboardRequest {
        name: format!("Device {}", &device_uuid[..8]),
        email: format!("device-{}@test.com", &device_uuid[..8]),
        company_id: tin.clone(),
    };

    let response = user.post_json("/onboard", &onboard_request).await?;

    let token = match response.response {
        Ok(resp) => {
            match resp.json::<OnboardResponse>().await {
                Ok(json) => json.token,
                Err(_) => format!("{}:{}", tin, device_uuid),
            }
        }
        Err(_) => format!("{}:{}", tin, device_uuid),
    };

    let enroll_request = EnrollRequest {
        token: token.clone(),
        csr: csr_der_b64,
    };

    let response = user.post_json("/enroll", &enroll_request).await?;

    let certificate = match response.response {
        Ok(resp) => {
            match resp.json::<EnrollResponse>().await {
                Ok(json) => {
                    if json.success {
                        if let Some(ref data) = json.data {
                            let cert = der_base64_to_pem(&data.certificate);
                            if cert.is_some() {
                                store_certificate(cred_index, data.certificate.clone());
                            }
                            cert
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        }
        Err(_) => None,
    };

    let session_data = UserSessionData {
        token,
        device_uuid,
        tin: tin.clone(),
        certificate,
        private_key_pem: Some(private_key_pem),
        credential_index: Some(cred_index),
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

    let (key, cert): (String, Option<String>) = if let Some(cred_index) = sess.credential_index {
        let pool = CREDENTIALS_POOL.lock().unwrap();
        let cred = pool.get_entry(cred_index);
        (cred.private_key_pem.clone(), cred.certificate.clone())
    } else {
        (
            sess.private_key_pem.clone().unwrap_or_default(),
            sess.certificate.clone(),
        )
    };

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

    let (key, cert): (String, Option<String>) = if let Some(cred_index) = sess.credential_index {
        let pool = CREDENTIALS_POOL.lock().unwrap();
        let cred = pool.get_entry(cred_index);
        (cred.private_key_pem.clone(), cred.certificate.clone())
    } else {
        (
            sess.private_key_pem.clone().unwrap_or_default(),
            sess.certificate.clone(),
        )
    };

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