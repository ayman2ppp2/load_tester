use std::sync::Arc;

use goose::prelude::*;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};

// EnrollDTO structure matching server expectation
#[derive(Serialize, Deserialize)]
struct EnrollDTO {
    csr: String,
}

// User session data to store CSR
// #[derive(Serialize, Deserialize)]
struct UserSessionData {
    csr: Arc<String>,
}

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        .register_scenario(
            scenario!("CSRAndInvoiceLoadTest")
                // Setup transaction - runs once per user at start
                .register_transaction(transaction!(setup_user_csr).set_on_start())
                // Weighted transactions - 50% health, 50% CSR
                .register_transaction(transaction!(health_check).set_weight(5)?)
                .register_transaction(transaction!(csr_signing_request).set_weight(5)?),
        )
        .execute()
        .await?;

    Ok(())
}
async fn health_check(user: &mut GooseUser) -> TransactionResult {
    let _goose_metrics = user.get("/health_check").await?;

    Ok(())
}
// Setup transaction - generates CSR once per user
async fn setup_user_csr(user: &mut GooseUser) -> TransactionResult {
    let enroll_dto = generate_csr_and_enroll_dto();
    let session_data = UserSessionData {
        csr: enroll_dto.csr.into(),
    };
    user.set_session_data(session_data);
    Ok(())
}

// CSR Signing Transaction - reuses cached CSR
async fn csr_signing_request(user: &mut GooseUser) -> TransactionResult {
    let session_data = user
        .get_session_data::<UserSessionData>()
        .expect("CSR not found in session data - setup_user_csr should have run first");
    let enroll_dto = EnrollDTO {
        csr: session_data.csr.to_string(),
    };
    let _goose_metrics = user.post_json("/enroll", &enroll_dto).await?;
    Ok(())
}

// Generate CSR in PEM format and create EnrollDTO
fn generate_csr_and_enroll_dto() -> EnrollDTO {
    use openssl::rand::rand_bytes;

    // Generate random hex string (6 bytes = 12 hex chars)
    let mut random_bytes = [0u8; 6];
    rand_bytes(&mut random_bytes).unwrap();
    let rand_hex = random_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Create subject string like the bash script
    let subject = format!(
        "/C=SD/ST=Khartoum/L=Khartoum/O=TestBusiness-{}/OU=Enrollment/CN=client-{}",
        rand_hex, rand_hex
    );

    // Generate RSA private key (2048 bits)
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    // Create CSR using the subject string
    let req = create_csr_from_subject(&subject, &pkey).unwrap();

    // Get CSR as PEM string
    let csr_pem = match req.to_pem() {
        Ok(pem_bytes) => match String::from_utf8(pem_bytes) {
            Ok(pem_string) => pem_string,
            Err(_) => {
                eprintln!("Failed to convert CSR PEM bytes to string");
                return EnrollDTO {
                    csr: "ERROR: Invalid PEM encoding".to_string(),
                };
            }
        },
        Err(e) => {
            eprintln!("Failed to generate CSR PEM: {}", e);
            return EnrollDTO {
                csr: format!("ERROR: CSR generation failed: {}", e),
            };
        }
    };

    EnrollDTO { csr: csr_pem }
}

// Helper function to create CSR from subject string
fn create_csr_from_subject(
    subject: &str,
    pkey: &PKey<openssl::pkey::Private>,
) -> Result<openssl::x509::X509Req, openssl::error::ErrorStack> {
    use openssl::hash::MessageDigest;
    use openssl::x509::X509ReqBuilder;

    // Parse subject string and create X509 name
    let name = parse_subject_string(subject)?;

    // Build CSR
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_version(2)?;
    req_builder.set_subject_name(&name)?;
    req_builder.set_pubkey(pkey)?;

    // Sign the CSR on the builder
    req_builder.sign(pkey, MessageDigest::sha256())?;

    Ok(req_builder.build())
}

// Parse subject string like "/C=SD/ST=Khartoum/L=Khartoum/O=TestBusiness-abc123/OU=Enrollment/CN=client-abc123"
fn parse_subject_string(
    subject: &str,
) -> Result<openssl::x509::X509Name, openssl::error::ErrorStack> {
    use openssl::x509::X509NameBuilder;

    let mut name_builder = X509NameBuilder::new()?;

    // Split by '/' and parse each component
    let components: Vec<&str> = subject.split('/').filter(|s| !s.is_empty()).collect();

    for component in components {
        if let Some((key, value)) = component.split_once('=') {
            match key {
                "C" => name_builder.append_entry_by_text("C", value)?,
                "ST" => name_builder.append_entry_by_text("ST", value)?,
                "L" => name_builder.append_entry_by_text("L", value)?,
                "O" => name_builder.append_entry_by_text("O", value)?,
                "OU" => name_builder.append_entry_by_text("OU", value)?,
                "CN" => name_builder.append_entry_by_text("CN", value)?,
                _ => {} // Skip unknown components
            }
        }
    }

    Ok(name_builder.build())
}
