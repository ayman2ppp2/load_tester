use reqwest::Client;
use std::error::Error;
use uuid::Uuid;

use crate::constants::VALID_TINS;
use crate::dto::{EnrollRequest, EnrollResponse, OnboardRequest, OnboardResponse};
use crate::generator::{generate_csr_for_pool_entry, get_credential_index, store_certificate, CREDENTIALS_POOL};

pub async fn pre_enroll_user(
    client: &Client,
    host: &str,
    user_index: usize,
) -> Result<usize, Box<dyn Error + Send + Sync>> {
    let cred_index = get_credential_index();
    let private_key_pem = {
        let pool = CREDENTIALS_POOL.lock().unwrap();
        pool.get_entry(cred_index).private_key_pem.clone()
    };

    let device_uuid = Uuid::new_v4().to_string();
    let tin = VALID_TINS[user_index % VALID_TINS.len()].to_string();

    let csr_der_b64 = generate_csr_for_pool_entry(&device_uuid, &tin, &private_key_pem);

    let onboard_request = OnboardRequest {
        name: format!("Device {}", &device_uuid[..8]),
        email: format!("device-{}@test.com", &device_uuid[..8]),
        company_id: tin.clone(),
    };

    let response = client
        .post(format!("{}/onboard", host))
        .json(&onboard_request)
        .send()
        .await?;

    let onboard_response: OnboardResponse = response.json().await?;
    let token = onboard_response.token;

    let enroll_request = EnrollRequest {
        token: token.clone(),
        csr: csr_der_b64,
    };

    let response = client
        .post(format!("{}/enroll", host))
        .json(&enroll_request)
        .send()
        .await?;

    let enroll_response: EnrollResponse = response.json().await?;

    if enroll_response.success {
        if let Some(data) = enroll_response.data {
            store_certificate(cred_index, data.certificate);
        }
        Ok(cred_index)
    } else {
        Err(format!("Enrollment failed for user {}", user_index).into())
    }
}

pub async fn pre_enroll_all_users(host: &str, num_users: usize) -> Result<(), Box<dyn Error + Send + Sync>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;

    let mut handles = Vec::new();

    for i in 0..num_users {
        let host = host.to_string();
        let client = client.clone();
        let handle = tokio::spawn(async move {
            pre_enroll_user(&client, &host, i).await
        });
        handles.push(handle);
    }

    let mut failed_count = 0;
    for handle in handles {
        match handle.await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                eprintln!("User enrollment failed: {}", e);
                failed_count += 1;
            }
            Err(e) => {
                eprintln!("Task join error: {}", e);
                failed_count += 1;
            }
        }
    }

    if failed_count > 0 {
        return Err(format!("{} users failed to pre-enroll", failed_count).into());
    }

    Ok(())
}