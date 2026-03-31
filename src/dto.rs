use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct OnboardRequest {
    pub name: String,
    pub email: String,
    #[serde(rename = "company_id")]
    pub company_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct OnboardResponse {
    pub message: String,
    pub token: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EnrollRequest {
    pub token: String,
    pub csr: String,
}

#[derive(Serialize, Deserialize)]
pub struct EnrollResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<EnrollData>,
}

#[derive(Serialize, Deserialize)]
pub struct EnrollData {
    pub certificate: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct QrVerifyRequest {
    #[serde(rename = "qr_b64")]
    pub qr_b64: String,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct UserSessionData {
    pub token: String,
    pub device_uuid: String,
    pub tin: String,
    pub certificate: Option<String>,
    pub private_key_pem: Option<String>,
    pub credential_index: Option<usize>,
    pub icv: i32,
    pub last_pih: Option<Vec<u8>>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct ClearanceResponse {
    pub success: bool,
}
