use chrono::Utc;
use rand::Rng;
use serde_json;

// Include the same data structures from main.rs
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct CSRSigningRequest {
    common_name: String,
    hosts: Vec<String>,
    key: KeyInfo,
    names: Vec<NameInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifetime: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct KeyInfo {
    algo: String,
    size: u32,
}

#[derive(Serialize, Deserialize)]
struct NameInfo {
    #[serde(rename = "C")]
    country: String, // Renamed to avoid warning
    #[serde(rename = "L")]
    locality: String, // Renamed to avoid warning
    #[serde(rename = "O")]
    organization: String, // Renamed to avoid warning
    #[serde(rename = "OU")]
    organizational_unit: String, // Renamed to avoid warning
    #[serde(rename = "ST")]
    state: String, // Renamed to avoid warning
}

#[derive(Serialize, Deserialize)]
struct InvoiceSubmissionRequest {
    invoice_number: String,
    invoice_date: String,
    customer: CustomerInfo,
    items: Vec<InvoiceItem>,
    total_amount: f64,
    currency: String,
    due_date: String,
}

#[derive(Serialize, Deserialize)]
struct CustomerInfo {
    customer_id: String,
    name: String,
    email: String,
    billing_address: AddressInfo,
}

#[derive(Serialize, Deserialize)]
struct InvoiceItem {
    item_id: String,
    description: String,
    quantity: u32,
    unit_price: f64,
    total_price: f64,
    tax_rate: f64,
}

#[derive(Serialize, Deserialize)]
struct AddressInfo {
    street: String,
    city: String,
    state: String,
    postal_code: String,
    country: String,
}

fn main() {
    println!("=== CSR Signing Request Payload ===");
    let csr_payload = generate_csr_payload();
    let csr_json = serde_json::to_string_pretty(&csr_payload).unwrap();
    println!("{}", csr_json);

    println!("\n=== Invoice Submission Request Payload ===");
    let invoice_payload = generate_invoice_payload();
    let invoice_json = serde_json::to_string_pretty(&invoice_payload).unwrap();
    println!("{}", invoice_json);
}

fn generate_csr_payload() -> CSRSigningRequest {
    let domains = vec![
        "example.com".to_string(),
        "api.example.com".to_string(),
        "www.example.com".to_string(),
        "secure.example.com".to_string(),
        "cdn.example.com".to_string(),
    ];

    CSRSigningRequest {
        common_name: "api.example.com".to_string(),
        hosts: domains,
        key: KeyInfo {
            algo: "rsa".to_string(),
            size: 2048,
        },
        names: vec![NameInfo {
            country: "US".to_string(),
            locality: "San Francisco".to_string(),
            organization: "Example Corp".to_string(),
            organizational_unit: "IT Department".to_string(),
            state: "California".to_string(),
        }],
        lifetime: Some(365),
    }
}

fn generate_invoice_payload() -> InvoiceSubmissionRequest {
    InvoiceSubmissionRequest {
        invoice_number: format!(
            "INV-{}-{:06}",
            Utc::now().format("%Y%m%d"),
            rand::thread_rng().gen_range(1..999999)
        ),
        invoice_date: Utc::now().format("%Y-%m-%d").to_string(),
        customer: CustomerInfo {
            customer_id: format!("CUST-{:04}", rand::thread_rng().gen_range(1..9999)),
            name: "Test Customer".to_string(),
            email: format!("test{}@example.com", rand::thread_rng().gen_range(1..999)),
            billing_address: AddressInfo {
                street: "123 Test St".to_string(),
                city: "Test City".to_string(),
                state: "CA".to_string(),
                postal_code: "90210".to_string(),
                country: "US".to_string(),
            },
        },
        items: vec![
            InvoiceItem {
                item_id: format!("ITEM-{:04}", rand::thread_rng().gen_range(1..9999)),
                description: "Professional Services".to_string(),
                quantity: 10,
                unit_price: 150.00,
                total_price: 1500.00,
                tax_rate: 8.5,
            },
            InvoiceItem {
                item_id: format!("ITEM-{:04}", rand::thread_rng().gen_range(1..9999)),
                description: "Software License".to_string(),
                quantity: 1,
                unit_price: 299.99,
                total_price: 299.99,
                tax_rate: 0.0,
            },
        ],
        total_amount: 1799.99,
        currency: "USD".to_string(),
        due_date: (Utc::now() + chrono::Duration::days(30))
            .format("%Y-%m-%d")
            .to_string(),
    }
}
