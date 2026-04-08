use base64::Engine;
use chrono::Utc;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509ReqBuilder;
use rand::Rng;
use tracing::debug;
use uuid::Uuid;

use crate::constants::VALID_TINS;

pub struct CredentialEntry {
    pub private_key_pem: String,
    pub certificate: Option<String>,
    // pub credential_index: Option<usize>,
    pub device_uuid: Option<String>,
    pub tin: Option<String>,
}

pub struct CredentialsPool {
    entries: Vec<CredentialEntry>,
    // next_index: std::sync::atomic::AtomicUsize,
}

impl CredentialsPool {
    pub fn new(num_users: usize) -> Self {
        let mut entries = Vec::with_capacity(num_users);
        for i in 0..num_users {
            let rsa = Rsa::generate(2048).unwrap();
            let pkey = PKey::from_rsa(rsa).unwrap();
            let private_key_pem = pkey.private_key_to_pem_pkcs8().unwrap();
            let private_key_pem_str = String::from_utf8(private_key_pem).unwrap();

            let device_uuid = Uuid::new_v4().to_string();
            let tin = VALID_TINS[i % VALID_TINS.len()].to_string();

            entries.push(CredentialEntry {
                private_key_pem: private_key_pem_str,
                certificate: None,
                // credential_index: Some(i),
                device_uuid: Some(device_uuid),
                tin: Some(tin),
            });
            if (i + 1) % 10 == 0 {
                eprintln!("Pre-generated {}/{} RSA key pairs", i + 1, num_users);
            }
        }
        eprintln!(
            "CredentialsPool initialized with {} RSA key pairs",
            num_users
        );

        Self {
            entries,
            // next_index: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    // pub fn get_credential(&self) -> usize {
    //     let idx = self
    //         .next_index
    //         .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    //     idx % self.entries.len()
    // }

    // pub fn store_certificate(&mut self, index: usize, certificate: String) {
    //     let idx = index % self.entries.len();
    //     self.entries[idx].certificate = Some(certificate);
    // }

    pub fn store_full_credential(
        &mut self,
        index: usize,
        certificate: String,
        device_uuid: String,
        tin: String,
    ) {
        let idx = index % self.entries.len();
        self.entries[idx].certificate = Some(certificate);
        self.entries[idx].device_uuid = Some(device_uuid);
        self.entries[idx].tin = Some(tin);
    }

    // pub fn get_entry_by_user(&self, user_index: usize) -> &CredentialEntry {
    //     &self.entries[user_index % self.entries.len()]
    // }

    pub fn get_entry(&self, index: usize) -> &CredentialEntry {
        &self.entries[index % self.entries.len()]
    }
}

pub static CREDENTIALS_POOL: std::sync::LazyLock<std::sync::Mutex<CredentialsPool>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(CredentialsPool::new(10)));

pub fn init_credentials_pool(num_users: usize) {
    let mut pool = CREDENTIALS_POOL.lock().unwrap();
    *pool = CredentialsPool::new(num_users);
}

// pub fn get_credential_index() -> usize {
//     CREDENTIALS_POOL.lock().unwrap().get_credential()
// }

// pub fn get_credential_index_for_user(user_index: usize) -> usize {
//     let pool = CREDENTIALS_POOL.lock().unwrap();
//     pool.get_entry_by_user(user_index)
//         .credential_index
//         .unwrap_or_else(|| user_index)
// }

// pub fn store_certificate(index: usize, certificate: String) {
//     CREDENTIALS_POOL
//         .lock()
//         .unwrap()
//         .store_certificate(index, certificate);
// }

pub fn store_full_credential(index: usize, certificate: String, device_uuid: String, tin: String) {
    CREDENTIALS_POOL
        .lock()
        .unwrap()
        .store_full_credential(index, certificate, device_uuid, tin);
}

// pub fn enroll_and_store(index: usize, certificate: String) {
//     let mut pool = CREDENTIALS_POOL.lock().unwrap();
//     let idx = index % pool.entries.len();
//     pool.entries[idx].certificate = Some(certificate);
// }

pub fn generate_csr_for_pool_entry(device_uuid: &str, tin: &str, private_key_pem: &str) -> String {
    let pkey = PKey::private_key_from_pem(private_key_pem.as_bytes()).unwrap();

    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("O", tin).unwrap();
    name_builder
        .append_entry_by_text("serialNumber", device_uuid)
        .unwrap();
    let name = name_builder.build();

    let mut req_builder = X509ReqBuilder::new().unwrap();
    req_builder.set_version(0).unwrap();
    req_builder.set_subject_name(&name).unwrap();
    req_builder.set_pubkey(&pkey).unwrap();
    req_builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let req = req_builder.build();
    let der = req.to_der().unwrap();
    base64::engine::general_purpose::STANDARD.encode(der)
}

pub fn generate_signed_ubl_invoice(
    supplier_tin: &str,
    customer_tin: &str,
    is_clearance: bool,
    certificate_b64: Option<&str>,
    private_key_pem: Option<&str>,
    icv: i32,
    previous_invoice_hash: Option<&[u8]>,
    uuid : Uuid,
) -> (String, String, i32) {
    if let (Some(cert_b64), Some(key_pem)) = (certificate_b64, private_key_pem) {
        return sign_invoice_template_based(
            supplier_tin,
            customer_tin,
            is_clearance,
            cert_b64,
            key_pem,
            icv,
            previous_invoice_hash,
            uuid,
        );
    }

    let unsigned_invoice = generate_ubl_invoice_unsigned(
        supplier_tin,
        customer_tin,
        is_clearance,
        icv,
        previous_invoice_hash,
        uuid
    );

    (unsigned_invoice.0, String::new(), unsigned_invoice.1)
}

fn generate_ubl_invoice_unsigned(
    supplier_tin: &str,
    customer_tin: &str,
    is_clearance: bool,
    icv: i32,
    previous_invoice_hash: Option<&[u8]>,
    uuid : Uuid,
) -> (String, i32) {
    let mut rng = rand::rng();
    let invoice_id = format!("INV-{}", rng.random_range(100000..999999));
    let uuid = uuid;
    let issue_date = Utc::now().format("%Y-%m-%d").to_string();
    let issue_time = Utc::now().format("%H:%M:%S").to_string();
    let quantity: f64 = rng.random_range(1.0..10.0);
    let unit_price: f64 = rng.random_range(10.0..500.0);
    let line_amount = quantity * unit_price;
    let tax_rate = 15.0;
    let tax_amount = line_amount * (tax_rate / 100.0);
    let payable_amount = line_amount + tax_amount;

    let next_icv = icv + 1;

    let profile_id = if is_clearance {
        "clearance:1.0"
    } else {
        "reporting:1.0"
    };

    let pih_hash = if let Some(pih) = previous_invoice_hash {
        base64::engine::general_purpose::STANDARD.encode(pih)
    } else {
        let empty_pih =
            hex::decode("5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9")
                .unwrap_or_else(|_| vec![0u8; 32]);
        base64::engine::general_purpose::STANDARD.encode(&empty_pih)
    };

    let qr_data: String = (0..100)
        .map(|_| {
            let idx = rng.random_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'A' + idx - 10) as char
            }
        })
        .collect();
    let qr_b64 = base64::engine::general_purpose::STANDARD.encode(qr_data.as_bytes());

    let invoice_body = format!(
        r##"<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
    xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
    xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
    xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
    <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
    <cbc:CustomizationID>1.0</cbc:CustomizationID>
    <cbc:ProfileID>{}</cbc:ProfileID>
    <cbc:ProfileExecutionID>1</cbc:ProfileExecutionID>
    <cbc:ID>{}</cbc:ID>
    <cbc:UUID>{}</cbc:UUID>
    <cbc:IssueDate>{}</cbc:IssueDate>
    <cbc:IssueTime>{}</cbc:IssueTime>
    <cbc:InvoiceTypeCode name="0100000">388</cbc:InvoiceTypeCode>
    <cbc:DocumentCurrencyCode>SDG</cbc:DocumentCurrencyCode>
    <cbc:TaxCurrencyCode>SDG</cbc:TaxCurrencyCode>
    <cac:AdditionalDocumentReference>
        <cbc:ID>ICV</cbc:ID>
        <cbc:UUID>{}</cbc:UUID>
    </cac:AdditionalDocumentReference>
    <cac:AdditionalDocumentReference>
        <cbc:ID>PIH</cbc:ID>
        <cac:Attachment>
            <cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">{}</cbc:EmbeddedDocumentBinaryObject>
        </cac:Attachment>
    </cac:AdditionalDocumentReference>
    <cac:AdditionalDocumentReference>
        <cbc:ID>QR</cbc:ID>
        <cac:Attachment>
            <cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">{}</cbc:EmbeddedDocumentBinaryObject>
        </cac:Attachment>
    </cac:AdditionalDocumentReference>
    <cac:AccountingSupplierParty>
        <cac:Party>
            <cac:PartyTaxScheme>
                <cbc:CompanyID>{}</cbc:CompanyID>
                <cac:TaxScheme>
                    <cbc:ID>VAT</cbc:ID>
                </cac:TaxScheme>
            </cac:PartyTaxScheme>
            <cac:PartyLegalEntity>
                <cbc:RegistrationName>Test Supplier</cbc:RegistrationName>
            </cac:PartyLegalEntity>
        </cac:Party>
    </cac:AccountingSupplierParty>
    <cac:AccountingCustomerParty>
        <cac:Party>
            <cac:PartyTaxScheme>
                <cbc:CompanyID>{}</cbc:CompanyID>
                <cac:TaxScheme>
                    <cbc:ID>VAT</cbc:ID>
                </cac:TaxScheme>
            </cac:PartyTaxScheme>
            <cac:PartyLegalEntity>
                <cbc:RegistrationName>Test Customer</cbc:RegistrationName>
            </cac:PartyLegalEntity>
        </cac:Party>
    </cac:AccountingCustomerParty>
    <cac:TaxTotal>
        <cbc:TaxAmount currencyID="SDG">{}</cbc:TaxAmount>
    </cac:TaxTotal>
    <cac:LegalMonetaryTotal>
        <cbc:LineExtensionAmount currencyID="SDG">{}</cbc:LineExtensionAmount>
        <cbc:TaxInclusiveAmount currencyID="SDG">{}</cbc:TaxInclusiveAmount>
        <cbc:PayableAmount currencyID="SDG">{}</cbc:PayableAmount>
    </cac:LegalMonetaryTotal>
    <cac:InvoiceLine>
        <cbc:ID>1</cbc:ID>
        <cbc:InvoicedQuantity unitCode="PCE">{}</cbc:InvoicedQuantity>
        <cbc:LineExtensionAmount currencyID="SDG">{}</cbc:LineExtensionAmount>
        <cac:TaxTotal>
            <cbc:TaxAmount currencyID="SDG">{}</cbc:TaxAmount>
        </cac:TaxTotal>
        <cac:Item>
            <cbc:Name>Test Item</cbc:Name>
        </cac:Item>
        <cac:Price>
            <cbc:PriceAmount currencyID="SDG">{}</cbc:PriceAmount>
        </cac:Price>
    </cac:InvoiceLine>
</Invoice>"##,
        profile_id,
        invoice_id,
        uuid,
        issue_date,
        issue_time,
        next_icv,
        pih_hash,
        qr_b64,
        supplier_tin,
        customer_tin,
        tax_amount,
        line_amount,
        payable_amount,
        payable_amount,
        quantity,
        line_amount,
        tax_amount,
        unit_price
    );

    (invoice_body, next_icv)
}

pub fn canonicalize_c14n11(xml: &str) -> String {
    use xml_c14n::{CanonicalizationMode, CanonicalizationOptions, canonicalize_xml};

    let options = CanonicalizationOptions {
        mode: CanonicalizationMode::Canonical1_1,
        keep_comments: false,
        inclusive_ns_prefixes: vec![],
    };

    match canonicalize_xml(xml, options) {
        Ok(canonical) => canonical,
        Err(_) => xml.to_string(),
    }
}

pub fn extract_invoice_for_signing(full_invoice_xml: &str) -> String {
    use quick_xml::Reader;
    use quick_xml::events::Event;
    use std::io::Cursor;

    #[derive(PartialEq)]
    enum State {
        OutsideInvoice,
        InInvoice,
        Skipping,
        InAdditionalDocRef,
        InAdditionalDocRefId,
    }

    let mut reader = Reader::from_reader(Cursor::new(full_invoice_xml.as_bytes()));
    reader.config_mut().trim_text(false);

    let mut output: Vec<u8> = Vec::new();
    let mut buf = Vec::new();
    let mut state = State::OutsideInvoice;
    let mut skip_depth = 0;
    let mut adr_depth = 0;
    let mut is_qr_reference = false;
    let mut adr_buffer: Vec<u8> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local_name = e.local_name();
                let name_str = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                match state {
                    State::OutsideInvoice => {
                        if name_str == "Invoice" {
                            state = State::InInvoice;
                            output.push(b'<');
                            output.extend_from_slice(e.as_ref());
                            output.push(b'>');
                        }
                    }
                    State::Skipping => {
                        skip_depth += 1;
                    }
                    State::InInvoice => {
                        if name_str == "UBLExtensions" || name_str == "Signature" {
                            state = State::Skipping;
                            skip_depth = 1;
                        } else if name_str == "AdditionalDocumentReference" {
                            state = State::InAdditionalDocRef;
                            adr_depth = 1;
                            is_qr_reference = false;
                            adr_buffer.clear();
                            adr_buffer.extend_from_slice(b"<");
                            adr_buffer.extend_from_slice(e.as_ref());
                            adr_buffer.extend_from_slice(b">");
                        } else {
                            output.push(b'<');
                            output.extend_from_slice(e.as_ref());
                            output.push(b'>');
                        }
                    }
                    State::InAdditionalDocRef | State::InAdditionalDocRefId => {
                        adr_depth += 1;
                        if name_str == "ID" && state == State::InAdditionalDocRef {
                            state = State::InAdditionalDocRefId;
                        }
                        adr_buffer.extend_from_slice(b"<");
                        adr_buffer.extend_from_slice(e.as_ref());
                        adr_buffer.extend_from_slice(b">");
                    }
                }
            }
            Ok(Event::Text(e)) => match state {
                State::Skipping | State::OutsideInvoice => {}
                State::InAdditionalDocRefId => {
                    if e.as_ref().trim_ascii() == b"QR" {
                        is_qr_reference = true;
                    }
                    adr_buffer.extend_from_slice(e.as_ref());
                }
                State::InAdditionalDocRef => {
                    adr_buffer.extend_from_slice(e.as_ref());
                }
                State::InInvoice => {
                    output.extend_from_slice(e.as_ref());
                }
            },
            Ok(Event::End(e)) => {
                // let local_name = e.local_name();
                // let name_str = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                match state {
                    State::OutsideInvoice => {}
                    State::Skipping => {
                        skip_depth -= 1;
                        if skip_depth == 0 {
                            state = State::InInvoice;
                        }
                    }
                    State::InAdditionalDocRefId | State::InAdditionalDocRef => {
                        adr_depth -= 1;
                        adr_buffer.extend_from_slice(b"</");
                        adr_buffer.extend_from_slice(e.as_ref());
                        adr_buffer.extend_from_slice(b">");

                        if state == State::InAdditionalDocRefId {
                            state = State::InAdditionalDocRef;
                        }

                        if adr_depth == 0 {
                            if !is_qr_reference {
                                output.extend_from_slice(&adr_buffer);
                            }
                            state = State::InInvoice;
                        }
                    }
                    State::InInvoice => {
                        output.extend_from_slice(b"</");
                        output.extend_from_slice(e.as_ref());
                        output.extend_from_slice(b">");
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                let name_str = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                match state {
                    State::OutsideInvoice | State::Skipping => {}
                    State::InInvoice => {
                        if name_str != "UBLExtensions" && name_str != "Signature" {
                            output.extend_from_slice(b"<");
                            output.extend_from_slice(e.as_ref());
                            output.extend_from_slice(b"/>");
                        }
                    }
                    _ => {
                        adr_buffer.extend_from_slice(b"<");
                        adr_buffer.extend_from_slice(e.as_ref());
                        adr_buffer.extend_from_slice(b"/>");
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(ev) => {
                if state == State::InInvoice {
                    output.extend_from_slice(ev.as_ref());
                } else if state == State::InAdditionalDocRef || state == State::InAdditionalDocRefId
                {
                    adr_buffer.extend_from_slice(ev.as_ref());
                }
            }
            Err(_) => break,
        }
        buf.clear();
    }

    String::from_utf8(output).expect("Invoice XML must be valid UTF-8")
}

pub fn sign_invoice_template_based(
    supplier_tin: &str,
    customer_tin: &str,
    is_clearance: bool,
    certificate_b64: &str,
    private_key_pem: &str,
    icv: i32,
    previous_invoice_hash: Option<&[u8]>,
    uuid : Uuid,
) -> (String, String, i32) {
    use openssl::sign::Signer;
    use openssl::x509::X509;
    use sha2::{Digest, Sha256};

    let mut rng = rand::rng();
    let invoice_id = format!("INV-{}", rng.random_range(100000..999999));
    let uuid = uuid;
    let issue_date = Utc::now().format("%Y-%m-%d").to_string();
    let issue_time = Utc::now().format("%H:%M:%S").to_string();
    let signing_time = Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    let quantity: f64 = rng.random_range(1.0..10.0);
    let unit_price: f64 = rng.random_range(10.0..500.0);
    let line_amount = quantity * unit_price;
    let tax_rate = 15.0;
    let tax_amount = line_amount * (tax_rate / 100.0);
    let payable_amount = line_amount + tax_amount;

    let next_icv = icv + 1;

    let profile_id = if is_clearance {
        "clearance:1.0"
    } else {
        "reporting:1.0"
    };

    let pih_hash = if let Some(pih) = previous_invoice_hash {
        base64::engine::general_purpose::STANDARD.encode(pih)
    } else {
        let empty_pih =
            hex::decode("5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9")
                .unwrap_or_else(|_| vec![0u8; 32]);
        base64::engine::general_purpose::STANDARD.encode(&empty_pih)
    };

    let qr_data: String = (0..100)
        .map(|_| {
            let idx = rng.random_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'A' + idx - 10) as char
            }
        })
        .collect();
    let qr_b64 = base64::engine::general_purpose::STANDARD.encode(qr_data.as_bytes());

    let full_invoice = build_to_sign_content(
        profile_id,
        &invoice_id,
        &uuid.to_string(),
        &issue_date,
        &issue_time,
        next_icv,
        &pih_hash,
        &qr_b64,
        supplier_tin,
        customer_tin,
        format!("{:.2}", tax_amount).as_str(),
        format!("{:.2}", line_amount).as_str(),
        format!("{:.2}", payable_amount).as_str(),
        format!("{:.3}", quantity).as_str(),
        format!("{:.2}", unit_price).as_str(),
    );

    let to_sign_content = extract_invoice_for_signing(&full_invoice);
    let canonical = canonicalize_c14n11(&to_sign_content);

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let invoice_hash = hasher.finalize();
    let invoice_hash_b64 = base64::engine::general_purpose::STANDARD.encode(invoice_hash);

    let pkey = PKey::private_key_from_pem(private_key_pem.as_bytes()).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.update(canonical.as_bytes()).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

    let cert_valid = certificate_b64.starts_with("-----BEGIN");
    debug!(
        cert_len = certificate_b64.len(),
        has_pem_header = cert_valid,
        "Parsing certificate for signing"
    );
    let cert = X509::from_pem(certificate_b64.as_bytes()).ok();
    debug!(cert_parsed = cert.is_some(), "Certificate parse result");

    let (cert_digest_b64, cert_der_b64, issuer_serial) = if let Some(cert) = &cert {
        let cert_der = cert.to_der().unwrap_or_default();
        let mut cert_hasher = Sha256::new();
        cert_hasher.update(&cert_der);
        let cert_digest = cert_hasher.finalize();
        let cert_digest_b64 = base64::engine::general_purpose::STANDARD.encode(cert_digest);
        let cert_der_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);
        let serial_bn = cert
            .serial_number()
            .to_bn()
            .unwrap_or_else(|_| openssl::bn::BigNum::new().unwrap());
        let serial_bytes = serial_bn.to_vec();
        let mut lower_bytes: Vec<u8> = serial_bytes.iter().rev().take(8).cloned().collect();
        lower_bytes.reverse();
        let lower_int: u64 = lower_bytes
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | (b as u64));
        let serial_str = lower_int.to_string();
        (cert_digest_b64, cert_der_b64, serial_str)
    } else {
        let dummy_digest = Sha256::digest(b"dummy");
        let dummy_digest_b64 = base64::engine::general_purpose::STANDARD.encode(dummy_digest);
        (dummy_digest_b64, String::new(), "1".to_string())
    };

    let signed_invoice = build_signed_invoice(
        profile_id,
        &invoice_id,
        &uuid.to_string(),
        &issue_date,
        &issue_time,
        next_icv,
        &pih_hash,
        &qr_b64,
        supplier_tin,
        customer_tin,
        format!("{:.2}", tax_amount).as_str(),
        format!("{:.2}", line_amount).as_str(),
        format!("{:.2}", payable_amount).as_str(),
        format!("{:.3}", quantity).as_str(),
        format!("{:.2}", unit_price).as_str(),
        &invoice_hash_b64,
        &signature_b64,
        &cert_der_b64,
        &signing_time,
        &cert_digest_b64,
        &issuer_serial,
    );

    (signed_invoice, invoice_hash_b64, next_icv)
}

fn build_to_sign_content(
    profile_id: &str,
    invoice_id: &str,
    uuid: &str,
    issue_date: &str,
    issue_time: &str,
    icv: i32,
    pih_hash: &str,
    qr_b64: &str,
    supplier_tin: &str,
    customer_tin: &str,
    tax_amount: &str,
    line_amount: &str,
    payable_amount: &str,
    quantity: &str,
    unit_price: &str,
) -> String {
    let ns = r#"xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2""#;

    format!(
        r#"<Invoice {ns}><ext:UBLExtensions></ext:UBLExtensions><cbc:UBLVersionID>2.1</cbc:UBLVersionID><cbc:CustomizationID>1.0</cbc:CustomizationID><cbc:ProfileID>{profile_id}</cbc:ProfileID><cbc:ProfileExecutionID>1</cbc:ProfileExecutionID><cbc:ID>{invoice_id}</cbc:ID><cbc:UUID>{uuid}</cbc:UUID><cbc:IssueDate>{issue_date}</cbc:IssueDate><cbc:IssueTime>{issue_time}</cbc:IssueTime><cbc:InvoiceTypeCode name="0100000">388</cbc:InvoiceTypeCode><cbc:DocumentCurrencyCode>SDG</cbc:DocumentCurrencyCode><cbc:TaxCurrencyCode>SDG</cbc:TaxCurrencyCode><cac:AdditionalDocumentReference><cbc:ID>ICV</cbc:ID><cbc:UUID>{icv}</cbc:UUID></cac:AdditionalDocumentReference><cac:AdditionalDocumentReference><cbc:ID>PIH</cbc:ID><cac:Attachment><cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">{pih_hash}</cbc:EmbeddedDocumentBinaryObject></cac:Attachment></cac:AdditionalDocumentReference><cac:AdditionalDocumentReference><cbc:ID>QR</cbc:ID><cac:Attachment><cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">{qr_b64}</cbc:EmbeddedDocumentBinaryObject></cac:Attachment></cac:AdditionalDocumentReference><cac:AccountingSupplierParty><cac:Party><cac:PartyTaxScheme><cbc:CompanyID>{supplier_tin}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme><cac:PartyLegalEntity><cbc:RegistrationName>Test Supplier</cbc:RegistrationName></cac:PartyLegalEntity></cac:Party></cac:AccountingSupplierParty><cac:AccountingCustomerParty><cac:Party><cac:PartyTaxScheme><cbc:CompanyID>{customer_tin}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme><cac:PartyLegalEntity><cbc:RegistrationName>Test Customer</cbc:RegistrationName></cac:PartyLegalEntity></cac:Party></cac:AccountingCustomerParty><cac:TaxTotal><cbc:TaxAmount currencyID="SDG">{tax_amount}</cbc:TaxAmount></cac:TaxTotal><cac:LegalMonetaryTotal><cbc:LineExtensionAmount currencyID="SDG">{line_amount}</cbc:LineExtensionAmount><cbc:TaxInclusiveAmount currencyID="SDG">{payable_amount}</cbc:TaxInclusiveAmount><cbc:PayableAmount currencyID="SDG">{payable_amount}</cbc:PayableAmount></cac:LegalMonetaryTotal><cac:InvoiceLine><cbc:ID>1</cbc:ID><cbc:InvoicedQuantity unitCode="PCE">{quantity}</cbc:InvoicedQuantity><cbc:LineExtensionAmount currencyID="SDG">{line_amount}</cbc:LineExtensionAmount><cac:TaxTotal><cbc:TaxAmount currencyID="SDG">{tax_amount}</cbc:TaxAmount></cac:TaxTotal><cac:Item><cbc:Name>Test Item</cbc:Name></cac:Item><cac:Price><cbc:PriceAmount currencyID="SDG">{unit_price}</cbc:PriceAmount></cac:Price></cac:InvoiceLine></Invoice>"#,
        ns = ns,
        profile_id = profile_id,
        invoice_id = invoice_id,
        uuid = uuid,
        issue_date = issue_date,
        issue_time = issue_time,
        icv = icv,
        pih_hash = pih_hash,
        qr_b64 = qr_b64,
        supplier_tin = supplier_tin,
        customer_tin = customer_tin,
        tax_amount = tax_amount,
        line_amount = line_amount,
        payable_amount = payable_amount,
        quantity = quantity,
        unit_price = unit_price
    )
}

fn build_signed_invoice(
    profile_id: &str,
    invoice_id: &str,
    uuid: &str,
    issue_date: &str,
    issue_time: &str,
    icv: i32,
    pih_hash: &str,
    qr_b64: &str,
    supplier_tin: &str,
    customer_tin: &str,
    tax_amount: &str,
    line_amount: &str,
    payable_amount: &str,
    quantity: &str,
    unit_price: &str,
    invoice_hash_b64: &str,
    signature_b64: &str,
    certificate_b64: &str,
    signing_time: &str,
    cert_digest_b64: &str,
    issuer_serial: &str,
) -> String {
    let signature_xml = format!(
        r#"<ext:UBLExtensions><ext:UBLExtension><ext:ExtensionURI>urn:oasis:names:specification:ubl:dsig:enveloped:xades</ext:ExtensionURI><ext:ExtensionContent><sig:UBLDocumentSignatures xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2" xmlns:sac="urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2" xmlns:sbc="urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2"><sac:SignatureInformation><cbc:ID>urn:oasis:names:specification:ubl:signature:1</cbc:ID><sbc:ReferencedSignatureID>urn:oasis:names:specification:ubl:signature:Invoice</sbc:ReferencedSignatureID><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="signature"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(//ancestor-or-self::ext:UBLExtensions)</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(//ancestor-or-self::cac:Signature)</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{invoice_hash_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>{signature_b64}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="signature"><xades:SignedProperties Id="xadesSignedProperties"><xades:SignedSignatureProperties><xades:SigningTime>{signing_time}</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{cert_digest_b64}</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>CN=Test</ds:X509IssuerName><ds:X509SerialNumber>{issuer_serial}</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties></xades:SignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature></sac:SignatureInformation></sig:UBLDocumentSignatures></ext:ExtensionContent></ext:UBLExtension></ext:UBLExtensions>"#,
        invoice_hash_b64 = invoice_hash_b64,
        signature_b64 = signature_b64,
        certificate_b64 = certificate_b64,
        signing_time = signing_time,
        cert_digest_b64 = cert_digest_b64,
        issuer_serial = issuer_serial
    );

    let cac_signature = r#"<cac:Signature><cbc:ID>urn:oasis:names:specification:ubl:signature:Invoice</cbc:ID><cbc:SignatureMethod>urn:oasis:names:specification:ubl:dsig:enveloped:xades</cbc:SignatureMethod></cac:Signature>"#;

    let ns = r#"xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2""#;

    format!(
        r#"<Invoice {ns}>{signature_xml}<cbc:UBLVersionID>2.1</cbc:UBLVersionID><cbc:CustomizationID>1.0</cbc:CustomizationID><cbc:ProfileID>{profile_id}</cbc:ProfileID><cbc:ProfileExecutionID>1</cbc:ProfileExecutionID><cbc:ID>{invoice_id}</cbc:ID><cbc:UUID>{uuid}</cbc:UUID><cbc:IssueDate>{issue_date}</cbc:IssueDate><cbc:IssueTime>{issue_time}</cbc:IssueTime><cbc:InvoiceTypeCode name="0100000">388</cbc:InvoiceTypeCode><cbc:DocumentCurrencyCode>SDG</cbc:DocumentCurrencyCode><cbc:TaxCurrencyCode>SDG</cbc:TaxCurrencyCode><cac:AdditionalDocumentReference><cbc:ID>ICV</cbc:ID><cbc:UUID>{icv}</cbc:UUID></cac:AdditionalDocumentReference><cac:AdditionalDocumentReference><cbc:ID>PIH</cbc:ID><cac:Attachment><cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">{pih_hash}</cbc:EmbeddedDocumentBinaryObject></cac:Attachment></cac:AdditionalDocumentReference><cac:AdditionalDocumentReference><cbc:ID>QR</cbc:ID><cac:Attachment><cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">{qr_b64}</cbc:EmbeddedDocumentBinaryObject></cac:Attachment></cac:AdditionalDocumentReference>{cac_signature}<cac:AccountingSupplierParty><cac:Party><cac:PartyTaxScheme><cbc:CompanyID>{supplier_tin}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme><cac:PartyLegalEntity><cbc:RegistrationName>Test Supplier</cbc:RegistrationName></cac:PartyLegalEntity></cac:Party></cac:AccountingSupplierParty><cac:AccountingCustomerParty><cac:Party><cac:PartyTaxScheme><cbc:CompanyID>{customer_tin}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme><cac:PartyLegalEntity><cbc:RegistrationName>Test Customer</cbc:RegistrationName></cac:PartyLegalEntity></cac:Party></cac:AccountingCustomerParty><cac:TaxTotal><cbc:TaxAmount currencyID="SDG">{tax_amount}</cbc:TaxAmount></cac:TaxTotal><cac:LegalMonetaryTotal><cbc:LineExtensionAmount currencyID="SDG">{line_amount}</cbc:LineExtensionAmount><cbc:TaxInclusiveAmount currencyID="SDG">{payable_amount}</cbc:TaxInclusiveAmount><cbc:PayableAmount currencyID="SDG">{payable_amount}</cbc:PayableAmount></cac:LegalMonetaryTotal><cac:InvoiceLine><cbc:ID>1</cbc:ID><cbc:InvoicedQuantity unitCode="PCE">{quantity}</cbc:InvoicedQuantity><cbc:LineExtensionAmount currencyID="SDG">{line_amount}</cbc:LineExtensionAmount><cac:TaxTotal><cbc:TaxAmount currencyID="SDG">{tax_amount}</cbc:TaxAmount></cac:TaxTotal><cac:Item><cbc:Name>Test Item</cbc:Name></cac:Item><cac:Price><cbc:PriceAmount currencyID="SDG">{unit_price}</cbc:PriceAmount></cac:Price></cac:InvoiceLine></Invoice>"#,
        ns = ns,
        profile_id = profile_id,
        invoice_id = invoice_id,
        uuid = uuid,
        issue_date = issue_date,
        issue_time = issue_time,
        icv = icv,
        pih_hash = pih_hash,
        qr_b64 = qr_b64,
        supplier_tin = supplier_tin,
        customer_tin = customer_tin,
        tax_amount = tax_amount,
        line_amount = line_amount,
        payable_amount = payable_amount,
        quantity = quantity,
        unit_price = unit_price,
        cac_signature = cac_signature
    )
}

pub fn generate_random_qr_data() -> String {
    let qr_data: String = (0..100)
        .map(|_| {
            let idx = rand::rng().random_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'A' + idx - 10) as char
            }
        })
        .collect();

    base64::engine::general_purpose::STANDARD.encode(qr_data.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_invoice_for_signing() {
        let invoice = r#"<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
    xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
    <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
    <cbc:ID>INV-123</cbc:ID>
</Invoice>"#;

        let extracted = extract_invoice_for_signing(invoice);

        let invoice_count = extracted.matches("<Invoice").count();
        assert_eq!(
            invoice_count, 1,
            "Should have exactly 1 <Invoice tag, found {}",
            invoice_count
        );
    }
}
