# STC Load Tester

A Rust-based load testing tool using Goose framework for testing the Sudanese Taxation Chamber (STC) Electronic Invoicing Server.

## Features

- **Full API Testing** - Tests all STC server endpoints
- **Device Enrollment** - PKI-based CSR generation and enrollment
- **Invoice Submission** - UBL 2.1 invoice generation for clearance and reporting
- **QR Verification** - QR code verification endpoint testing
- **Realistic Test Data** - Dynamic generation of realistic payloads
- **Sandbox Mode** - All invoice submissions use sandbox mode for testing

## Endpoints Tested

| Endpoint | Weight | Description |
|----------|--------|-------------|
| `/health_check` | 30% | Server health check |
| `/onboard` | 10% | Token generation |
| `/enroll` | 10% | Device enrollment with CSR |
| `/clear` | 25% | Invoice clearance submission |
| `/report` | 20% | Invoice reporting submission |
| `/verify_qr` | 5% | QR code verification |

## Usage

### Basic Usage
```bash
# Run load test against your server
cargo run --release -- --host http://localhost:8080 -u 50 -t 60s

# Generate HTML report
cargo run --release -- --host http://localhost:8080 -u 100 -t 120s --report-file report.html

# Enable detailed logging
cargo run --release -- --host http://localhost:8080 -u 25 -t 30s \
  --request-log requests.log --transaction-log transactions.log
```

### Configuration Options

- `--host` - Target server URL (default: http://localhost:8080)
- `-u, --users` - Number of concurrent users (default: CPU count)
- `-t, --run-time` - Test duration (e.g., 30s, 10m, 1h)
- `-r, --hatch-rate` - Users spawned per second (default: 1)
- `--report-file` - Generate HTML report
- `--request-log` - Log all requests
- `--transaction-log` - Log transaction details

## Test Data

### Device Enrollment
- RSA 2048-bit key generation
- CSR with subject containing TIN (organizationName) and device UUID (serialNumber)
- Base64 DER encoded CSR format

### Invoice Submission
- Valid UBL 2.1 XML invoices
- Dynamic invoice IDs and amounts
- Clearance profile (clearance:1.0)
- SGD currency (Sudanese Pound)
- Tax calculations included

### Valid TINs
The load tester uses these test TINs:
- 399999999900003
- 399999999900001
- 399999999900002

## Building

```bash
# Debug build
cargo build

# Release build (recommended for testing)
cargo build --release
```

## Examples

```bash
# Light load test
./target/release/load_tester --host http://localhost:8080 -u 10 -t 30s

# Heavy load test with reporting
./target/release/load_tester --host http://localhost:8080 -u 200 -t 300s \
  --report-file load_test_report.html

# Rate-limited test
./target/release/load_tester --host http://localhost:8080 -u 50 -r 5 -t 120s
```

## API Endpoints Tested

The load tester targets these STC server endpoints:
- `GET /health_check` - Server health check
- `POST /onboard` - Generate enrollment token
- `POST /enroll` - Device enrollment with CSR
- `POST /clear` - Submit invoice for clearance (sandbox mode)
- `POST /report` - Submit invoice for reporting (sandbox mode)
- `POST /verify_qr` - Verify QR code
