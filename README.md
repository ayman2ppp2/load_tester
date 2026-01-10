# Load Tester

A Rust-based load testing tool using Goose framework for testing CSR signing requests and invoice submission requests.

## Features

- **CSR Signing Requests** - Certificate signing request load testing
- **Invoice Submission Requests** - Financial invoice submission load testing  
- **Realistic Test Data** - Dynamic generation of realistic payloads
- **Comprehensive Metrics** - Response times, success rates, percentiles
- **Professional Reports** - HTML reports with detailed statistics

## Usage

### Basic Usage
```bash
# Run load test against your server
cargo run -- --host https://your-api.com -u 50 -t 60s

# Generate HTML report
cargo run -- --host https://your-api.com -u 100 -t 120s --report-file report.html

# Enable detailed logging
cargo run -- --host https://your-api.com -u 25 -t 30s \
  --request-log requests.log --transaction-log transactions.log
```

### Configuration Options

- `--host` - Target server URL
- `-u, --users` - Number of concurrent users (default: CPU count)
- `-t, --run-time` - Test duration (e.g., 30s, 10m, 1h)
- `-r, --hatch-rate` - Users spawned per second (default: 1)
- `--report-file` - Generate HTML report
- `--request-log` - Log all requests
- `--transaction-log` - Log transaction details

## Test Data

### CSR Signing Requests
- Common name: api.example.com
- Domains: Multiple subdomains
- Key algorithm: RSA 2048-bit
- Certificate details: US-based organization

### Invoice Submission Requests  
- Dynamic customer IDs and invoice numbers
- Multiple line items (services, licenses)
- Realistic pricing and tax calculations
- US addresses and contact info

## Load Distribution

By default, the load tester runs:
- **60% CSR signing requests**
- **40% invoice submission requests**

This can be modified by changing the weights in the source code.

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
./target/release/load_tester --host https://api.example.com -u 10 -t 30s

# Heavy load test with reporting
./target/release/load_tester --host https://api.example.com -u 200 -t 300s \
  --report-file load_test_report.html

# Rate-limited test
./target/release/load_tester --host https://api.example.com -u 50 -r 5 -t 120s
```

## API Endpoints

The load tester targets these endpoints:
- `POST /api/csr/sign` - CSR signing requests
- `POST /api/invoices/submit` - Invoice submission requests

Make sure your server implements these endpoints with the expected JSON payload formats.