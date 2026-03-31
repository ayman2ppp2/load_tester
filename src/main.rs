mod constants;
mod dto;
mod generator;
mod pre_enroll;
mod transactions;

use goose::prelude::*;

use constants::DEFAULT_HOST;
use generator::{init_credentials_pool, CREDENTIALS_POOL};
use pre_enroll::pre_enroll_all_users;
use transactions::{health_check, submit_clearance, submit_reporting, verify_qr};

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    let args: Vec<String> = std::env::args().collect();

    let mut host = DEFAULT_HOST.to_string();
    let mut users = 10;
    let mut run_time = 60;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                if i + 1 < args.len() {
                    host = args[i + 1].trim_end_matches('/').to_string();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--users" => {
                if i + 1 < args.len() {
                    users = args[i + 1].parse().unwrap_or(10);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--run-time" => {
                if i + 1 < args.len() {
                    run_time = args[i + 1].parse().unwrap_or(60);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    println!("Initializing credentials pool with {} users...", users);
    init_credentials_pool(users);

    println!("Pre-enrolling all {} users...", users);
    pre_enroll_all_users(&host, users)
        .await
        .expect("Failed to pre-enroll users");
    println!("All users pre-enrolled successfully!");

    println!("\nLoad testing STC Server: {}", host);
    println!("Configuration:");
    println!("  - {} concurrent users", users);
    println!("  - {} second run time", run_time);
    println!("  - 5% Health checks");
    println!("  - 50% Clearance (invoice submission)");
    println!("  - 40% Reporting (invoice submission)");
    println!("  - 5% QR Verify");

    let _ = &CREDENTIALS_POOL;

    GooseAttack::initialize()?
        .register_scenario(
            scenario!("STCLoadTest")
                .register_transaction(transaction!(health_check).set_weight(5)?)
                .register_transaction(transaction!(submit_clearance).set_weight(50)?)
                .register_transaction(transaction!(submit_reporting).set_weight(40)?)
                .register_transaction(transaction!(verify_qr).set_weight(5)?),
        )
        .execute()
        .await?;

    Ok(())
}
