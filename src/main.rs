mod constants;
mod dto;
mod generator;
mod pre_enroll;
mod transactions;

use goose::config::GooseConfiguration;
use goose::prelude::*;
use gumdrop::Options;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use generator::{CREDENTIALS_POOL, init_credentials_pool};
use pre_enroll::pre_enroll_all_users;
use transactions::{health_check, submit_clearance, submit_reporting, verify_qr};

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("load_tester=warn,transaction=warn"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();
}

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    init_tracing();

    let configuration = GooseConfiguration::parse_args_default_or_exit();
    let goose_attack = GooseAttack::initialize_with_config(configuration.clone())?;

    let host = configuration.host.to_string();
    let users = configuration.users.unwrap_or(10);
    let run_time: u64 = configuration.run_time.parse().unwrap_or(60);

    println!("Initializing credentials pool with {} users...", users);
    init_credentials_pool(users);

    println!("Pre-enrolling all {} users...", users);
    pre_enroll_all_users(&host, users)
        .await
        .expect("Failed to pre-enroll users");
    println!("All users pre-enrolled successfully!");

    println!("Starting load test...");

    println!("\nLoad testing STC Server: {}", host);
    println!("Configuration:");
    println!("  - {} concurrent users", users);
    println!("  - {} second run time", run_time);
    println!("  - 5% Health checks");
    println!("  - 50% Clearance (invoice submission)");
    println!("  - 40% Reporting (invoice submission)");
    println!("  - 5% QR Verify");

    let _ = &CREDENTIALS_POOL;

    goose_attack
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
