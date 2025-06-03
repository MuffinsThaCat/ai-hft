use ai_trading_agent::statelessvm::client::{StatelessVmClient, StatelessTxRequest, SecurityVerificationRequest};
use ethers::prelude::*;
use std::env;
use log::{info, error};
use simple_logger::SimpleLogger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logger
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();

    info!("=== Starting Simple StatelessVM Test ===");
    info!("This test will verify connectivity to the StatelessVM service with a test transaction");

    // Get StatelessVM URL from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| {
        info!("STATELESSVM_URL not set, using default local endpoint");
        "http://localhost:7548".to_string()
    });
    info!("Using StatelessVM endpoint: {}", statelessvm_url);

    // Create a test wallet directly using a private key instead of keystore
    // In real scenarios, NEVER hardcode a private key or put it in the code
    // This is strictly for testing purposes
    let private_key = env::var("TEST_PRIVATE_KEY").unwrap_or_else(|_| {
        // This is a test private key, never use this for real transactions
        // This corresponds to a test account with no real funds
        "0x6fe2a98104944bf86ddbb6c493b80680eedba054d67a015652914662c52a7979".to_string()
    });
    
    // Create wallet from private key
    let wallet = create_wallet_from_private_key(&private_key)?;
    info!("Created test wallet with address: {}", wallet.address());

    // Create StatelessVM client
    let client = StatelessVmClient::new(&statelessvm_url);
    
    // Create a simple test transaction request
    let tx_request = create_test_transaction(&wallet.address());
    info!("Created test transaction request");
    
    // Send the request to StatelessVM
    info!("Sending request to StatelessVM...");
    match client.execute_transaction(tx_request).await {
        Ok(response) => {
            info!("✅ StatelessVM response received successfully!");
            info!("Transaction hash: {}", response.tx_hash);
            info!("Status: {}", response.status);
            
            if let Some(result) = response.result {
                info!("Result: {}", result);
            }
            
            if let Some(error) = response.error {
                error!("Error: {}", error);
            }
            
            if let Some(security_result) = response.security_verification {
                info!("Security verification: {}", if security_result.passed { "PASSED" } else { "FAILED" });
                info!("Risk score: {}", security_result.risk_score);
                
                if let Some(exec_time) = security_result.execution_time_ms {
                    info!("Security verification execution time: {} ms", exec_time);
                }
                
                if let Some(vuln_count) = security_result.vulnerability_count {
                    info!("Vulnerability count: {}", vuln_count);
                }
                
                if !security_result.passed && security_result.warnings.is_some() {
                    info!("Security warnings:");
                    for warning in security_result.warnings.unwrap() {
                        info!("  - Type: {}, Severity: {}, Description: {}", 
                            warning.warning_type, warning.severity, warning.description);
                    }
                }
            }
        },
        Err(e) => {
            error!("❌ StatelessVM request failed: {}", e);
            
            // Check if we can still get the service health status
            match reqwest::get(format!("{}/health", statelessvm_url)).await {
                Ok(response) => {
                    if response.status().is_success() {
                        info!("StatelessVM service health check succeeded, so the service is running");
                        info!("The issue is likely with the transaction parameters");
                    } else {
                        error!("StatelessVM service health check failed with status: {}", response.status());
                    }
                },
                Err(health_err) => {
                    error!("StatelessVM service connectivity issue: {}", health_err);
                    error!("Make sure the service is running and accessible at {}", statelessvm_url);
                }
            }
            
            // Convert to our error type
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())) as Box<dyn std::error::Error + Send + Sync>);
        }
    }

    info!("=== Simple StatelessVM Test Complete ===");
    Ok(())
}

fn create_wallet_from_private_key(private_key: &str) -> Result<LocalWallet, Box<dyn std::error::Error + Send + Sync>> {
    // Parse private key and create a wallet
    let private_key = private_key.trim_start_matches("0x");
    let private_key_bytes = hex::decode(private_key)?;
    let wallet = LocalWallet::from_bytes(&private_key_bytes)?
        .with_chain_id(43114u64); // Avalanche C-Chain

    Ok(wallet)
}

fn create_test_transaction(from_address: &Address) -> StatelessTxRequest {
    // Create a simple test transaction for StatelessVM
    StatelessTxRequest {
        from: format!("{:?}", from_address),
        to: "0x0000000000000000000000000000000000000000".to_string(), // Zero address for testing
        value: "0".to_string(),
        data: "0x".to_string(),
        gas_limit: "100000".to_string(),
        gas_price: "50000000000".to_string(), // 50 Gwei
        bundle_id: Some(uuid::Uuid::new_v4().to_string()),
        security_verification: SecurityVerificationRequest {
            address: from_address.to_string(),
            enabled: true,
            max_risk_score: 50,
            verify_reentrancy: true,
            verify_integer_underflow: true,
            verify_integer_overflow: true,
            verify_unchecked_calls: true,
            verify_upgradability: true,
            verify_mev_vulnerability: true,
            verify_cross_contract_reentrancy: true,
            verify_precision_loss: true,
            verify_gas_griefing: true,
        },
    }
}
