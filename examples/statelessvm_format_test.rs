use std::env;
use log::{info, error};
use simple_logger::SimpleLogger;
use serde_json::json;
use uuid::Uuid;
use ai_trading_agent::statelessvm::client::{StatelessVmClient, StatelessTxRequest, SecurityVerificationRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();
        
    info!("=== Starting StatelessVM Format Test ===");
    
    // Get StatelessVM URL from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string());
    info!("Using StatelessVM endpoint: {}", statelessvm_url);

    // Create the StatelessVM client using the official library
    let stateless_vm_client = StatelessVmClient::new(&statelessvm_url);
    info!("Created StatelessVM client with URL: {}", statelessvm_url);
    
    // Define a simple wallet address and transaction
    let from_addr = "0xcf6179c724a4e8079f21530952e32c0c090e1003";
    let to_addr = "0x1234567890123456789012345678901234567890";
    
    // Create security verification request
    let security_verification = SecurityVerificationRequest {
        address: to_addr.to_string(),
        enabled: false,
        max_risk_score: 100,
        verify_reentrancy: true,
        verify_integer_underflow: true,
        verify_integer_overflow: true,
        verify_unchecked_calls: true,
        verify_upgradability: true,
        verify_mev_vulnerability: true,
        verify_cross_contract_reentrancy: true,
        verify_precision_loss: true,
        verify_gas_griefing: true,
    };
    
    // Create transaction request using the proper struct
    let tx_request = StatelessTxRequest {
        from: from_addr.to_string(),
        to: to_addr.to_string(),
        value: "0x0".to_string(),
        data: "0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001".to_string(),
        gas_limit: "0x100000".to_string(),
        gas_price: "0x3b9aca00".to_string(),
        security_verification,
    };
    
    info!("Sending StatelessVM transaction request:");
    info!("{:#?}", tx_request);
    
    // Execute the transaction using the official client
    let response = stateless_vm_client.execute_transaction(tx_request).await;
    
    match response {
        Ok(tx_response) => {
            info!("✅ Transaction request succeeded!");
            info!("Response: {:#?}", tx_response);
            info!("Transaction hash: {}", tx_response.tx_hash);
            
            if let Some(error) = tx_response.error {
                error!("Transaction executed but returned error: {}", error);
            } else {
                info!("Transaction executed successfully");
            }
            
            if let Some(sec_verification) = tx_response.security_verification {
                info!("Security verification: {}", if sec_verification.passed { "PASSED" } else { "FAILED" });
                info!("Risk score: {}", sec_verification.risk_score);
            }
        },
        Err(e) => {
            error!("❌ Transaction request failed: {}", e);
        }
    }
    
    info!("\nTest completed: This verifies that the StatelessVM client implementation works correctly");
    info!("If this test succeeds, we should update trading_executor.rs to use the client library");
    
    Ok(())
}
