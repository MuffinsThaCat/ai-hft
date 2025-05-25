use ai_trading_agent::statelessvm::client::{SecurityVerificationRequest, StatelessTxResponse, StatelessVmClient};
use std::env;
use log::{info, error};
use simple_logger::SimpleLogger;
use ethers::types::Address;
use reqwest::Client;
use serde_json::json;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logger
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();

    info!("=== Starting Bundle Transaction Test ===");

    // Get StatelessVM URL from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string());
    info!("Using StatelessVM endpoint: {}", statelessvm_url);

    // Use a hard-coded address for testing
    let wallet_address = Address::from_slice(&hex::decode("cf6179c724a4e8079f21530952e32c0c090e1003").unwrap());
    info!("Using wallet with address: 0x{}", hex::encode(wallet_address.as_bytes()));

    // Create a test transaction
    let from_addr = format!("0x{}", hex::encode(wallet_address.as_bytes()));
    let to_addr = "0x1234567890123456789012345678901234567890";
    
    // Function selector for "transfer(address,uint256)" = 0xa9059cbb
    let mut calldata = vec![0xa9, 0x05, 0x9c, 0xbb];
    
    // Encode the target address (padded to 32 bytes)
    let mut address_param = vec![0u8; 12]; // 12 zeros for padding
    address_param.extend_from_slice(&hex::decode("1234567890123456789012345678901234567890").unwrap());
    
    // Encode amount - 1 token (padded to 32 bytes)
    let mut amount_param = vec![0u8; 31]; // 31 zeros for padding
    amount_param.push(1); // 1 token unit
    
    // Combine parameters
    calldata.extend_from_slice(&address_param);
    calldata.extend_from_slice(&amount_param);
    
    // Create security verification object
    let security_settings = SecurityVerificationRequest {
        address: from_addr.clone(),
        enabled: false,
        max_risk_score: 100,
        verify_reentrancy: false,
        verify_integer_underflow: false,
        verify_integer_overflow: false,
        verify_unchecked_calls: false,
        verify_upgradability: false,
        verify_mev_vulnerability: false,
        verify_cross_contract_reentrancy: false,
        verify_precision_loss: false,
        verify_gas_griefing: false,
    };
    
    // Create transaction object
    let tx_object = json!({
        "from": from_addr,
        "to": to_addr,
        "value": "0x0",
        "data": format!("0x{}", hex::encode(calldata)),
        "gas_limit": "0x100000",
        "gas_price": "0x3b9aca00",
        "security_verification": security_settings
    });
    
    // Generate a unique bundle ID
    let bundle_id = format!("test-bundle-{}", Uuid::new_v4());
    
    // Create the bundle with transactions array
    let bundle_request = json!({
        "bundle_id": bundle_id,
        "transactions": [tx_object]
    });
    
    // Log the request details
    info!("----- StatelessVM Request Details -----");
    info!("Bundle ID: {}", bundle_id);
    let serialized = serde_json::to_string_pretty(&bundle_request).unwrap();
    info!("Full Request JSON: \n{}", serialized);
    info!("----- End of Request Details -----");
    
    // Send the request to StatelessVM
    info!("Sending bundle request to StatelessVM...");
    let client = Client::new();
    
    let response = client
        .post(&format!("{}/execute", statelessvm_url))
        .json(&bundle_request)
        .send()
        .await?;
    
    let status = response.status();
    
    if status.is_success() {
        info!("✅ Bundle request succeeded with status: {}", status);
        let tx_response: StatelessTxResponse = response.json().await?;
        info!("Transaction hash: {}", tx_response.tx_hash);
        info!("Status: {}", tx_response.status);
        
        if let Some(result) = tx_response.result {
            info!("Result: {}", result);
        }
        
        if let Some(error) = tx_response.error {
            error!("Error: {}", error);
        }
        
        if let Some(security_result) = tx_response.security_verification {
            info!("Security verification: {}", if security_result.passed { "PASSED" } else { "FAILED" });
            info!("Risk score: {}", security_result.risk_score);
        }
    } else {
        error!("❌ Bundle request failed with status: {}", status);
        let error_body = response.text().await?;
        error!("Error body: {}", error_body);
    }
    
    Ok(())
}
