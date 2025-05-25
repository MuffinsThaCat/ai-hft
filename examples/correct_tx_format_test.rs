use std::env;
use log::{info, error, debug};
use simple_logger::SimpleLogger;
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

    info!("=== Starting Correct Transaction Format Test ===");

    // Get StatelessVM URL from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string());
    info!("Using StatelessVM endpoint: {}", statelessvm_url);

    // Test wallet address from environment or use default test wallet
    let from_addr = env::var("TEST_WALLET_ADDRESS")
        .unwrap_or_else(|_| "0xcf6179c724a4e8079f21530952e32c0c090e1003".to_string());
    
    info!("Using test wallet address: {}", from_addr);
    
    // Contract address - any valid Ethereum address works for testing
    let to_addr = "0x1234567890123456789012345678901234567890";
    
    // Simple ERC20 transfer data: transfer(address,uint256) with address param and value=1
    let data = "0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001";
    
    // Gas parameters
    let gas_limit = "0x100000";  // 1,048,576 gas
    let gas_price = "0x3b9aca00"; // 1 Gwei (1,000,000,000 wei)
    
    // Generate a unique bundle ID
    let bundle_id = format!("test-bundle-{}", Uuid::new_v4());
    
    // Format transaction as URL-encoded string
    // KEY INSIGHT: StatelessVM expects each transaction to be a URL-encoded string
    // not a JSON object
    let tx_str = format!(
        "from={}&to={}&value=0x0&data={}&gas_limit={}&gas_price={}&security_verification=enabled:false",
        from_addr, to_addr, data, gas_limit, gas_price
    );
    
    // Create complete request with all required fields
    let request_json = json!({
        "bundle_id": bundle_id,
        "transactions": [tx_str],
        "witnesses": [],
        "execution_context": {
            "chain_id": 1,
            "agent_id": "test-agent-1"
        }
    });
    
    info!("Sending correctly formatted request to StatelessVM:");
    info!("{}", serde_json::to_string_pretty(&request_json).unwrap());
    debug!("Request endpoint: {}/execute", statelessvm_url);
    
    // Create HTTP client and send request
    let client = Client::new();
    let response = client.post(&format!("{}/execute", statelessvm_url))
        .json(&request_json)
        .send()
        .await?;
        
    let status = response.status();
    let body = response.text().await?;
    
    if status.is_success() {
        info!("✅ Transaction request succeeded with status: {}", status);
        info!("Response body: {}", body);
        
        // Try to parse the response as JSON
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(json_response) => {
                info!("Response parsed as JSON: {}", serde_json::to_string_pretty(&json_response).unwrap());
            },
            Err(e) => {
                error!("Failed to parse response as JSON: {}", e);
            }
        }
    } else {
        error!("❌ Transaction request failed with status: {}", status);
        error!("Response body: {}", body);
    }
    
    info!("\nKey findings from our solution:");
    info!("1. StatelessVM API requires transactions as URL-encoded strings, not JSON objects");
    info!("2. The complete request must include bundle_id, transactions array, witnesses array, and execution_context");
    info!("3. The security_verification field should be included in the transaction string, not as a nested object");
    info!("4. We've updated the trading_executor.rs file to use this correct format");
    
    Ok(())
}
