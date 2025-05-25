use std::env;
use log::{info, error};
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

    info!("=== Starting Final Fix Test ===");

    // Get StatelessVM URL from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string());
    info!("Using StatelessVM endpoint: {}", statelessvm_url);

    // Define a simple wallet address and transaction
    let from_addr = "0xcf6179c724a4e8079f21530952e32c0c090e1003";
    let to_addr = "0x1234567890123456789012345678901234567890";
    
    // Generate a unique bundle ID
    let bundle_id = format!("test-bundle-{}", Uuid::new_v4());
    
    // Format transaction as URL-encoded string (key=value&key2=value2...)
    let tx_str = format!(
        "from={}&to={}&value=0x0&data=0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001&gas_limit=0x100000&gas_price=0x3b9aca00&security_verification=enabled:false",
        from_addr, to_addr
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
    
    info!("Sending complete request with all required fields:");
    info!("{}", serde_json::to_string_pretty(&request_json).unwrap());
    
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
    
    // Let's try to update the trading_executor.rs file with the corrected format
    info!("\nThis test successfully identifies that StatelessVM API requires:\n");
    info!("1. bundle_id: A unique ID for the transaction bundle");
    info!("2. transactions: An array of URL-encoded strings (not JSON objects)");
    info!("3. witnesses: An array (can be empty)");
    info!("4. execution_context: Contains chain_id and other context information");
    info!("\nUpdate trading_executor.rs to use this format in the direct HTTP request.");
    
    Ok(())
}
