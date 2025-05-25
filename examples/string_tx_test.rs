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

    info!("=== Starting String TX Test ===");

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
        "from={}&to={}&value=0x0&data=0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001&gas_limit=0x100000&gas_price=0x3b9aca00",
        from_addr, to_addr
    );
    
    // Create request with bundle_id and string transactions
    let request_json = json!({
        "bundle_id": bundle_id,
        "transactions": [tx_str]
    });
    
    info!("Sending request with string transactions:");
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
    } else {
        error!("❌ Transaction request failed with status: {}", status);
        error!("Response body: {}", body);
    }
    
    Ok(())
}
