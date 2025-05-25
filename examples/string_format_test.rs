use std::env;
use log::{info, error};
use simple_logger::SimpleLogger;
use reqwest::Client;
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logger
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();

    info!("=== Starting String Format Test ===");

    // Get StatelessVM URL from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string());
    info!("Using StatelessVM endpoint: {}", statelessvm_url);

    // Define a simple wallet address and transaction
    let from_addr = "0xcf6179c724a4e8079f21530952e32c0c090e1003";
    let to_addr = "0x1234567890123456789012345678901234567890";
    
    // Generate a unique bundle ID
    let bundle_id = format!("test-bundle-{}", Uuid::new_v4());
    
    // Create a transaction string instead of an object
    let tx_string = format!(
        "from={}&to={}&value=0x0&data=0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001&gas_limit=0x100000&gas_price=0x3b9aca00",
        from_addr, to_addr
    );
    
    // Format 1: Try with a single transaction string
    let format1_request = json!({
        "bundle_id": bundle_id,
        "transactions": [tx_string]
    });
    
    info!("Using string transaction format:");
    info!("{}", serde_json::to_string_pretty(&format1_request).unwrap());
    
    // Create HTTP client and send request
    let client = Client::new();
    let response = client.post(&format!("{}/execute", statelessvm_url))
        .json(&format1_request)
        .send()
        .await?;
        
    let status = response.status();
    let body = response.text().await?;
    
    if status.is_success() {
        info!("✅ String transaction format succeeded with status: {}", status);
        info!("Response body: {}", body);
    } else {
        error!("❌ String transaction format failed with status: {}", status);
        error!("Response body: {}", body);
    }
    
    // Format 2: Try with URL-encoded form format
    info!("\nTrying with URL-encoded form format...");
    
    let form_params = [
        ("bundle_id", bundle_id.clone()),
        ("transactions[0]", tx_string)
    ];
    
    let form_response = client.post(&format!("{}/execute", statelessvm_url))
        .form(&form_params)
        .send()
        .await?;
        
    let form_status = form_response.status();
    let form_body = form_response.text().await?;
    
    if form_status.is_success() {
        info!("✅ Form format succeeded with status: {}", form_status);
        info!("Response body: {}", form_body);
    } else {
        error!("❌ Form format failed with status: {}", form_status);
        error!("Response body: {}", form_body);
    }
    
    // Format 3: Try a completely different format with direct transaction parameters
    info!("\nTrying with direct transaction parameters...");
    
    let direct_request = json!({
        "from": from_addr,
        "to": to_addr,
        "value": "0x0",
        "data": "0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001",
        "gas_limit": "0x100000",
        "gas_price": "0x3b9aca00"
    });
    
    info!("Direct transaction format:");
    info!("{}", serde_json::to_string_pretty(&direct_request).unwrap());
    
    let direct_response = client.post(&format!("{}/execute", statelessvm_url))
        .json(&direct_request)
        .send()
        .await?;
        
    let direct_status = direct_response.status();
    let direct_body = direct_response.text().await?;
    
    if direct_status.is_success() {
        info!("✅ Direct transaction format succeeded with status: {}", direct_status);
        info!("Response body: {}", direct_body);
    } else {
        error!("❌ Direct transaction format failed with status: {}", direct_status);
        error!("Response body: {}", direct_body);
    }
    
    // Check endpoints - just in case we're using the wrong endpoint
    info!("\nChecking available endpoints...");
    
    let endpoints = [
        "/execute", 
        "/transaction", 
        "/tx", 
        "/submit", 
        "/api/execute",
        "/api/transaction",
        "/api/tx",
        "/api/submit"
    ];
    
    for endpoint in endpoints {
        let check_url = format!("{}{}", statelessvm_url, endpoint);
        match client.get(&check_url).send().await {
            Ok(resp) => {
                info!("Endpoint {} returned status: {}", endpoint, resp.status());
            },
            Err(e) => {
                error!("Endpoint {} error: {}", endpoint, e);
            }
        }
    }
    
    Ok(())
}
