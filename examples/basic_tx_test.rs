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

    info!("=== Starting Basic Transaction Test ===");

    // Get StatelessVM URL from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string());
    info!("Using StatelessVM endpoint: {}", statelessvm_url);

    // Define a simple wallet address and transaction
    let from_addr = "0xcf6179c724a4e8079f21530952e32c0c090e1003";
    let to_addr = "0x1234567890123456789012345678901234567890";
    
    // Generate a unique bundle ID
    let bundle_id = format!("test-bundle-{}", Uuid::new_v4());
    
    // Try extremely simplified format - just simple strings for each value
    let basic_request_json = json!({
        "bundle_id": bundle_id,
        "transactions": [
            {
                "from": from_addr,
                "to": to_addr,
                "value": "0x0",
                "data": "0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001",
                "gas_limit": "0x100000",
                "gas_price": "0x3b9aca00"
            }
        ]
    });
    
    info!("Using basic JSON format:");
    info!("{}", serde_json::to_string_pretty(&basic_request_json).unwrap());
    
    // Create HTTP client and send request
    let client = Client::new();
    let response = client.post(&format!("{}/execute", statelessvm_url))
        .json(&basic_request_json)
        .send()
        .await?;
        
    let status = response.status();
    let body = response.text().await?;
    
    if status.is_success() {
        info!("✅ Transaction request succeeded with status: {}", status);
        info!("Response body: {}", body);
        
        // Try to parse the response as JSON
        match serde_json::from_str::<Value>(&body) {
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
        
        // Try to parse the error response as JSON
        match serde_json::from_str::<Value>(&body) {
            Ok(error_json) => {
                error!("Error details: {}", serde_json::to_string_pretty(&error_json).unwrap());
            },
            Err(_) => {
                // Body is not JSON, already printed above
            }
        }
    }
    
    // Try an even more simplified approach - just raw strings
    info!("\nTrying with raw string JSON...");
    
    let raw_json = format!(r#"{{
        "bundle_id": "{}",
        "transactions": [
            {{
                "from": "{}",
                "to": "{}",
                "value": "0x0",
                "data": "0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001",
                "gas_limit": "0x100000",
                "gas_price": "0x3b9aca00"
            }}
        ]
    }}"#, bundle_id, from_addr, to_addr);
    
    info!("Raw JSON: {}", raw_json);
    
    let raw_response = client.post(&format!("{}/execute", statelessvm_url))
        .header("Content-Type", "application/json")
        .body(raw_json)
        .send()
        .await?;
        
    let raw_status = raw_response.status();
    let raw_body = raw_response.text().await?;
    
    if raw_status.is_success() {
        info!("✅ Raw transaction request succeeded with status: {}", raw_status);
        info!("Response body: {}", raw_body);
    } else {
        error!("❌ Raw transaction request failed with status: {}", raw_status);
        error!("Response body: {}", raw_body);
    }
    
    // Check if the service is running
    let health_response = reqwest::get(&format!("{}/health", statelessvm_url)).await?;
    if health_response.status().is_success() {
        info!("StatelessVM service health check passed");
    } else {
        error!("StatelessVM service health check failed");
    }
    
    Ok(())
}
