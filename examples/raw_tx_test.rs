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

    info!("=== Starting Raw TX Test ===");

    // Get StatelessVM URL from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string());
    info!("Using StatelessVM endpoint: {}", statelessvm_url);

    // Define a simple wallet address and transaction
    let from_addr = "0xcf6179c724a4e8079f21530952e32c0c090e1003";
    let to_addr = "0x1234567890123456789012345678901234567890";
    
    // Try with single transaction (no bundle)
    let single_tx_request = json!({
        "from": from_addr,
        "to": to_addr,
        "value": "0x0",
        "data": "0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001",
        "gas_limit": "0x100000",
        "gas_price": "0x3b9aca00"
    });
    
    info!("Trying single transaction approach:");
    
    // Create HTTP client and send request
    let client = Client::new();
    let response = client.post(&format!("{}/execute", statelessvm_url))
        .json(&single_tx_request)
        .send()
        .await?;
        
    let status = response.status();
    let body = response.text().await?;
    
    if status.is_success() {
        info!("✅ Single transaction succeeded with status: {}", status);
        info!("Response body: {}", body);
    } else {
        error!("❌ Single transaction failed with status: {}", status);
        error!("Response body: {}", body);
    }
    
    // Try a completely raw approach - just string data
    info!("\nTrying raw string approach...");
    
    // Try with just the transaction hash/hex directly
    let tx_data = "0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001";
    
    let raw_response = client.post(&format!("{}/execute", statelessvm_url))
        .header("Content-Type", "text/plain")
        .body(tx_data)
        .send()
        .await?;
        
    let raw_status = raw_response.status();
    let raw_body = raw_response.text().await?;
    
    if raw_status.is_success() {
        info!("✅ Raw tx data succeeded with status: {}", raw_status);
        info!("Response body: {}", raw_body);
    } else {
        error!("❌ Raw tx data failed with status: {}", raw_status);
        error!("Response body: {}", raw_body);
    }
    
    // Try with simpler request - just tx string with all fields
    info!("\nTrying with simpler JSON request...");
    
    let simple_tx = json!({
        "tx": format!("from={}&to={}&value=0x0&data={}&gas_limit=0x100000&gas_price=0x3b9aca00", 
                      from_addr, to_addr, tx_data)
    });
    
    let simple_response = client.post(&format!("{}/execute", statelessvm_url))
        .json(&simple_tx)
        .send()
        .await?;
        
    let simple_status = simple_response.status();
    let simple_body = simple_response.text().await?;
    
    if simple_status.is_success() {
        info!("✅ Simple tx format succeeded with status: {}", simple_status);
        info!("Response body: {}", simple_body);
    } else {
        error!("❌ Simple tx format failed with status: {}", simple_status);
        error!("Response body: {}", simple_body);
    }
    
    // Try without bundle_id
    info!("\nTrying with just transactions array...");
    
    let tx_array_json = json!({
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
    
    let tx_array_response = client.post(&format!("{}/execute", statelessvm_url))
        .json(&tx_array_json)
        .send()
        .await?;
        
    let tx_array_status = tx_array_response.status();
    let tx_array_body = tx_array_response.text().await?;
    
    if tx_array_status.is_success() {
        info!("✅ Transaction array succeeded with status: {}", tx_array_status);
        info!("Response body: {}", tx_array_body);
    } else {
        error!("❌ Transaction array failed with status: {}", tx_array_status);
        error!("Response body: {}", tx_array_body);
    }
    
    // Try with security verification set to false (explicitly)
    info!("\nTrying with security verification disabled...");
    
    let security_disabled_json = json!({
        "from": from_addr,
        "to": to_addr,
        "value": "0x0",
        "data": "0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000000000000000001",
        "gas_limit": "0x100000",
        "gas_price": "0x3b9aca00",
        "security_verification": {
            "enabled": false
        }
    });
    
    let security_disabled_response = client.post(&format!("{}/execute", statelessvm_url))
        .json(&security_disabled_json)
        .send()
        .await?;
        
    let security_disabled_status = security_disabled_response.status();
    let security_disabled_body = security_disabled_response.text().await?;
    
    if security_disabled_status.is_success() {
        info!("✅ Security disabled format succeeded with status: {}", security_disabled_status);
        info!("Response body: {}", security_disabled_body);
    } else {
        error!("❌ Security disabled format failed with status: {}", security_disabled_status);
        error!("Response body: {}", security_disabled_body);
    }
    
    Ok(())
}
