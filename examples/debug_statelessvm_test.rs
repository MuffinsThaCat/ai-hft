use ai_trading_agent::statelessvm::client::{StatelessVmClient, StatelessTxRequest, SecurityVerificationRequest};
use std::env;
use log::{info, error, debug};
use simple_logger::SimpleLogger;
use ethers::types::Address;
use reqwest::Client;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logger
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();

    info!("=== Starting Debug StatelessVM Test ===");

    // Get StatelessVM URL from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string());
    info!("Using StatelessVM endpoint: {}", statelessvm_url);

    // Use a hard-coded address for testing
    let wallet_address = Address::from_slice(&hex::decode("cf6179c724a4e8079f21530952e32c0c090e1003").unwrap());
    info!("Using wallet with address: 0x{}", hex::encode(wallet_address.as_bytes()));

    // Create a test transaction request
    let tx_request = create_test_transaction(wallet_address);
    
    info!("----- StatelessVM Request Details -----");
    info!("From: {}", tx_request.from);
    info!("To: {}", tx_request.to);
    info!("Value: {}", tx_request.value);
    info!("Data: {}", tx_request.data);
    info!("Gas Limit: {}", tx_request.gas_limit);
    info!("Gas Price: {}", tx_request.gas_price);
    info!("Security Verification Enabled: {}", tx_request.security_verification.enabled);
    
    // Serialize the request for debugging
    let serialized = serde_json::to_string_pretty(&tx_request).unwrap();
    info!("Full JSON Request: \n{}", serialized);
    info!("----- End of Request Details -----");
    
    // Send the request to StatelessVM using direct HTTP calls for debugging
    info!("Sending direct request to StatelessVM for debugging...");
    let client = Client::new();

    // First try using JSON
    let json_response = client.post(&format!("{}/execute", statelessvm_url))
        .json(&tx_request)
        .send()
        .await?;
    
    let status = json_response.status();
    let response_body = json_response.text().await?;
    
    if status.is_success() {
        info!("✅ JSON Request succeeded with status: {}", status);
    } else {
        error!("❌ JSON Request failed with status: {}", status);
    }
    info!("Response body: {}", response_body);
    
    // Now try using bundle_id and transactions format
    info!("Trying alternative format with bundle_id and transactions array...");
    
    // Convert the transaction to raw format
    let tx_data = json!({
        "bundle_id": format!("test-bundle-{}", uuid::Uuid::new_v4()),
        "transactions": [
            {
                "from": tx_request.from,
                "to": tx_request.to,
                "value": tx_request.value,
                "data": tx_request.data,
                "gas_limit": tx_request.gas_limit,
                "gas_price": tx_request.gas_price,
                "security_verification": tx_request.security_verification
            }
        ]
    });
    
    let serialized_alt = serde_json::to_string_pretty(&tx_data).unwrap();
    info!("Alternative JSON Request: \n{}", serialized_alt);
    
    let alt_response = client.post(&format!("{}/execute", statelessvm_url))
        .json(&tx_data)
        .send()
        .await?;
    
    let alt_status = alt_response.status();
    let alt_response_body = alt_response.text().await?;
    
    if alt_status.is_success() {
        info!("✅ Alternative request succeeded with status: {}", alt_status);
    } else {
        error!("❌ Alternative request failed with status: {}", alt_status);
    }
    info!("Alternative response body: {}", alt_response_body);
    
    // Try to get API documentation or version info
    info!("Checking StatelessVM API endpoints...");
    let endpoints_to_check = vec![
        "/api",
        "/api/v1",
        "/swagger",
        "/docs",
        "/version",
        "/info",
    ];
    
    for endpoint in endpoints_to_check {
        match client.get(&format!("{}{}", statelessvm_url, endpoint)).send().await {
            Ok(response) => {
                info!("Endpoint {} returned status: {}", endpoint, response.status());
                if response.status().is_success() {
                    let body = response.text().await?;
                    if !body.is_empty() && body.len() < 1000 {
                        info!("Response: {}", body);
                    } else {
                        info!("Response too large to display");
                    }
                }
            },
            Err(e) => {
                debug!("Error checking endpoint {}: {}", endpoint, e);
            }
        }
    }
    
    Ok(())
}

fn create_test_transaction(wallet_address: Address) -> StatelessTxRequest {
    // Create a simple ERC20 transfer as test transaction
    let to_address = "0x1234567890123456789012345678901234567890";
    
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
    
    // Create the StatelessTxRequest
    StatelessTxRequest {
        from: format!("0x{}", hex::encode(wallet_address.as_bytes())),
        to: to_address.to_string(),
        value: "0x0".to_string(),
        data: format!("0x{}", hex::encode(calldata)),
        gas_limit: "0x100000".to_string(),
        gas_price: "0x3b9aca00".to_string(), // 1 Gwei
        security_verification: SecurityVerificationRequest {
            address: format!("0x{}", hex::encode(wallet_address.as_bytes())),
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
        },
    }
}
