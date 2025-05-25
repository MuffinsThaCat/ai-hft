use ai_trading_agent::statelessvm::client::{StatelessVmClient, StatelessTxRequest, SecurityVerificationRequest};
// TradingWallet doesn't exist, using ethers types directly
use ethers::types::Address;
use ethers::core::types::U256;
use ethers::signers::{LocalWallet, Signer};
use std::str::FromStr;
use std::env;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use log::{info, error, debug};
use reqwest;
use serde_json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Set up logging with debug level
    std::env::set_var("RUST_LOG", "debug,reqwest=debug,hyper=debug");
    env_logger::init();
    
    debug!("Starting StatelessVM client test with debug logging...");
    
    println!("Starting StatelessVM client test...");
    
    // Get the StatelessVM URL from environment variable or use default
    let statelessvm_url = env::var("STATELESSVM_URL")
        .unwrap_or_else(|_| "http://localhost:7548".to_string());
        
    println!("Using StatelessVM URL: {}", statelessvm_url);
    
    // First, let's check if the server is responsive by making a basic HTTP request
    println!("Testing basic connectivity to StatelessVM server...");
    match reqwest::get(&format!("{}/health", statelessvm_url)).await {
        Ok(response) => {
            println!("Server health check response: {}", response.status());
            if let Ok(text) = response.text().await {
                println!("Response body: {}", text);
            }
        },
        Err(e) => {
            println!("❌ Failed to connect to StatelessVM server: {}", e);
            println!("Attempting to continue with client test anyway...");
        }
    }
    
    // Create a test wallet - in a real scenario this would be securely managed
    let private_key = env::var("PRIVATE_KEY").unwrap_or_else(|_| {
        println!("Using mock private key for testing");
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string()
    });
    
    // Create a wallet instance
    let wallet = private_key.trim_start_matches("0x");
    let wallet = LocalWallet::from_str(wallet).map_err(|e| Box::new(e) as Box<dyn Error>)?;
    let address = wallet.address();
    println!("Using wallet address: {}", address);
    
    // Create a StatelessVM client
    let client = StatelessVmClient::new_async(
        Some(statelessvm_url.clone()), 
        None, 
        true // Enable debug mode for detailed logs
    ).await?;
    
    println!("Created StatelessVM client");
    
    // Create a test transaction request
    let tx_request = StatelessTxRequest {
        from: address.to_string(),
        to: "0x1234567890123456789012345678901234567890".to_string(),
        value: "0".to_string(),
        data: "0xa9059cbb000000000000000000000000123456789012345678901234567890123456789000000000000000000000000000000000000000000000000000000000000000011".to_string(),
        gas_limit: "1000000".to_string(),
        gas_price: "1000000000".to_string(),
        security_verification: SecurityVerificationRequest {
            address: "0x1234567890123456789012345678901234567890".to_string(),
            enabled: true,
            max_risk_score: 80,
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
        bundle_id: Some("test".to_string()),
    };
    
    println!("Created test transaction request");
    
    // Try direct manual API call to diagnose issues
    println!("Testing direct API call to /sequence endpoint...");
    
    // Generate a timestamp for the sequence ID
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    
    let sequence_id = format!("test_seq_{}", timestamp);
    
    // Create a transaction object in JSON format
    let tx_object = serde_json::json!({
        "from": tx_request.from,
        "to": tx_request.to,
        "value": tx_request.value,
        "data": tx_request.data,
        "gas": tx_request.gas_limit,
        "gasPrice": tx_request.gas_price,
        "security_verification": tx_request.security_verification,
    });
    
    // The service expects the transaction data as a raw string, not a JSON object
    // Format the transaction as a hex string as expected by the StatelessVM service
    let from_hex = format!("{:0>40}", tx_request.from.trim_start_matches("0x"));
    let to_hex = format!("{:0>40}", tx_request.to.trim_start_matches("0x"));
    let value_hex = format!("{:0>64x}", u128::from_str(&tx_request.value).unwrap_or(0));
    let data = tx_request.data.trim_start_matches("0x");
    let data_hex = format!("{:0>64x}", data.len() / 2) + data; // Include data length as a prefix
    let gas_limit_hex = format!("{:0>64x}", u128::from_str(&tx_request.gas_limit).unwrap_or(0));
    let gas_price_hex = format!("{:0>64x}", u128::from_str(&tx_request.gas_price).unwrap_or(0));
    
    // Format as per the StatelessVM server's expected format
    let tx_formatted = format!("{}{}{}{}{}{}", from_hex, to_hex, value_hex, data_hex, gas_limit_hex, gas_price_hex);
    
    // Construct the request JSON with the formatted transaction
    let request_json = serde_json::json!({
        "atomic": true,
        "execution_context": {
            "chain_id": 43114,  // Avalanche C-Chain
            "metadata": {},
            "timestamp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        },
        "sequence_id": sequence_id,
        "timeout_seconds": 30,
        "bundle_id": format!("bundle_{}", timestamp),
        "transactions": [tx_formatted]
    });
    
    println!("Request JSON: {}", serde_json::to_string_pretty(&request_json)?);
    
    // Make the API call
    let req_client = reqwest::Client::new();
    match req_client.post(&format!("{}/sequence", statelessvm_url))
        .json(&request_json)
        .send()
        .await
    {
        Ok(response) => {
            println!("Direct API call status: {}", response.status());
            match response.text().await {
                Ok(body) => println!("Response body: {}", body),
                Err(e) => println!("Failed to read response body: {}", e)
            }
        },
        Err(e) => println!("❌ Direct API call failed: {}", e)
    }
    
    // Now try with our StatelessVmClient implementation
    println!("Executing transaction via StatelessVM client...");
    
    println!("Executing transaction via StatelessVM client...");
    
    // Wrap in a match with a timeout to ensure we don't wait forever
    let execute_future = client.execute_transaction(tx_request);
    
    // Handle timeout and execution with proper error conversions
    match tokio::time::timeout(std::time::Duration::from_secs(30), execute_future).await {
        Ok(result) => {
            match result {
                Ok(response) => {
                    println!("✅ Transaction executed successfully!");
                    println!("Response: {:?}", response);
                    
                    if let Some(security) = response.security_verification {
                        println!("Security verification result: {}", if security.passed { "PASSED" } else { "FAILED" });
                        println!("Risk score: {}/100", security.risk_score);
                        
                        if let Some(warnings) = security.warnings {
                            println!("Security warnings: {}", warnings.len());
                            for warning in warnings {
                                println!("- {}: {} ({})", warning.warning_type, warning.message, warning.severity);
                            }
                        } else {
                            println!("No security warnings detected");
                        }
                    } else {
                        println!("No security verification results returned");
                    }
                },
                Err(e) => {
                    error!("❌ Transaction execution failed: {}", e);
                    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())) as Box<dyn Error>);
                }
            }
        },
        Err(_) => {
            error!("❌ Transaction execution timed out after 30 seconds");
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "Transaction execution timed out")) as Box<dyn Error>);
        }
    }
    
    Ok(())
}

// Helper function for creating test transactions (not used in this example but kept for reference)
fn create_test_transaction(wallet_address: &str) -> StatelessTxRequest {
    // Create a simple test transaction
    let to_address = "0x1234567890123456789012345678901234567890";
    
    // Create calldata for a simple transfer function call
    // Function selector for 'transfer(address,uint256)' = 0xa9059cbb
    let mut calldata = vec![0xa9, 0x05, 0x9c, 0xbb];
    
    // Pad the address to 32 bytes (addresses are 20 bytes)
    let mut address_param = vec![0u8; 12]; // 12 zeros for padding
    address_param.extend_from_slice(&hex::decode("1234567890123456789012345678901234567890").unwrap_or_default());
    
    // Pad a simple value (1 token with 18 decimals = 1000000000000000000)
    let mut value_param = vec![0u8; 31]; // 31 zeros for padding
    value_param.push(1); // Just sending 1 token unit
    
    // Combine everything
    calldata.extend_from_slice(&address_param);
    calldata.extend_from_slice(&value_param);
    
    // Convert calldata to hex string
    let data = format!("0x{}", hex::encode(&calldata));
    
    // Create the transaction request
    StatelessTxRequest {
        from: format!("0x{}", hex::encode(wallet_address.as_bytes())),
        to: to_address.to_string(),
        value: "0x0".to_string(),
        data,
        gas_limit: "0x100000".to_string(),
        gas_price: "0x3b9aca00".to_string(), // 1 Gwei
        security_verification: SecurityVerificationRequest {
            address: format!("0x{}", hex::encode(wallet_address.as_bytes())),
            enabled: false, // Disable security verification for this test
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
        bundle_id: Some(format!("test-{}", uuid::Uuid::new_v4())),
    }
}
