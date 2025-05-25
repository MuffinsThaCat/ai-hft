use ai_trading_agent::statelessvm::client::{StatelessVmClient, StatelessTxRequest, SecurityVerificationRequest};
use ai_trading_agent::wallet::WalletManager;
use std::env;
use log::{info, error};
use simple_logger::SimpleLogger;
use ethers::types::Address;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logger
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();

    info!("=== Starting Correct StatelessVM Test ===");

    // Get StatelessVM URL from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| {
        info!("STATELESSVM_URL not set, using default local endpoint");
        "http://localhost:7548".to_string()
    });
    info!("Using StatelessVM endpoint: {}", statelessvm_url);

    // Get private key from environment 
    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set for this test");
    
    // Create wallet using the WalletManager
    let wallet_manager = WalletManager::new().await.unwrap();
    let wallet_address = wallet_manager.get_address().await.unwrap();
    info!("Using wallet with address: {}", wallet_address);

    // Create StatelessVM client
    let client = StatelessVmClient::new(&statelessvm_url);
    info!("Created StatelessVM client");
    
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
    info!("----- End of Request Details -----");
    
    // Send the request to StatelessVM
    info!("Sending request to StatelessVM...");
    match client.execute_transaction(tx_request).await {
        Ok(response) => {
            info!("✅ StatelessVM response received successfully!");
            info!("Transaction hash: {}", response.tx_hash);
            info!("Status: {}", response.status);
            
            if let Some(result) = response.result {
                info!("Result: {}", result);
            }
            
            if let Some(error) = response.error {
                error!("Error: {}", error);
            }
            
            if let Some(security_result) = response.security_verification {
                info!("Security verification: {}", if security_result.passed { "PASSED" } else { "FAILED" });
                info!("Risk score: {}", security_result.risk_score);
            }
            
            Ok(())
        },
        Err(e) => {
            error!("❌ StatelessVM request failed: {}", e);
            
            // Check if the service is running
            match reqwest::get(format!("{}/health", statelessvm_url)).await {
                Ok(response) => {
                    if response.status().is_success() {
                        info!("StatelessVM service health check succeeded, so the service is running");
                        info!("The issue is likely with the transaction parameters");
                    } else {
                        error!("StatelessVM service health check failed with status: {}", response.status());
                    }
                },
                Err(health_err) => {
                    error!("StatelessVM service connectivity issue: {}", health_err);
                }
            }
            
            Err(format!("StatelessVM request failed: {}", e).into())
        }
    }
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
