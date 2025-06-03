use ai_trading_agent::models::trading::{Opportunity, MarketData, TransactionRecord};
use ai_trading_agent::statelessvm::client::{StatelessTxRequest, SecurityVerificationRequest};
use ai_trading_agent::wallet::WalletManager;
use ai_trading_agent::models::error::AgentResult;
use uuid::Uuid;
use chrono::{Utc, Duration};
use std::env;
use std::str::FromStr;
use ethers::types::{Address, H256, U256, Bytes};
use log::{info, error, debug, warn};
use simple_logger::SimpleLogger;

#[tokio::main]
async fn main() -> AgentResult<()> {
    // Initialize logger
    SimpleLogger::new().with_level(log::LevelFilter::Debug).init().unwrap();
    info!("Starting simplified trading test...");

    // Load environment variables
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string());
    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set for this test");
    
    // Initialize wallet
    let wallet_manager = WalletManager::new().await?;
    
    // Create a test opportunity
    let opportunity = create_test_opportunity();
    info!("Created test opportunity: {}", opportunity.opportunity_id);
    
    // Get wallet address
    let wallet_address = wallet_manager.get_address().await?;
    let wallet_address_str = format!("0x{}", hex::encode(wallet_address.as_bytes()));
    
    // Create transaction parameters
    let to_addr = "0x1234567890123456789012345678901234567890";
    
    // Create a basic transfer function call (function selector for 'transfer(address,uint256)' = 0xa9059cbb)
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
    
    // Create security verification request
    let security_verification = SecurityVerificationRequest {
        address: wallet_address_str.clone(),
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
    };
    
    // Create StatelessVM request
    let statelessvm_request = StatelessTxRequest {
        from: wallet_address_str,
        to: to_addr.to_string(),
        value: "0x0".to_string(),
        data,
        gas_limit: "0x100000".to_string(),
        gas_price: "0x3b9aca00".to_string(), // 1 Gwei
        bundle_id: Some(Uuid::new_v4().to_string()),
        security_verification,
    };
    
    // Log the request for debugging
    info!("----- StatelessVM Request Details -----");
    info!("From: {}", statelessvm_request.from);
    info!("To: {}", statelessvm_request.to);
    info!("Value: {}", statelessvm_request.value);
    info!("Data: {}", statelessvm_request.data);
    info!("Gas Limit: {}", statelessvm_request.gas_limit);
    info!("Gas Price: {}", statelessvm_request.gas_price);
    info!("Security Verification Enabled: {}", statelessvm_request.security_verification.enabled);
    info!("----- End of Request Details -----");
    
    // Create StatelessVM client
    let client = reqwest::Client::new();
    
    // Create a custom JSON object in the format expected by the updated StatelessVM API
    let bundle_id = format!("test-bundle-{}", Uuid::new_v4());
    
    // Create a structured request with bundle_id and transactions array
    let mut request_map = serde_json::Map::new();
    request_map.insert("bundle_id".to_string(), serde_json::Value::String(bundle_id.clone()));
    
    // Convert our single transaction into a transactions array
    let tx_value = serde_json::to_value(&statelessvm_request).unwrap();
    let transactions_array = serde_json::Value::Array(vec![tx_value]);
    request_map.insert("transactions".to_string(), transactions_array);
    
    // Add chain_id (required for the updated API)
    request_map.insert("chain_id".to_string(), serde_json::Value::Number(serde_json::Number::from(43114))); // Avalanche C-Chain
    
    // Convert to JSON Value
    let request_json = serde_json::Value::Object(request_map);
    
    info!("Sending request with bundle_id and transactions array");
    
    // Submit transaction to StatelessVM
    let response = client.post(&format!("{}/execute", statelessvm_url))
        .json(&request_json)
        .send()
        .await;
    
    match response {
        Ok(res) => {
            if res.status().is_success() {
                let body = res.text().await.unwrap_or_default();
                info!("✅ Transaction submitted successfully!");
                info!("Response: {}", body);
                Ok(())
            } else {
                let status = res.status();
                let body = res.text().await.unwrap_or_default();
                error!("❌ Transaction failed with status: {}", status);
                error!("Response body: {}", body);
                Err(format!("StatelessVM API request failed with status: {}", status).into())
            }
        },
        Err(e) => {
            error!("❌ Request error: {}", e);
            Err(format!("Request error: {}", e).into())
        }
    }
}

fn create_test_opportunity() -> Opportunity {
    // Create a simple test opportunity for a small trade
    // This is just for testing connectivity and doesn't represent a real arbitrage opportunity
    
    Opportunity {
        // Only include fields that exist in the Opportunity struct
        opportunity_id: format!("test-{}", Uuid::new_v4()),
        base_token: "AVAX".to_string(),
        quote_token: "USDC".to_string(),
        profit_percent: 0.25, // 0.25% profit
        market_data: MarketData {
            buy_price: 20.0,           // $20 USDC per AVAX
            sell_price: 20.05,         // $20.05 USDC per AVAX
            buy_exchange: "Trader Joe".to_string(),
            sell_exchange: "Pangolin".to_string(),
            timestamp: Utc::now(),
        },
        expires_at: Utc::now() + Duration::seconds(60), // Expires in 60 seconds
    }
}
