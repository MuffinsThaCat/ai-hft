use ai_trading_agent::execution::trading_executor::TradingExecutor;
use ai_trading_agent::models::trading::{Opportunity, MarketData};
use ai_trading_agent::models::error::AgentResult;
use chrono::{Utc, Duration};
use std::env;
use uuid::Uuid;
use log::{info, error};
use simple_logger::SimpleLogger;

#[tokio::main]
async fn main() -> AgentResult<()> {
    // Initialize logger
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();

    info!("=== Starting Trading Executor Test ===");
    info!("This test will verify connectivity to the StatelessVM service and execute a simple test trade");

    // Make sure the StatelessVM_URL is set
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| {
        info!("STATELESSVM_URL not set, using default local endpoint");
        "http://localhost:7548".to_string()
    });
    info!("Using StatelessVM endpoint: {}", statelessvm_url);

    // Initialize the trading executor
    info!("Initializing trading executor...");
    let executor = TradingExecutor::new().await?;
    info!("Trading executor initialized successfully");

    // Create a simple test opportunity
    let test_opportunity = create_test_opportunity();
    info!("Created test opportunity: {}", test_opportunity.opportunity_id);

    // Execute the trade
    info!("Executing test trade...");
    match executor.execute_trade(&test_opportunity).await {
        Ok(tx_record) => {
            info!("✅ Test trade executed successfully!");
            info!("Transaction hash: {:?}", tx_record.tx_hash);
            info!("Gas used: {}", tx_record.gas_used);
            println!("Profit/Loss (USD): ${:.2}", tx_record.profit_loss_usd);
            println!("Transaction cost (USD): ${:.2}", tx_record.tx_cost_usd);
        },
        Err(e) => {
            error!("❌ Test trade failed: {}", e);
            error!("This could be due to:");
            error!("1. StatelessVM service is not running or not accessible");
            error!("2. Wallet configuration issues");
            error!("3. Invalid transaction parameters");
            error!("4. Security verification failures");
            
            // Check if we can still get the service health status
            match reqwest::get(format!("{}/health", statelessvm_url)).await {
                Ok(response) => {
                    if response.status().is_success() {
                        info!("StatelessVM service health check succeeded, so the service is running");
                        info!("The issue is likely with the transaction parameters or security verification");
                    } else {
                        error!("StatelessVM service health check failed with status: {}", response.status());
                    }
                },
                Err(e) => {
                    error!("StatelessVM service connectivity issue: {}", e);
                    error!("Make sure the service is running and accessible at {}", statelessvm_url);
                }
            }
            
            return Err(e);
        }
    }

    info!("=== Trading Executor Test Complete ===");
    Ok(())
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
