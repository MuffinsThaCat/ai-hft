use crate::data::provider::DataProvider;
use crate::models::error::AgentError;
use crate::models::error::AgentResult;
use crate::strategies::high_frequency::{HighFrequencyStrategy, TradeStats};
use crate::utils::config::{Config, HighFrequencyConfig, TradingPair};
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use log::{info, warn, error, debug};

// Example configuration for high-frequency trading
fn create_test_config() -> HighFrequencyConfig {
    // Define trading pairs with WETH and USDC on different DEXes
    let trading_pairs = vec![
        TradingPair {
            token_a: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(), // WETH
            token_b: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(), // USDC
            trade_amount: "0.1".to_string(), // 0.1 ETH per trade
            min_profit_threshold_percent: 0.2, // 0.2% minimum profit threshold
        },
        TradingPair {
            token_a: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(), // WETH
            token_b: "0x6B175474E89094C44Da98b954EedeAC495271d0F".to_string(), // DAI
            trade_amount: "0.1".to_string(), // 0.1 ETH per trade
            min_profit_threshold_percent: 0.25, // 0.25% minimum profit threshold
        },
    ];

    // Define monitored DEXes
    let dexes = vec![
        "uniswap".to_string(), 
        "sushiswap".to_string(),
    ];
    
    HighFrequencyConfig {
        enabled: true,
        monitored_dexes: dexes,
        trading_pairs,
        min_profit_multiplier: 1.5, // Net profit must be 1.5x gas cost
        max_slippage_percent: 0.5, // 0.5% maximum slippage
        max_trade_size_usd: 1000.0, // Maximum $1000 per trade
        min_block_confirmations: 1, // Only need 1 confirmation
        scan_interval_ms: 500, // Scan every 500ms
        gas_boost_percent: 10, // Boost gas price by 10% above fast price
        wallet_address: "0xYourWalletAddress".to_string(), // Placeholder
        security_verification_enabled: true, // Enable security verification
        max_risk_score: 7, // Accept medium risk
    }
}

/// Run high-frequency trading with simulated execution
pub async fn run_high_frequency_example(config: &Config) -> AgentResult<()> {
    info!("Starting high-frequency trading simulation...");
    debug!("Using config: {:?}", config);

    // Initialize data provider with error handling
    info!("Initializing data provider...");
    let data_provider = match DataProvider::new(&config.data).await {
        Ok(provider) => {
            info!("Data provider successfully initialized");
            provider  // DataProvider::new() already returns an Arc<DataProvider>
        }
        Err(e) => {
            error!("Failed to initialize data provider: {}", e);
            return Err(AgentError::GeneralError {
                message: format!("Failed to initialize data provider: {}", e),
                source: None
            });
        }
    };

    // Create high-frequency strategy with test config (or use config from file)
    info!("Creating high-frequency strategy...");
    let hf_config = config.strategies.high_frequency.clone().unwrap_or_else(|| {
        info!("Using default test configuration");
        create_test_config()
    });
    let hf_strategy = HighFrequencyStrategy::new(data_provider, hf_config);
    info!("High-frequency strategy successfully initialized");
    
    // Main trading loop
    info!("Starting high-frequency trading loop...");
    let mut iteration = 0;
    let max_iterations = 20; // Limit for example purposes
    
    while iteration < max_iterations {
        // Log the current iteration
        info!("High-frequency trading iteration: {}/{}", iteration, max_iterations);
        
        // Simulate finding trading opportunities (every 3rd iteration)
        if iteration % 3 == 0 {
            info!("Simulating a trading opportunity...");
            
            // Simulate execution timing with some variance
            let execution_time_ms = 50 + (iteration * 5); // Gradually increasing execution time
            
            // Simulate a successful trade with varying profit
            let profit = 0.25 + (iteration as f64 * 0.05); // Increasing profit pattern
            
            // Update trade statistics with error handling
            match hf_strategy.update_trade_stats(true, profit, execution_time_ms).await {
                Ok(_) => {
                    info!("SIMULATED TRADE: Profit: ${:.2}, Execution time: {}ms", profit, execution_time_ms);
                },
                Err(e) => {
                    error!("Failed to update trade stats: {}", e);
                    // Continue despite the error
                }
            }
        } else if iteration % 7 == 0 {
            // Occasionally simulate a failed trade
            info!("Simulating a failed trade opportunity...");
            let execution_time_ms = 120; // Failed trades tend to take longer
            
            match hf_strategy.update_trade_stats(false, 0.0, execution_time_ms).await {
                Ok(_) => {
                    info!("SIMULATED FAILED TRADE: Execution time: {}ms", execution_time_ms);
                },
                Err(e) => {
                    error!("Failed to update trade stats for failed trade: {}", e);
                }
            }
        }
        
        // Get and display trade statistics every 5 iterations
        if iteration % 5 == 0 {
            let stats = hf_strategy.get_trade_stats().await;
            info!("=== TRADING STATS AT ITERATION {} ===", iteration);
            info!("Total Trades: {}", stats.total_trades);
            info!("Successful Trades: {}", stats.successful_trades);
            info!("Failed Trades: {}", stats.failed_trades);
            info!("Total Profit: ${:.2}", stats.total_profit_usd);
            info!("Average Execution Time: {}ms", stats.total_execution_time_ms);
        }
        
        // Wait before next iteration with some jitter to simulate real-world conditions
        let wait_time = 400 + (iteration % 3) * 100;
        debug!("Waiting for {}ms before next iteration", wait_time);
        sleep(Duration::from_millis(wait_time)).await;
        iteration += 1;
    }
    
    // Display final statistics
    let final_stats = hf_strategy.get_trade_stats().await;
    info!("======== HIGH-FREQUENCY TRADING STATS ========");
    info!("Total Trades: {}", final_stats.total_trades);
    info!("Successful Trades: {}", final_stats.successful_trades);
    info!("Failed Trades: {}", final_stats.failed_trades);
    info!("Total Profit: ${:.2}", final_stats.total_profit_usd);
    info!("Max Profit Trade: ${:.2}", final_stats.max_profit_trade_usd);
    info!("Average Execution Time: {}ms", final_stats.total_execution_time_ms);
    info!("Trades Per Minute: {:.2}", final_stats.trades_per_hour / 60.0);
    
    Ok(())
}
