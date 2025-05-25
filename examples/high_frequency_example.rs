use ai_trading_agent::utils::config::{Config, DataConfig, StrategyConfig, HighFrequencyConfig, TradingPair, SecurityConfig, ExecutionConfig, LLMConfig};
use ai_trading_agent::strategies::high_frequency::HighFrequencyStrategy;
use ai_trading_agent::data::provider::DataProvider;
use ai_trading_agent::models::error::AgentResult;
use ai_trading_agent::statelessvm::client::StatelessTxRequest;
use log::{info, debug, error, LevelFilter};
use env_logger::Builder;
use std::env;
use tokio::time::sleep;
use std::time::Duration;

// Import our StatelessVM executor
mod stateless_vm_executor;
use stateless_vm_executor::StatelessVmExecutor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use anyhow::Result with a ? operator to resolve type issues
    Ok(run().await?)
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger with more detailed configuration
    let mut builder = Builder::new();
    
    // Check if a log level was specified via environment variable
    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    match log_level.to_lowercase().as_str() {
        "debug" => builder.filter_level(LevelFilter::Debug),
        "trace" => builder.filter_level(LevelFilter::Trace),
        "warn" => builder.filter_level(LevelFilter::Warn),
        "error" => builder.filter_level(LevelFilter::Error),
        _ => builder.filter_level(LevelFilter::Info),
    };
    
    builder.init();
    
    info!("Starting high-frequency trading example");
    info!("Log level set to: {}", log_level);
    
    // Create a config for testing
    let config = create_test_config();
    debug!("Created test configuration");
    
    // Run the high-frequency trading example with timing
    let start_time = std::time::Instant::now();
    // Run the example and handle any errors
    if let Err(e) = run_high_frequency_example(&config).await {
        let elapsed = start_time.elapsed();
        error!("Error running high-frequency trading example: {}", e);
        error!("Failed after running for {:.2?}", elapsed);
        // Convert AgentError to Box<dyn Error>
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())));
    }
    
    let elapsed = start_time.elapsed();
    info!("High-frequency trading example completed successfully");
    info!("Total execution time: {:.2?}", elapsed);
    Ok(())
}

// Create a test configuration for high-frequency trading
fn create_test_config() -> Config {
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
    
    let hf_config = HighFrequencyConfig {
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
    };

    let strategy_config = StrategyConfig {
        active_strategies: vec!["high_frequency".to_string()],
        risk_level: 3,
        max_position_size: "1000".to_string(),
        max_slippage_bps: 50,
        min_confidence_score: 0.7,
        high_frequency: Some(hf_config),
    };

    let data_config = DataConfig {
        providers: vec!["coingecko".to_string(), "dextools".to_string()],
        update_interval_ms: 1000,
        cache_duration_s: 30,
        avalanche_rpc_url: "https://api.avax.network/ext/bc/C/rpc".to_string(),
    };

    let execution_config = ExecutionConfig {
        relayer_url: "https://relayer.example.com".to_string(),
        avalanche_rpc_url: "https://api.avax.network/ext/bc/C/rpc".to_string(),
        stateless_vm_url: "https://statelessvm.example.com".to_string(),
        max_gas_price_gwei: 100,
        confirmation_blocks: 2,
        bundle_timeout_ms: 5000,
        retry_attempts: 3,
        wallet_key: "0xYourPrivateKey".to_string(),
        wallet_address: "0xYourWalletAddress".to_string(),
        max_risk_score: 7,
        witness_generation_timeout_ms: 10000,
    };

    let llm_config = LLMConfig {
        provider: "openai".to_string(),
        api_key: "demo_key".to_string(),
        model: "gpt-4".to_string(),
        temperature: 0.7,
        max_tokens: 1024,
        retry_delay_ms: 1000,
        retry_attempts: 3,
        backoff_ms: 500,
    };

    let security_config = SecurityConfig {
        verification_mode: "standard".to_string(),
        verify_contracts: true,
        max_risk_score: 7,
        verify_reentrancy: true,
        verify_integer_underflow: true,
        verify_integer_overflow: true,
        verify_unchecked_calls: true,
        verify_upgradability: true,
        verify_mev_vulnerability: true,
        verify_cross_contract_reentrancy: true,
        verify_precision_loss: true,
        verify_gas_griefing: true,
        cache_verification_results: true,
        verification_cache_duration_s: 3600,
    };

    Config {
        data: data_config,
        strategies: strategy_config,
        execution: execution_config,
        llm: llm_config,
        security: security_config,
    }
}

/// Run high-frequency trading with simulated execution
async fn run_high_frequency_example(config: &Config) -> AgentResult<()> {
    info!("Starting high-frequency trading simulation...");
    debug!("Using config: {:?}", config);

    // Initialize data provider with error handling
    info!("Initializing data provider...");
    let data_provider = DataProvider::new(&config.data).await?;
    info!("Data provider successfully initialized");

    // Create high-frequency strategy with the config
    info!("Creating high-frequency strategy...");
    let hf_config = config.strategies.high_frequency.clone().unwrap();
    let hf_strategy = HighFrequencyStrategy::new(data_provider, hf_config);
    info!("High-frequency strategy successfully initialized");
    
    // Initialize StatelessVM executor with appropriate timeout and retry settings
    info!("Initializing StatelessVM executor...");
    // Get the StatelessVM endpoint from environment variable or use default
    // This allows us to configure the endpoint without recompiling
    let stateless_vm_url = std::env::var("STATELESSVM_URL")
        .unwrap_or_else(|_| {
            info!("STATELESSVM_URL not set, using default local endpoint");
            "http://localhost:7548".to_string()
        });
    info!("Using StatelessVM endpoint: {}", stateless_vm_url);
    let verification_timeout_ms = 30000; // 30 seconds for witness generation
    let max_retry_attempts = 3;  // 3 retry attempts
    let retry_backoff_ms = 1000; // 1 second base backoff time
    
    let mut executor = StatelessVmExecutor::new(
        stateless_vm_url, 
        verification_timeout_ms, 
        max_retry_attempts, 
        retry_backoff_ms
    );
    info!("StatelessVM executor initialized with URL: {}", stateless_vm_url);
    
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
            
            // Generate a sample transaction for the StatelessVM
            let sample_tx = StatelessTxRequest {
                from: "0xYourWalletAddress".to_string(),
                to: "0xTargetContractAddress".to_string(),
                value: "0".to_string(),
                data: "0x123456789abcdef".to_string(), // Sample transaction data
                gas_limit: "200000".to_string(),
                gas_price: "5000000000".to_string(), // 5 gwei
                security_verification: hf_strategy.prepare_security_verification("0xTargetContractAddress"),
            };
            
            // Simulate StatelessVM transaction execution (with witness generation)
            info!("Submitting transaction to StatelessVM with security verification...");
            match executor.execute_transaction(sample_tx).await {
                Ok(response) => {
                    info!("Transaction successfully executed via StatelessVM");
                    info!("Transaction hash: {}", response.tx_hash);
                    
                    // Get performance metrics
                    let metrics = executor.get_metrics();
                    info!("Performance metrics:");
                    info!(" - Witness generation time: {}ms", metrics.witness_generation_time_ms);
                    info!(" - Transaction submission time: {}ms", metrics.transaction_submission_time_ms);
                    info!(" - Total execution time: {}ms", metrics.witness_generation_time_ms + metrics.transaction_submission_time_ms);
                    
                    // Update trade statistics with error handling
                    hf_strategy.update_trade_stats(true, profit, execution_time_ms).await?;
                    info!("Successfully executed trade with {:.2}% profit", profit);
                },
                Err(e) => {
                    error!("StatelessVM transaction execution failed: {}", e);
                    // In a production environment, we would implement fallback strategy here
                    // For this example, we'll just log the error and continue
                    
                    // Update trade statistics to record the failure
                    hf_strategy.update_trade_stats(false, 0.0, execution_time_ms).await?;
                }
            }
        } else {
            info!("No trading opportunity found in this iteration");
        }
        
        // Simulate scanning interval
        sleep(Duration::from_millis(200)).await;
        iteration += 1;
    }
    
    // Print final trade statistics
    info!("High-frequency trading simulation completed");
    // In a real implementation, we would print trade statistics here
    
    Ok(())
}
