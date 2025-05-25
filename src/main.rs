use std::sync::{Arc, Mutex};
use models::error::{AgentError, AgentResult};

mod data;
mod models;
mod strategies;
mod execution;
mod security;
mod utils;
mod reasoning;
mod statelessvm;
mod examples;
mod wallet;

// Helper function for monitoring bundle status
async fn monitor_bundle_status(bundle_hash: &str, _client: &reqwest::Client) -> AgentResult<()> {
    println!("Monitoring bundle status: {}", bundle_hash);
    // Basic implementation - in production, this would query the blockchain
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    println!("Bundle {} has been confirmed", bundle_hash);
    Ok(())
}

// Conversion function for strategy types
// Convert from manager::StrategyResult to strategy::StrategyResult and vice versa
fn manager_to_model_strategy(strategy: &strategies::manager::StrategyResult) -> models::strategy::StrategyResult {

    models::strategy::StrategyResult {
        strategy_type: strategy.strategy.clone(),
        description: format!("Strategy generated from market analysis"),
        confidence: strategy.confidence_score as f64,
        actions: strategy.actions.iter().map(|a| models::strategy::TradingAction {
            action_type: match a.action_type {
                strategies::manager::ActionType::Buy => models::strategy::ActionType::Buy,
                strategies::manager::ActionType::Sell => models::strategy::ActionType::Sell,
            },
            asset: a.asset.clone(),
            amount: a.amount.clone(),
            reason: a.reason.clone(),
            target_address: a.target_address.clone(),
            action_data: a.action_data.clone(),
            gas_price: a.gas_price.clone(),
            nonce: a.nonce,
        }).collect(),
        expected_profit_usd: 0.0, // Not available in the source type
        risk_level: 1, // Default low risk
    }
}

// Convert from model::StrategyResult to manager::StrategyResult
fn convert_to_manager_strategy(strategy: &models::strategy::StrategyResult) -> strategies::manager::StrategyResult {
    let mut manager_actions = Vec::new();
    
    for action in &strategy.actions {
        let manager_action_type = match action.action_type {
            models::strategy::ActionType::Buy => strategies::manager::ActionType::Buy,
            models::strategy::ActionType::Sell => strategies::manager::ActionType::Sell,
            _ => strategies::manager::ActionType::Buy, // Default for other action types
        };
        
        manager_actions.push(strategies::manager::TradingAction {
            action_type: manager_action_type,
            asset: action.asset.clone(),
            amount: action.amount.clone(),
            reason: action.reason.clone(),
            target_address: action.target_address.clone(),
            action_data: action.action_data.clone(),
            gas_price: action.gas_price.clone(),
            nonce: action.nonce,
        });
    }
    
    strategies::manager::StrategyResult {
        market_analysis: format!("Analysis based on {}", strategy.strategy_type),
        strategy: strategy.strategy_type.clone(),
        actions: manager_actions,
        risk_assessment: format!("Risk level: {}", strategy.risk_level),
        confidence_score: strategy.confidence,
    }
}

// Function for running real-time arbitrage trading
async fn run_real_time_arbitrage(config: &utils::config::Config) -> AgentResult<()> {
    // Initialize data provider
    let data_provider = data::provider::DataProvider::new(&config.data).await
        .map_err(|e| AgentError::from(e))?;
    println!("Data provider initialized");

    // Initialize security verifier
    let security_verifier = security::verifier::SecurityVerifier::new(&config.security, &config.execution.stateless_vm_url);
    println!("Security verifier initialized");
    
    // Initialize StatelessVM client
    // Check if we should use direct mode based on RPC URL presence
    let is_production = !config.execution.avalanche_rpc_url.is_empty();
    let stateless_client = if is_production {
        // In production, use direct RPC mode
        println!("Using direct RPC mode for production trading");
        statelessvm::client::StatelessVmClient::new_direct(
            &config.execution.avalanche_rpc_url
        )
    } else {
        // In test mode, connect to the StatelessVM service
        println!("Connecting to StatelessVM service for test trading");
        statelessvm::client::StatelessVmClient::new(
            &config.execution.stateless_vm_url
        )
    };
    println!("StatelessVM client initialized");
    
    // Load DEX pairs to monitor
    // In a real implementation, these would be loaded from a config file
    // Here we're using a hardcoded list of major Avalanche DEXes and pairs
    let pairs = vec![
        ("traderjoe".to_string(), "0x9Ad6C38BE94206cA50bb0d90783181662f0Cfa10".to_string()), // TraderJoe USDC/WAVAX
        ("pangolin".to_string(), "0xf4003F4efBE8691B60249E6afbD307aBE7758adb".to_string()),  // Pangolin USDC/WAVAX
        ("sushiswap".to_string(), "0x2e8879Aa61471C5D37096293daD99f5807BF1C26".to_string()), // SushiSwap USDC/WAVAX
        ("traderjoe".to_string(), "0xFE15c2695F1F920da45C30AAE47d11dE51007AF9".to_string()), // TraderJoe WETH/WAVAX
        ("pangolin".to_string(), "0x7BbDaF56D8c0d9Db6Ad919ef5D2a67C91764156C".to_string()),  // Pangolin WETH/WAVAX
        ("sushiswap".to_string(), "0x9Ee0a4E21bd333a6bb2ab298194320b8DaA26516".to_string()), // SushiSwap WETH/WAVAX
        ("traderjoe".to_string(), "0x62cf16BF2BC053E7102E2AC1DEE6aa44F2B427C3".to_string()), // TraderJoe USDT/WAVAX
        ("pangolin".to_string(), "0x9EE0a4E21bD333a6bb2aB298194320b8DaA26516".to_string()),  // Pangolin USDT/WAVAX
    ];
    
    // Configure the real-time market monitor
    let polling_interval_ms = 5000; // Check for opportunities every 5 seconds
    let min_price_diff_percent = 1.0; // At least 1% price difference for arbitrage
    let min_profit_threshold = 20.0; // Minimum $20 profit to execute a trade
    
    // Create the real-time market monitor
    let market_monitor = Arc::new(
        data::real_time_monitor::RealTimeMonitor::new(
            data_provider.clone(),
            pairs,
            min_price_diff_percent,
            min_profit_threshold,
            polling_interval_ms,
        )
    );
    println!("Real-time market monitor initialized");
    
    // Start the market monitoring
    market_monitor.start_monitoring().await
        .map_err(|e| AgentError::from(e))?;
    println!("Market monitoring started");
    
    // Configure the real-time trader
    let min_trade_interval_seconds = 60; // At least 60 seconds between trades
    
    // Create the real-time trader
    let trader = execution::real_time_trader::RealTimeTrader::new(
        data_provider.clone(),
        market_monitor.clone(),
        stateless_client,
        security_verifier,
        config.execution.clone(),
        min_trade_interval_seconds,
    );
    println!("Real-time trader initialized");
    
    // Start trading
    trader.start_trading().await
        .map_err(|e| AgentError::from(e))?;
    println!("Trading started! Press Ctrl+C to stop.");
    
    // Print the monitoring instructions
    println!("\nMonitoring for arbitrage opportunities between these DEXes:");
    println!("- TraderJoe");
    println!("- Pangolin");
    println!("- SushiSwap");
    
    // Using the monitor_bundle_status function defined at module level
    
    // Keep the agent running until Ctrl+C
    tokio::signal::ctrl_c().await
        .map_err(|e| AgentError::from(format!("Error waiting for Ctrl+C: {}", e)))?;
    
    println!("Shutting down AI Trading Agent...");
    Ok(())
}

#[tokio::main]
async fn main() -> AgentResult<()> {
    println!("Starting AI Trading Agent...");
    
    // Load configuration
    let config = utils::config::load_config("config/config.toml")
        .map_err(|e| AgentError::from(e))?;
    
    // Check command line args for examples
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() > 1 {
        match args[1].as_str() {
            "multi-step" => {
                println!("Running multi-step transaction example");
                return examples::run_multi_step_transaction_example().await;
            }
            "flash-arbitrage" => {
                println!("Running flash arbitrage example");
                return examples::run_flash_arbitrage_example().await;
            }
            "real-time-arbitrage" => {
                println!("Running real-time arbitrage trading");
                return run_real_time_arbitrage(&config).await;
            }
            "high-frequency" => {
                println!("Running high-frequency trading example");
                return examples::run_high_frequency_example(&config).await;
            }
            _ => {}
        }
    }
    
    // Load configuration
    let config = utils::config::load_config("config/config.toml")
        .map_err(|e| AgentError::from(e))?;
    println!("Configuration loaded successfully");
    
    // Initialize data provider (already returns Arc<DataProvider>)
    let data_provider = data::provider::DataProvider::new(&config.data).await
        .map_err(|e| AgentError::from(e))?;
    println!("Data provider initialized");
    
    // Initialize LLM client
    let llm_client = models::llm::LLMClient::new(&config.llm).await
        .map_err(|e| AgentError::from(e))?;
    println!("LLM client initialized");
    
    // Initialize strategies
    let arbitrage_strategy = strategies::arbitrage::ArbitrageStrategy::new(
        data_provider.clone(),
        &config.strategies,
        Vec::new(), // DEX pairs - in a real implementation these would be loaded from config
    );
    
    // Initialize flash loan providers
    let flash_providers = vec![
        ("aave".to_string(), "0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf".to_string()), // Aave on Avalanche
        ("benqi".to_string(), "0x2b2C81e08f1Af8835a78Bb2A90AE924ACE0eA4bE".to_string()), // Benqi on Avalanche
    ];
    
    // Initialize flash arbitrage strategy - this utilizes our multi-step transaction capability
    let flash_arbitrage_strategy = strategies::flash_arbitrage::FlashArbitrageStrategy::new(
        data_provider.clone(),
        &config.strategies,
        Vec::new(), // DEX pairs - in a real implementation these would be loaded from config
        flash_providers.clone(),
    );
    
    // Initialize triangular arbitrage strategy - our advanced multi-step optimization
    let triangular_arbitrage_strategy = strategies::triangular_arbitrage::TriangularArbitrageStrategy::new(
        data_provider.clone(),
        &config.strategies,
        Vec::new(), // DEX pairs - these would be loaded from config in production
        flash_providers,
    );
    
    let liquidation_strategy = strategies::liquidation::LiquidationStrategy::new(
        data_provider.clone(),
        config.strategies.clone(),
    );
    
    println!("Trading strategies initialized");
    
    // Initialize market analyzer (AI reasoning component)
    let mut market_analyzer = reasoning::analyzer::MarketAnalyzer::new(
        data_provider.clone(), 
        &config.llm
    );
    println!("Market analyzer initialized");
    
    // Initialize reasoning engine (AI trading decision maker)
    let mut reasoning_engine = reasoning::engine::ReasoningEngine::new(
        data_provider.clone(),
        arbitrage_strategy,
        liquidation_strategy,
        flash_arbitrage_strategy,
        triangular_arbitrage_strategy, // Add our new triangular arbitrage strategy
        &config.strategies,
        &config.llm,
        &config.security
    );
    println!("AI reasoning engine initialized");
    
    // Initialize strategy manager (legacy component, will eventually be replaced by reasoning engine)
    let strategy_manager = Arc::new(Mutex::new(strategies::manager::StrategyManager::new(
        data_provider.clone(),
        llm_client.clone(),
        &config.strategies,
    )));
    println!("Strategy manager initialized");
    
    // Initialize security verifier (integrating with EVM-Verify)
    let security_verifier = security::verifier::SecurityVerifier::new(&config.security, &config.execution.stateless_vm_url);
    println!("Security verifier initialized");
    
    // Initialize execution engine (connecting to your bundle relayer)
    let mut execution_engine = execution::engine::ExecutionEngine::new(
        &config.execution,
        strategy_manager.clone(),
        security_verifier,
    ).await
        .map_err(|e| AgentError::from(e))?;
    println!("Execution engine initialized and connected to bundle relayer");
    
    println!("Starting AI Trading Agent with enhanced reasoning capabilities...");
    
    // Main trading loop
    loop {
        // 1. Analyze market conditions with AI reasoning
        let market_analysis = match market_analyzer.analyze_market().await {
            Ok(analysis) => {
                println!("AI market analysis complete: {:?} market trend, {:?} volatility", 
                    analysis.market_trend, analysis.volatility);
                analysis
            },
            Err(e) => {
                eprintln!("Error in market analysis: {}", e);
                continue;
            }
        };
        
        // 2. Update reasoning engine with market analysis
        reasoning_engine.update_market_analysis(market_analysis);
        
        // 3. Generate trading strategy using AI reasoning
        match reasoning_engine.generate_strategy().await {
            Ok(Some(strategy)) => {
                println!("AI generated trading strategy: {}", strategy.strategy_type);
                println!("Confidence score: {:.2}", strategy.confidence);
                println!("Expected profit: ${:.2}", strategy.expected_profit_usd);
                
                // 4. Execute the strategy if confidence is high enough
                if strategy.confidence >= config.strategies.min_confidence_score as f64 {
                    println!("Executing strategy with {} actions...", strategy.actions.len());
                    
                    // Convert strategy to the manager type expected by execute_strategy
                    let manager_strategy = convert_to_manager_strategy(&strategy);
                    
                    // Execute the strategy using our execution engine
                    match execution_engine.execute_strategy(&manager_strategy).await {
                        Ok(bundle_hash) => {
                            println!("Strategy executed successfully!");
                            println!("Bundle hash: {}", bundle_hash);
                            println!("Monitoring transaction status...");
                            
                            // Clone the bundle hash for the monitoring task
                            let bundle_hash_clone = bundle_hash.clone();
                            
                            // Create a clone of the necessary components for monitoring
                            let monitor_client = execution_engine.get_client_clone();
                            
                            // Asynchronously monitor bundle status without moving execution_engine
                            tokio::spawn(async move {
                                // Monitor bundle until it's included in a block
                                if let Err(e) = monitor_bundle_status(&bundle_hash_clone, &monitor_client).await {
                                    eprintln!("Error monitoring bundle: {}", e);
                                }
                            });
                            
                            // Using the monitor_bundle_status function defined earlier in the file
                        },
                        Err(e) => {
                            eprintln!("Error executing strategy: {}", e);
                        }
                    }
                } else {
                    println!("Strategy confidence too low, skipping execution");
                }
            },
            Ok(None) => {
                println!("No viable trading strategy found at this time");
            },
            Err(e) => {
                eprintln!("Error generating strategy: {}", e);
            }
        }
        
        // Wait before next analysis cycle (10 seconds in this example)
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        
        // Continue the loop, which is effectively an infinite loop
        // The only way to exit is through error handling above
    }
    
    // This code is unreachable but required for the function signature
    #[allow(unreachable_code)]
    Ok(())
}
