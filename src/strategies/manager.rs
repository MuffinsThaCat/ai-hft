use crate::data::provider::{DataProvider, GasInfo};
use crate::models::llm::LLMClient;
use crate::strategies::arbitrage::ArbitrageStrategy;
use crate::strategies::flash_arbitrage::FlashArbitrageStrategy;
use crate::strategies::high_frequency::HighFrequencyStrategy;
use crate::utils::config::{StrategyConfig, HighFrequencyConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// Define a SendError type alias that's Send + Sync
type SendError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradingAction {
    pub action_type: ActionType,
    pub asset: String,
    pub amount: String,
    pub reason: String,
    pub target_address: String,     // Contract address to interact with
    pub action_data: String,        // Encoded contract call data
    pub gas_price: Option<String>,  // Optional gas price override
    pub nonce: Option<u64>,         // Optional nonce override
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    #[serde(rename = "BUY")]
    Buy,
    #[serde(rename = "SELL")]
    Sell,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyResult {
    pub market_analysis: String,
    pub strategy: String,
    pub actions: Vec<TradingAction>,
    pub risk_assessment: String,
    pub confidence_score: f64,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum StrategyType {
    Arbitrage,
    FlashArbitrage,
    LLMGenerated,
    MarketMaking,
    Liquidation,
    HighFrequency,
}

#[derive(Debug)]
#[derive(Clone)]
pub struct StrategyManager {
    data_provider: Arc<DataProvider>,
    llm_client: Arc<LLMClient>,
    config: StrategyConfig,
    arbitrage_strategy: ArbitrageStrategy,
    flash_arbitrage_strategy: FlashArbitrageStrategy,
    high_frequency_strategy: Option<HighFrequencyStrategy>,
    last_strategy_times: HashMap<StrategyType, Instant>,
    // Pairs to monitor (dex_name, pair_address)
    pairs: Vec<(String, String)>,
    // Flash loan providers (provider_name, provider_address)
    flash_providers: Vec<(String, String)>,
}

impl StrategyManager {
    pub fn new(
        data_provider: Arc<DataProvider>,
        llm_client: Arc<LLMClient>,
        config: &StrategyConfig,
    ) -> Self {
        // Initialize pairs to monitor
        let pairs = vec![
            ("trader_joe".to_string(), "0xf4003f4efbe8691b60249e6afbd307abe7758adb".to_string()), // TraderJoe AVAX/USDC
            ("trader_joe".to_string(), "0xed8cbd9f0ce3c6986b22002f03c6475ceb7a6256".to_string()), // TraderJoe ETH/AVAX
        ];
        
        // Initialize flash loan providers
        let flash_providers = vec![
            ("aave".to_string(), "0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf".to_string()), // Aave on Avalanche
            ("benqi".to_string(), "0x2b2C81e08f1Af8835a78Bb2A90AE924ACE0eA4bE".to_string()), // Benqi on Avalanche
        ];
        
        // Initialize arbitrage strategy
        let arbitrage_strategy = ArbitrageStrategy::new(
            data_provider.clone(),
            config,
            pairs.clone(),
        );
        
        // Initialize flash arbitrage strategy
        let flash_arbitrage_strategy = FlashArbitrageStrategy::new(
            data_provider.clone(),
            config,
            pairs.clone(),
            flash_providers.clone(),
        );
        
        // Initialize last strategy times
        let mut last_strategy_times = HashMap::new();
        last_strategy_times.insert(StrategyType::Arbitrage, Instant::now());
        last_strategy_times.insert(StrategyType::FlashArbitrage, Instant::now());
        last_strategy_times.insert(StrategyType::LLMGenerated, Instant::now());
        last_strategy_times.insert(StrategyType::MarketMaking, Instant::now());
        last_strategy_times.insert(StrategyType::Liquidation, Instant::now());
        last_strategy_times.insert(StrategyType::HighFrequency, Instant::now());
        
        // Initialize high frequency strategy if configured
        let high_frequency_strategy = if let Some(hf_config) = &config.high_frequency {
            if hf_config.enabled {
                Some(HighFrequencyStrategy::new(
                    data_provider.clone(),
                    hf_config.clone(),
                ))
            } else {
                None
            }
        } else {
            None
        };
        
        Self {
            data_provider,
            llm_client,
            config: config.clone(),
            arbitrage_strategy,
            flash_arbitrage_strategy,
            high_frequency_strategy,
            last_strategy_times,
            pairs,
            flash_providers,
        }
    }

    // Main method to generate a strategy using all available methods
    pub async fn generate_strategy(&mut self) -> Result<Option<StrategyResult>, SendError> {
        // Check for high-frequency trading opportunities first (every 500ms)
        // This is our highest priority strategy due to time sensitivity
        if self.should_run_strategy(&StrategyType::HighFrequency, Duration::from_millis(500)) {
            // Update strategy time first, before any borrows
            self.update_strategy_time(&StrategyType::HighFrequency);
            
            if let Some(high_freq_strategy) = &self.high_frequency_strategy {
                println!("Scanning for high-frequency trading opportunities...");
                
                if let Some(strategy) = high_freq_strategy.scan_opportunities().await.map_err(|e| {
                    Box::new(std::io::Error::new(std::io::ErrorKind::Other, 
                        format!("High-frequency strategy error: {}", e)))
                })? {
                    if self.should_execute_strategy(&strategy) {
                        println!("Found viable high-frequency trading opportunity with expected profit {:.2}%", 
                            strategy.confidence_score);
                        return Ok(Some(strategy));
                    }
                }
            }
        }
        
        // Check for flash arbitrage opportunities (every 15 seconds)
        // This leverages our multi-step transaction capabilities
        if self.should_run_strategy(&StrategyType::FlashArbitrage, Duration::from_secs(15)) {
            println!("Checking for flash arbitrage opportunities...");
            self.update_strategy_time(&StrategyType::FlashArbitrage);
            
            if let Some(strategy) = self.flash_arbitrage_strategy.generate_strategy().await? {
                if self.should_execute_strategy(&strategy) {
                    println!("Found viable flash arbitrage strategy with confidence {:.2}", strategy.confidence_score);
                    return Ok(Some(strategy));
                }
            }
        }
        
        // Check for regular arbitrage opportunities (every 10 seconds)
        if self.should_run_strategy(&StrategyType::Arbitrage, Duration::from_secs(10)) {
            println!("Checking for arbitrage opportunities...");
            self.update_strategy_time(&StrategyType::Arbitrage);
            
            if let Some(strategy) = self.arbitrage_strategy.generate_strategy().await? {
                if self.should_execute_strategy(&strategy) {
                    println!("Found viable arbitrage strategy with confidence {:.2}", strategy.confidence_score);
                    return Ok(Some(strategy));
                }
            }
        }
        
        // If no arbitrage opportunities, check for LLM-generated strategies (every 60 seconds)
        if self.should_run_strategy(&StrategyType::LLMGenerated, Duration::from_secs(60)) {
            println!("Generating LLM trading strategy...");
            self.update_strategy_time(&StrategyType::LLMGenerated);
            
            if let Ok(strategy) = self.generate_llm_strategy().await {
                if self.should_execute_strategy(&strategy) {
                    println!("Generated viable LLM strategy with confidence {:.2}", strategy.confidence_score);
                    return Ok(Some(strategy));
                }
            }
        }
        
        // No viable strategy found
        Ok(None)
    }
    
    // Generate strategy using LLM
    async fn generate_llm_strategy(&self) -> Result<StrategyResult, SendError> {
        // Fetch formatted market data for LLM consumption
        let market_data = self.data_provider.get_formatted_market_data().await?;
        
        // Get current positions
        let current_positions = self.get_current_positions().await?;
        
        // Get risk parameters
        let risk_parameters = self.get_risk_parameters();
        
        // Use LLM to generate strategy
        let strategy_json = self.llm_client.get_trading_strategy(
            &market_data,
            &current_positions,
            &risk_parameters,
        ).await?;
        
        // Parse the strategy JSON
        let strategy_result: StrategyResult = serde_json::from_str(&strategy_json)
            .map_err(|e| format!("Failed to parse strategy JSON: {}. Raw JSON: {}", e, strategy_json))?;
        
        // Validate strategy
        self.validate_strategy(&strategy_result)?;
        
        Ok(strategy_result)
    }
    
    // Helper to check if a DEX pair has significant price movement
    async fn has_significant_price_movement(&self, dex: &str, pair_address: &str) -> Result<bool, SendError> {
        // Get current pair data
        let pair = self.data_provider.get_dex_pair(dex, pair_address).await?;
        
        // In a real implementation, you would compare to historical data
        // For now, just simulating a check
        let price_movement_threshold = 0.5; // 0.5% threshold
        let simulated_price_movement = (rand::random::<f64>() * 2.0) - 1.0; // -1.0 to 1.0
        
        Ok(simulated_price_movement.abs() > price_movement_threshold)
    }
    
    async fn get_current_positions(&self) -> Result<String, SendError> {
        // This would get actual positions from your portfolio management system
        // For now, returning mock data
        Ok("AVAX: 100 ($3,500), ETH: 5 ($17,500), USDC: 10,000 ($10,000)".to_string())
    }
    
    fn get_risk_parameters(&self) -> String {
        format!(
            "Risk Level: {}/10\nMax Position Size: {}\nMax Slippage: {} bps",
            self.config.risk_level,
            self.config.max_position_size,
            self.config.max_slippage_bps
        )
    }
    
    fn validate_strategy(&self, strategy: &StrategyResult) -> Result<(), SendError> {
        // Validate confidence score
        if strategy.confidence_score < 0.0 || strategy.confidence_score > 1.0 {
            return Err(format!("Invalid confidence score: {}", strategy.confidence_score).into());
        }
        
        // Validate actions
        for action in &strategy.actions {
            // Check if action type is valid
            match action.action_type {
                ActionType::Buy | ActionType::Sell => {}
            }
            
            // Check if asset is valid
            if action.asset.is_empty() {
                return Err("Empty asset name in trading action".into());
            }
            
            // Check if amount is valid
            if action.amount.is_empty() {
                return Err("Empty amount in trading action".into());
            }
            
            // Check target address
            if action.target_address.is_empty() {
                return Err("Empty target address in trading action".into());
            }
            
            // Validate target address format (should be a valid Ethereum address)
            if !action.target_address.starts_with("0x") || action.target_address.len() != 42 {
                return Err(format!("Invalid target address format: {}", action.target_address).into());
            }
            
            // Validate action data for contract interactions
            if action.action_data.is_empty() {
                return Err("Empty action data in trading action".into());
            }
            
            // Optional fields do not need validation
        }
        
        Ok(())
    }
    
    // Method to be called by execution engine
    pub fn should_execute_strategy(&self, strategy: &StrategyResult) -> bool {
        // Only execute high confidence strategies
        if strategy.confidence_score < self.config.min_confidence_score as f64 {
            return false;
        }
        
        // Check if any actions are present
        if strategy.actions.is_empty() {
            return false;
        }
        
        true
    }
    
    // Check if we should run a specific strategy type based on the last time it was run
    fn should_run_strategy(&self, strategy_type: &StrategyType, min_interval: Duration) -> bool {
        if let Some(last_time) = self.last_strategy_times.get(strategy_type) {
            last_time.elapsed() >= min_interval
        } else {
            true
        }
    }
    
    // Update the last run time for a strategy type
    fn update_strategy_time(&mut self, strategy_type: &StrategyType) {
        if let Some(last_time) = self.last_strategy_times.get_mut(strategy_type) {
            *last_time = Instant::now();
        }
    }
}
