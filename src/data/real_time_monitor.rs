use crate::data::provider::{DataProvider, DEXPair, GasInfo};
use crate::strategies::flash_arbitrage::FlashArbitrageOpportunity;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time;
use log::{info, warn, error, debug};

// Define a SendError type alias that's Send + Sync
type SendError = Box<dyn std::error::Error + Send + Sync>;

/// Real-time market monitor for detecting arbitrage opportunities
pub struct RealTimeMonitor {
    /// The data provider for fetching market data
    data_provider: Arc<DataProvider>,
    /// List of DEX pairs to monitor
    pairs: Vec<(String, String)>,
    /// Current active opportunities
    opportunities: Arc<Mutex<Vec<FlashArbitrageOpportunity>>>,
    /// Minimum price difference percentage to consider for arbitrage
    min_price_diff_percent: f64,
    /// Minimum profit in USD to consider executing an arbitrage
    min_profit_threshold: f64,
    /// Polling interval in milliseconds
    polling_interval_ms: u64,
    /// Last update timestamp
    last_update: Arc<Mutex<Instant>>,
    /// Flag to indicate if monitoring is active
    is_active: Arc<Mutex<bool>>,
}

impl RealTimeMonitor {
    /// Create a new real-time market monitor
    pub fn new(
        data_provider: Arc<DataProvider>,
        pairs: Vec<(String, String)>,
        min_price_diff_percent: f64,
        min_profit_threshold: f64,
        polling_interval_ms: u64,
    ) -> Self {
        Self {
            data_provider,
            pairs,
            opportunities: Arc::new(Mutex::new(Vec::new())),
            min_price_diff_percent,
            min_profit_threshold,
            polling_interval_ms,
            last_update: Arc::new(Mutex::new(Instant::now())),
            is_active: Arc::new(Mutex::new(false)),
        }
    }

    /// Start monitoring the market for arbitrage opportunities
    pub async fn start_monitoring(&self) -> Result<(), SendError> {
        // Set the active flag to true
        {
            let mut is_active = self.is_active.lock().unwrap();
            *is_active = true;
        }

        // Create a clone of the active flag for the async task
        let is_active = self.is_active.clone();
        let opportunities = self.opportunities.clone();
        let data_provider = self.data_provider.clone();
        let pairs = self.pairs.clone();
        let min_price_diff_percent = self.min_price_diff_percent;
        let min_profit_threshold = self.min_profit_threshold;
        let polling_interval = Duration::from_millis(self.polling_interval_ms);
        let last_update = self.last_update.clone();

        // Spawn a task to continuously monitor the market
        tokio::spawn(async move {
            info!("Starting real-time market monitoring for arbitrage opportunities");
            
            while *is_active.lock().unwrap() {
                debug!("Checking for arbitrage opportunities...");
                
                // Create a map to store token pairs across different DEXes
                let mut token_pairs: HashMap<String, Vec<(String, DEXPair)>> = HashMap::new();
                
                // Fetch the latest gas prices
                let gas_info = match data_provider.get_gas_prices().await {
                    Ok(info) => info,
                    Err(e) => {
                        error!("Failed to fetch gas prices: {}", e);
                        time::sleep(polling_interval).await;
                        continue;
                    }
                };
                
                // Fetch data for all configured pairs
                for (dex, pair_address) in &pairs {
                    match data_provider.get_dex_pair(dex, pair_address).await {
                        Ok(pair_data) => {
                            let pair_key = format!("{}/{}", pair_data.token0, pair_data.token1);
                            
                            // Add to our collection of token pairs across DEXes
                            if !token_pairs.contains_key(&pair_key) {
                                token_pairs.insert(pair_key.clone(), vec![]);
                            }
                            
                            if let Some(pairs) = token_pairs.get_mut(&pair_key) {
                                pairs.push((dex.clone(), pair_data));
                            }
                        },
                        Err(e) => {
                            warn!("Error fetching pair data for {}/{}: {}", dex, pair_address, e);
                            continue;
                        }
                    }
                }
                
                // Process the collected data to find arbitrage opportunities
                let mut new_opportunities = Vec::new();
                
                // For each token pair, check for arbitrage between different DEXes
                for (pair_name, dex_pairs) in token_pairs.iter() {
                    // We need at least 2 DEXes to compare for arbitrage
                    if dex_pairs.len() < 2 {
                        continue;
                    }
                    
                    // Compare each DEX with every other DEX for this token pair
                    for i in 0..dex_pairs.len() {
                        for j in i+1..dex_pairs.len() {
                            let (dex_a_name, dex_a_pair) = &dex_pairs[i];
                            let (dex_b_name, dex_b_pair) = &dex_pairs[j];
                            
                            // Calculate price difference percentage
                            let price_a = dex_a_pair.reserves1 / dex_a_pair.reserves0;
                            let price_b = dex_b_pair.reserves1 / dex_b_pair.reserves0;
                            let price_diff_percent = ((price_a - price_b) / price_a).abs() * 100.0;
                            
                            // Only consider opportunities with sufficient price difference
                            if price_diff_percent > min_price_diff_percent {
                                // Calculate potential flash loan size based on liquidity
                                let liquidity_a = dex_a_pair.reserves0 * price_a; // Convert to USD value
                                let liquidity_b = dex_b_pair.reserves0 * price_b; // Convert to USD value
                                let available_liquidity = liquidity_a.min(liquidity_b);
                                
                                // Use 30% of available liquidity for flash loan (conservative)
                                let flash_loan_amount_usdc = available_liquidity * 0.3;
                                
                                // Calculate flash loan fee (typically 0.09% for Aave)
                                let flash_loan_fee_rate = 0.0009; // 0.09%
                                let flash_loan_fee_usd = flash_loan_amount_usdc * flash_loan_fee_rate;
                                
                                // Calculate estimated profit (price difference * loan amount)
                                let estimated_profit = flash_loan_amount_usdc * price_diff_percent / 100.0;
                                
                                // Estimate gas cost based on current gas prices (flash loans use more gas)
                                let estimated_gas_cost_usd = match Some(gas_info.fast as f64) {
                                    Some(gwei) => {
                                        // Estimate gas: Flash loan (~300k) + 2 swaps (~150k each) + repay (~80k) = ~680k
                                        let estimated_gas = 680000.0;
                                        let gas_price_eth = gwei * 1e-9; // Convert gwei to ETH
                                        let eth_price_usd = 3000.0; // Hard-coded ETH price since GasInfo doesn't have eth_price field
                                        estimated_gas * gas_price_eth * eth_price_usd
                                    },
                                    None => 50.0, // Conservative default estimate of $50 if gas data unavailable
                                };
                                
                                // Calculate net profit after fees and gas
                                let net_profit = estimated_profit - flash_loan_fee_usd - estimated_gas_cost_usd;
                                
                                // Only consider profitable opportunities after fees and gas costs
                                if net_profit > min_profit_threshold {
                                    // Calculate confidence score (higher for larger profits and price differences)
                                    let confidence = 0.5 + (0.3 * (price_diff_percent / 5.0).min(1.0)) + 
                                                    (0.2 * (net_profit / 100.0).min(1.0));
                                    
                                    // Determine source and target DEXes (buy on cheaper, sell on more expensive)
                                    let (source_dex, source_price, target_dex, target_price) = if price_a < price_b {
                                        (dex_a_name.clone(), price_a, dex_b_name.clone(), price_b)
                                    } else {
                                        (dex_b_name.clone(), price_b, dex_a_name.clone(), price_a)
                                    };
                                    
                                    // Create a flash arbitrage opportunity
                                    let opportunity = FlashArbitrageOpportunity {
                                        source_dex: source_dex.clone(),
                                        target_dex: target_dex.clone(),
                                        token_pair: pair_name.clone(),
                                        source_price,
                                        target_price,
                                        price_difference_percent: price_diff_percent,
                                        flash_loan_amount_usd: flash_loan_amount_usdc,
                                        estimated_profit_usd: estimated_profit,
                                        estimated_gas_cost_usd,
                                        flash_loan_fee_usd,
                                        net_profit_usd: net_profit,
                                        confidence,
                                    };
                                    
                                    new_opportunities.push(opportunity);
                                    info!("Found arbitrage opportunity: {} -> {}, profit: ${:.2}, confidence: {:.2}", 
                                        source_dex, target_dex, net_profit, confidence);
                                }
                            }
                        }
                    }
                }
                
                // Update the opportunities list
                {
                    let mut opps = opportunities.lock().unwrap();
                    *opps = new_opportunities;
                    
                    // Update last update time
                    let mut last = last_update.lock().unwrap();
                    *last = Instant::now();
                }
                
                // Wait for the next polling interval
                time::sleep(polling_interval).await;
            }
            
            info!("Real-time market monitoring stopped");
        });
        
        Ok(())
    }
    
    /// Stop monitoring the market
    pub fn stop_monitoring(&self) {
        let mut is_active = self.is_active.lock().unwrap();
        *is_active = false;
        info!("Stopping real-time market monitoring");
    }
    
    /// Get current arbitrage opportunities
    pub fn get_opportunities(&self) -> Vec<FlashArbitrageOpportunity> {
        let opps = self.opportunities.lock().unwrap();
        opps.clone()
    }
    
    /// Get the best current arbitrage opportunity
    pub fn get_best_opportunity(&self) -> Option<FlashArbitrageOpportunity> {
        let opps = self.opportunities.lock().unwrap();
        if opps.is_empty() {
            return None;
        }
        
        // Find the opportunity with the highest net profit
        opps.iter()
            .max_by(|a, b| a.net_profit_usd.partial_cmp(&b.net_profit_usd).unwrap())
            .cloned()
    }
    
    /// Get time since last update
    pub fn time_since_last_update(&self) -> Duration {
        let last = self.last_update.lock().unwrap();
        last.elapsed()
    }
    
    /// Is the monitor currently active?
    pub fn is_active(&self) -> bool {
        let active = self.is_active.lock().unwrap();
        *active
    }
}
