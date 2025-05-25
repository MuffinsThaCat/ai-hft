use crate::data::provider::{DataProvider, GasInfo};
use crate::strategies::manager::{ActionType, StrategyResult, TradingAction};
use crate::utils::config::StrategyConfig;
use serde::{Deserialize, Serialize};
// Define a SendError type alias that's Send + Sync
type SendError = Box<dyn std::error::Error + Send + Sync>;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitrageOpportunity {
    pub source_dex: String,
    pub target_dex: String,
    pub token_pair: String,
    pub source_price: f64,
    pub target_price: f64,
    pub price_difference_percent: f64,
    pub estimated_profit_usd: f64,
    pub estimated_gas_cost_usd: f64,
    pub net_profit_usd: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct ArbitrageStrategy {
    data_provider: Arc<DataProvider>,
    config: StrategyConfig,
    // DEX pairs to monitor for arbitrage opportunities
    pairs: Vec<(String, String)>, // (dex, pair_address)
}

impl ArbitrageStrategy {
    pub fn new(data_provider: Arc<DataProvider>, config: &StrategyConfig, pairs: Vec<(String, String)>) -> Self {
        Self {
            data_provider,
            config: config.clone(),
            pairs,
        }
    }

    // Detect arbitrage opportunities between different DEXs
    pub async fn detect_opportunities(&self) -> Result<Vec<ArbitrageOpportunity>, SendError> {
        let mut opportunities = Vec::new();
        let gas_info = self.data_provider.get_gas_prices().await?;
        
        // Get all unique tokens and DEXes from our configured pairs
        let mut token_pairs = std::collections::HashMap::new();
        
        // Extract all unique pairs we need to check
        for (dex, pair_address) in &self.pairs {
            // Get pair data from the blockchain
            match self.data_provider.get_dex_pair(dex, pair_address).await {
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
                    // Log error but continue with other pairs
                    eprintln!("Error fetching pair data for {}/{}: {}", dex, pair_address, e);
                    continue;
                }
            }
        }
        
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
                    let price_diff_percent = ((dex_a_pair.price - dex_b_pair.price) / dex_a_pair.price).abs() * 100.0;
                    
                    // Only consider opportunities with sufficient price difference (minimum 0.5%)
                    if price_diff_percent > 0.5 {
                        // Calculate potential trade size based on config and available liquidity
                        let max_position_size = self.parse_position_size(&self.config.max_position_size);
                        let available_liquidity = dex_a_pair.liquidity_usd.min(dex_b_pair.liquidity_usd);
                        
                        // Use the smaller of max position size or 5% of available liquidity
                        let trade_amount_usdc = max_position_size.min(available_liquidity * 0.05);
                        
                        // Calculate estimated profit
                        let estimated_profit = trade_amount_usdc * price_diff_percent / 100.0;
                        
                        // Estimate gas cost based on current gas prices
                        let estimated_gas_cost_usd = self.estimate_gas_cost(&gas_info, "ARBITRAGE");
                        
                        // Calculate net profit
                        let net_profit = estimated_profit - estimated_gas_cost_usd;
                        
                        // Only consider profitable opportunities after gas costs
                        if net_profit > 0.0 {
                            let confidence = self.calculate_confidence(price_diff_percent, net_profit);
                            
                            // Determine source and target DEXes (buy on cheaper, sell on more expensive)
                            let (source_dex, source_price, target_dex, target_price) = if dex_a_pair.price < dex_b_pair.price {
                                (dex_a_name.clone(), dex_a_pair.price, dex_b_name.clone(), dex_b_pair.price)
                            } else {
                                (dex_b_name.clone(), dex_b_pair.price, dex_a_name.clone(), dex_a_pair.price)
                            };
                            
                            // Create an arbitrage opportunity
                            let opportunity = ArbitrageOpportunity {
                                source_dex,
                                target_dex,
                                token_pair: pair_name.clone(),
                                source_price,
                                target_price,
                                price_difference_percent: price_diff_percent,
                                estimated_profit_usd: estimated_profit,
                                estimated_gas_cost_usd,
                                net_profit_usd: net_profit,
                                confidence,
                            };
                            
                            opportunities.push(opportunity);
                        }
                    }
                }
            }
        }
        
        Ok(opportunities)
    }
    
    // Helper method to parse position size from string (e.g., "5000 USDC")
    fn parse_position_size(&self, position_size: &str) -> f64 {
        let parts: Vec<&str> = position_size.split_whitespace().collect();
        if parts.len() >= 1 {
            if let Ok(size) = parts[0].parse::<f64>() {
                return size;
            }
        }
        // Default if parsing fails
        1000.0
    }
    
    // Generate a trading strategy based on the detected arbitrage opportunities
    pub async fn generate_strategy(&self) -> Result<Option<StrategyResult>, SendError> {
        // Detect arbitrage opportunities
        let opportunities = self.detect_opportunities().await?;
        
        if opportunities.is_empty() {
            return Ok(None);
        }
        
        // Sort opportunities by net profit in descending order
        let mut sorted_opps = opportunities.clone();
        sorted_opps.sort_by(|a, b| b.net_profit_usd.partial_cmp(&a.net_profit_usd).unwrap());
        
        // Take the most profitable opportunity
        let best_opp = &sorted_opps[0];
        
        // Only generate a strategy if the confidence is above the threshold
        if best_opp.confidence < self.config.min_confidence_score as f64 {
            return Ok(None);
        }
        
        // Create trading actions for the arbitrage
        let mut actions = Vec::new();
        
        // Step 1: Buy on the cheaper DEX
        actions.push(TradingAction {
            action_type: ActionType::Buy,
            asset: "AVAX".to_string(), // For AVAX/USDC pair
            amount: format!("{} AVAX", 1000.0 / best_opp.source_price), // Buy with 1000 USDC
            reason: format!(
                "Buy AVAX on {} at ${} which is cheaper than ${} on {}",
                best_opp.source_dex,
                best_opp.source_price,
                best_opp.target_price,
                best_opp.target_dex
            ),
            target_address: best_opp.source_dex.clone(),
            action_data: format!("Buy {} AVAX", 1000.0 / best_opp.source_price),
            gas_price: None,
            nonce: None,
        });
        
        // Step 2: Sell on the more expensive DEX
        actions.push(TradingAction {
            action_type: ActionType::Sell,
            asset: "AVAX".to_string(),
            amount: format!("{} AVAX", 1000.0 / best_opp.source_price), // Sell the AVAX we bought
            reason: format!(
                "Sell AVAX on {} at ${} which is more expensive than ${} on {}",
                best_opp.target_dex,
                best_opp.target_price,
                best_opp.source_price,
                best_opp.source_dex
            ),
            target_address: best_opp.target_dex.clone(),
            action_data: format!("Sell {} AVAX", 1000.0 / best_opp.source_price),
            gas_price: None,
            nonce: None,
        });
        
        // Create the strategy result
        let strategy = StrategyResult {
            market_analysis: format!(
                "Found arbitrage opportunity between {} and {} for AVAX/USDC. Price difference: {:.2}%", 
                best_opp.source_dex,
                best_opp.target_dex,
                best_opp.price_difference_percent
            ),
            strategy: format!(
                "Execute arbitrage by buying AVAX on {} at ${:.4} and selling on {} at ${:.4}. Expected profit: ${:.2}",
                best_opp.source_dex,
                best_opp.source_price,
                best_opp.target_dex,
                best_opp.target_price,
                best_opp.net_profit_usd
            ),
            actions,
            risk_assessment: format!(
                "Gas costs estimated at ${:.2}. Net profit after gas: ${:.2}. Primary risk is price movement during transaction execution.",
                best_opp.estimated_gas_cost_usd,
                best_opp.net_profit_usd
            ),
            confidence_score: best_opp.confidence,
        };
        
        Ok(Some(strategy))
    }
    
    // Estimate gas cost for a transaction type
    fn estimate_gas_cost(&self, gas_info: &GasInfo, tx_type: &str) -> f64 {
        // These gas estimates are simplified - in reality, you would calculate more precisely
        let gas_limit = match tx_type {
            "ARBITRAGE" => 250000, // Complex operation involving multiple contract calls
            "SWAP" => 150000,      // Standard swap operation
            _ => 100000,           // Default gas limit
        };
        
        // Calculate gas cost in ETH
        let gas_price_gwei = gas_info.fast as f64; // Use "fast" gas price for reliable execution
        let gas_cost_eth = (gas_price_gwei * 1e-9) * (gas_limit as f64);
        
        // Convert to USD using current AVAX price (simplified)
        let avax_price_usd = 35.0; // In a real implementation, you would get this from your data provider
        let gas_cost_usd = gas_cost_eth * avax_price_usd;
        
        gas_cost_usd
    }
    
    // Calculate confidence score for the arbitrage opportunity
    fn calculate_confidence(&self, price_diff_percent: f64, net_profit: f64) -> f64 {
        // Start with a base confidence
        let mut confidence: f64 = 0.7;
        
        // Adjust based on price difference (higher price difference = higher confidence)
        if price_diff_percent > 1.0 {
            confidence += 0.1;
        } else if price_diff_percent > 2.0 {
            confidence += 0.15;
        }
        
        // Adjust based on net profit (higher profit = higher confidence)
        if net_profit > 5.0 {
            confidence += 0.05;
        } else if net_profit > 10.0 {
            confidence += 0.1;
        }
        
        // Cap confidence at 0.95
        confidence.min(0.95)
    }
}
