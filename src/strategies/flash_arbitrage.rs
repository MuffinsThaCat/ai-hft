use crate::data::provider::{DataProvider, GasInfo};
use crate::strategies::manager::{ActionType, StrategyResult, TradingAction};
use crate::utils::config::StrategyConfig;
use serde::{Deserialize, Serialize};
// Define a SendError type alias that's Send + Sync
type SendError = Box<dyn std::error::Error + Send + Sync>;
use std::sync::Arc;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashArbitrageOpportunity {
    pub source_dex: String,
    pub target_dex: String,
    pub token_pair: String,
    pub source_price: f64,
    pub target_price: f64,
    pub price_difference_percent: f64,
    pub flash_loan_amount_usd: f64,
    pub estimated_profit_usd: f64,
    pub estimated_gas_cost_usd: f64,
    pub flash_loan_fee_usd: f64,
    pub net_profit_usd: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct FlashArbitrageStrategy {
    data_provider: Arc<DataProvider>,
    config: StrategyConfig,
    // DEX pairs to monitor for arbitrage opportunities
    pairs: Vec<(String, String)>, // (dex, pair_address)
    // Flash loan providers
    flash_providers: Vec<(String, String)>, // (provider_name, provider_address)
}

impl FlashArbitrageStrategy {
    pub fn new(
        data_provider: Arc<DataProvider>, 
        config: &StrategyConfig, 
        pairs: Vec<(String, String)>,
        flash_providers: Vec<(String, String)>
    ) -> Self {
        Self {
            data_provider,
            config: config.clone(),
            pairs,
            flash_providers,
        }
    }

    // Detect flash arbitrage opportunities between different DEXs
    pub async fn detect_opportunities(&self) -> Result<Vec<FlashArbitrageOpportunity>, SendError> {
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
                    
                    // Only consider opportunities with sufficient price difference (minimum 1.0% for flash loans)
                    if price_diff_percent > 1.0 {
                        // Calculate potential flash loan size based on liquidity
                        let available_liquidity = dex_a_pair.liquidity_usd.min(dex_b_pair.liquidity_usd);
                        
                        // Use 50% of available liquidity for flash loan (aggressive but safer than using 100%)
                        let flash_loan_amount_usdc = available_liquidity * 0.5;
                        
                        // Calculate flash loan fee (typically 0.09% for Aave)
                        let flash_loan_fee_rate = 0.0009; // 0.09%
                        let flash_loan_fee_usd = flash_loan_amount_usdc * flash_loan_fee_rate;
                        
                        // Calculate estimated profit (price difference * loan amount)
                        let estimated_profit = flash_loan_amount_usdc * price_diff_percent / 100.0;
                        
                        // Estimate gas cost based on current gas prices (flash loans use more gas)
                        let estimated_gas_cost_usd = self.estimate_gas_cost(&gas_info, "FLASH_ARBITRAGE");
                        
                        // Calculate net profit after fees and gas
                        let net_profit = estimated_profit - flash_loan_fee_usd - estimated_gas_cost_usd;
                        
                        // Only consider profitable opportunities after fees and gas costs
                        if net_profit > 0.0 {
                            let confidence = self.calculate_confidence(price_diff_percent, net_profit);
                            
                            // Determine source and target DEXes (buy on cheaper, sell on more expensive)
                            let (source_dex, source_price, target_dex, target_price) = if dex_a_pair.price < dex_b_pair.price {
                                (dex_a_name.clone(), dex_a_pair.price, dex_b_name.clone(), dex_b_pair.price)
                            } else {
                                (dex_b_name.clone(), dex_b_pair.price, dex_a_name.clone(), dex_a_pair.price)
                            };
                            
                            // Create a flash arbitrage opportunity
                            let opportunity = FlashArbitrageOpportunity {
                                source_dex,
                                target_dex,
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
                            
                            opportunities.push(opportunity);
                        }
                    }
                }
            }
        }
        
        Ok(opportunities)
    }
    
    // Generate a flash loan arbitrage strategy
    pub async fn generate_strategy(&self) -> Result<Option<StrategyResult>, SendError> {
        // Detect flash arbitrage opportunities
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
        
        // Select a flash loan provider (first one in our list for this example)
        let flash_provider = if !self.flash_providers.is_empty() {
            &self.flash_providers[0]
        } else {
            return Err("No flash loan providers configured".into());
        };
        
        // Extract token symbols from the pair
        let token_symbols: Vec<&str> = best_opp.token_pair.split('/').collect();
        let token_a = token_symbols[0];
        let token_b = token_symbols[1];
        
        // Use USDC as the borrowed token for simplicity
        let borrowed_token = "USDC";
        let borrow_amount = best_opp.flash_loan_amount_usd;
        
        // Create atomic multi-step transaction sequence for flash arbitrage
        let mut actions = Vec::new();
        
        // Step 1: Flash loan borrow
        actions.push(TradingAction {
            action_type: ActionType::Buy, // Used for flash loan borrow
            asset: borrowed_token.to_string(),
            amount: format!("{} {}", borrow_amount, borrowed_token),
            reason: format!("Flash borrow {} {} from {}", borrow_amount, borrowed_token, flash_provider.0),
            target_address: flash_provider.1.clone(),
            action_data: format!("flashLoan(amount={})", borrow_amount),
            gas_price: None,
            nonce: None,
        });
        
        // Step 2: Buy on the cheaper DEX
        let buy_amount = borrow_amount / best_opp.source_price;
        actions.push(TradingAction {
            action_type: ActionType::Buy,
            asset: token_a.to_string(),
            amount: format!("{} {}", buy_amount, token_a),
            reason: format!(
                "Buy {} {} on {} at ${} which is cheaper than ${} on {}",
                buy_amount,
                token_a,
                best_opp.source_dex,
                best_opp.source_price,
                best_opp.target_price,
                best_opp.target_dex
            ),
            target_address: format!("0x{:x}", ethers::types::H160::from_str(&best_opp.source_dex).unwrap_or_default()),
            action_data: format!("swap({})", token_a),
            gas_price: None,
            nonce: None,
        });
        
        // Step 3: Sell on the more expensive DEX
        actions.push(TradingAction {
            action_type: ActionType::Sell,
            asset: token_a.to_string(),
            amount: format!("{} {}", buy_amount, token_a),
            reason: format!(
                "Sell {} {} on {} at ${} which is more expensive than ${} on {}",
                buy_amount,
                token_a,
                best_opp.target_dex,
                best_opp.target_price,
                best_opp.source_price,
                best_opp.source_dex
            ),
            target_address: format!("0x{:x}", ethers::types::H160::from_str(&best_opp.target_dex).unwrap_or_default()),
            action_data: format!("swap({})", borrowed_token),
            gas_price: None,
            nonce: None,
        });
        
        // Step 4: Flash loan repay
        let repay_amount = borrow_amount + best_opp.flash_loan_fee_usd;
        actions.push(TradingAction {
            action_type: ActionType::Sell, // Used for flash loan repay
            asset: borrowed_token.to_string(),
            amount: format!("{} {}", repay_amount, borrowed_token),
            reason: format!("Flash repay {} {} to {} (includes fee)", repay_amount, borrowed_token, flash_provider.0),
            target_address: flash_provider.1.clone(),
            action_data: format!("repay(amount={})", repay_amount),
            gas_price: None,
            nonce: None,
        });
        
        // Create the strategy result
        let strategy_result = StrategyResult {
            market_analysis: format!(
                "Found a flash arbitrage opportunity between {} and {} for the {}/{} pair. \
                Price on {} is ${}, while price on {} is ${}. \
                This creates a {}% price difference which can be exploited with a flash loan.",
                best_opp.source_dex, best_opp.target_dex, token_a, token_b,
                best_opp.source_dex, best_opp.source_price,
                best_opp.target_dex, best_opp.target_price,
                best_opp.price_difference_percent
            ),
            strategy: format!(
                "Flash Arbitrage: Borrow ${} in {}, buy {} on {}, sell on {}, repay flash loan.",
                borrow_amount, borrowed_token, token_a, best_opp.source_dex, best_opp.target_dex
            ),
            actions,
            risk_assessment: format!(
                "Profit: ${:.2}\nFees: ${:.2}\nGas Cost: ${:.2}\nNet Profit: ${:.2}\nConfidence: {:.2}",
                best_opp.estimated_profit_usd,
                best_opp.flash_loan_fee_usd,
                best_opp.estimated_gas_cost_usd,
                best_opp.net_profit_usd,
                best_opp.confidence
            ),
            confidence_score: best_opp.confidence,
        };
        
        Ok(Some(strategy_result))
    }
    
    // Estimate gas cost for a transaction type
    fn estimate_gas_cost(&self, gas_info: &GasInfo, tx_type: &str) -> f64 {
        // Use the fast gas price (in wei)
        let gas_price_wei = gas_info.fast;
        
        // For this example, we'll estimate ETH price at $3000
        // In a real implementation, this would come from the data provider
        let eth_price_usd = 3000.0;
        
        // Gas amounts for different transaction types
        let gas_amount = match tx_type {
            "FLASH_ARBITRAGE" => 500000, // Flash loans use more gas due to additional operations
            _ => 200000, // Default gas amount
        };
        
        // Calculate cost in USD
        let cost_in_eth = (gas_amount as f64) * (gas_price_wei as f64) / 1_000_000_000_000_000_000.0; // Convert wei to ETH
        let cost_in_usd = cost_in_eth * eth_price_usd;
        
        cost_in_usd
    }
    
    // Calculate confidence score for the flash arbitrage opportunity
    fn calculate_confidence(&self, price_diff_percent: f64, net_profit: f64) -> f64 {
        // Base confidence from price difference (max 0.4)
        let price_diff_confidence = (price_diff_percent / 10.0).min(0.4);
        
        // Profit-based confidence (max 0.4)
        let profit_confidence = (net_profit / 1000.0).min(0.4);
        
        // Fixed confidence component (0.2)
        let base_confidence = 0.2;
        
        // Combine all confidence factors
        let confidence = base_confidence + price_diff_confidence + profit_confidence;
        
        // Ensure confidence is between 0 and 1
        confidence.max(0.0).min(1.0)
    }
}
