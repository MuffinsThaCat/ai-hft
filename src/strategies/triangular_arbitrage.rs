use crate::data::provider::{DataProvider, GasInfo, DEXPair};
use crate::strategies::manager::{ActionType, StrategyResult, TradingAction};
use crate::utils::config::StrategyConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
// Define a SendError type alias that's Send + Sync
type SendError = Box<dyn std::error::Error + Send + Sync>;
use std::sync::Arc;
use std::str::FromStr;
use ethers::types::H160;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriangularArbitrageOpportunity {
    pub token_a: String,
    pub token_b: String,
    pub token_c: String,
    pub dex_ab: String,
    pub dex_bc: String,
    pub dex_ca: String,
    pub price_ab: f64,
    pub price_bc: f64,
    pub price_ca: f64,
    pub expected_profit_percent: f64,
    pub flash_loan_amount_usd: f64,
    pub estimated_profit_usd: f64,
    pub estimated_gas_cost_usd: f64,
    pub flash_loan_fee_usd: f64,
    pub net_profit_usd: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct TriangularArbitrageStrategy {
    data_provider: Arc<DataProvider>,
    config: StrategyConfig,
    // DEX pairs to monitor for arbitrage opportunities
    pairs: Vec<(String, String)>, // (dex, pair_address)
    // Flash loan providers
    flash_providers: Vec<(String, String)>, // (provider_name, provider_address)
}

impl TriangularArbitrageStrategy {
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

    // Detect triangular arbitrage opportunities across different DEXs
    pub async fn detect_opportunities(&self) -> Result<Vec<TriangularArbitrageOpportunity>, SendError> {
        let mut opportunities = Vec::new();
        let gas_info = self.data_provider.get_gas_prices().await?;
        
        // Build a graph of tokens and their connected pairs
        let mut token_graph: HashMap<String, HashMap<String, Vec<(String, DEXPair)>>> = HashMap::new();
        let mut all_tokens: HashSet<String> = HashSet::new();
        
        // Extract all pairs and build the token graph
        for (dex, pair_address) in &self.pairs {
            // Get pair data from the blockchain
            match self.data_provider.get_dex_pair(dex, pair_address).await {
                Ok(pair_data) => {
                    let token0 = pair_data.token0.clone();
                    let token1 = pair_data.token1.clone();
                    
                    // Add tokens to our collection
                    all_tokens.insert(token0.clone());
                    all_tokens.insert(token1.clone());
                    
                    // Add to token graph in both directions
                    // Token0 -> Token1
                    if !token_graph.contains_key(&token0) {
                        token_graph.insert(token0.clone(), HashMap::new());
                    }
                    if let Some(edges) = token_graph.get_mut(&token0) {
                        if !edges.contains_key(&token1) {
                            edges.insert(token1.clone(), vec![]);
                        }
                        if let Some(pairs) = edges.get_mut(&token1) {
                            pairs.push((dex.clone(), pair_data.clone()));
                        }
                    }
                    
                    // Token1 -> Token0
                    if !token_graph.contains_key(&token1) {
                        token_graph.insert(token1.clone(), HashMap::new());
                    }
                    if let Some(edges) = token_graph.get_mut(&token1) {
                        if !edges.contains_key(&token0) {
                            edges.insert(token0.clone(), vec![]);
                        }
                        if let Some(pairs) = edges.get_mut(&token0) {
                            pairs.push((dex.clone(), pair_data.clone()));
                        }
                    }
                },
                Err(e) => {
                    // Log error but continue with other pairs
                    eprintln!("Error fetching pair data for {}/{}: {}", dex, pair_address, e);
                    continue;
                }
            }
        }
        
        // For each token, look for triangular arbitrage opportunities
        for token_a in all_tokens.iter() {
            // Only consider stablecoins or major tokens as the starting point for flash loans
            if !is_stable_or_major_token(token_a) {
                continue;
            }
            
            if let Some(a_edges) = token_graph.get(token_a) {
                // Find all tokens connected to A
                for (token_b, ab_pairs) in a_edges.iter() {
                    if let Some(b_edges) = token_graph.get(token_b) {
                        // Find all tokens connected to B (excluding A)
                        for (token_c, bc_pairs) in b_edges.iter() {
                            if token_c == token_a {
                                continue; // Skip direct path back to A
                            }
                            
                            if let Some(c_edges) = token_graph.get(token_c) {
                                // Check if C connects back to A
                                if let Some(ca_pairs) = c_edges.get(token_a) {
                                    // We have a triangular path: A -> B -> C -> A
                                    
                                    // For each combination of DEXes, calculate potential profit
                                    for (dex_ab, pair_ab) in ab_pairs {
                                        for (dex_bc, pair_bc) in bc_pairs {
                                            for (dex_ca, pair_ca) in ca_pairs {
                                                // Calculate expected rates for the full path
                                                let rate_ab = if pair_ab.token0 == *token_a {
                                                    1.0 / pair_ab.price // Convert price to rate
                                                } else {
                                                    pair_ab.price
                                                };
                                                
                                                let rate_bc = if pair_bc.token0 == *token_b {
                                                    1.0 / pair_bc.price
                                                } else {
                                                    pair_bc.price
                                                };
                                                
                                                let rate_ca = if pair_ca.token0 == *token_c {
                                                    1.0 / pair_ca.price
                                                } else {
                                                    pair_ca.price
                                                };
                                                
                                                // Calculate the combined rate for the triangle
                                                let combined_rate = rate_ab * rate_bc * rate_ca;
                                                
                                                // If combined rate > 1.0, there's a potential arbitrage
                                                if combined_rate > 1.01 { // 1% minimum profit
                                                    let profit_percent = (combined_rate - 1.0) * 100.0;
                                                    
                                                    // Calculate potential flash loan size based on liquidity
                                                    let min_liquidity = [
                                                        pair_ab.liquidity_usd,
                                                        pair_bc.liquidity_usd,
                                                        pair_ca.liquidity_usd
                                                    ].iter().fold(f64::INFINITY, |a, &b| a.min(b));
                                                    
                                                    // Use 30% of available liquidity for flash loan
                                                    let flash_loan_amount_usd = min_liquidity * 0.3;
                                                    
                                                    // Calculate flash loan fee (typically 0.09% for Aave)
                                                    let flash_loan_fee_rate = 0.0009; // 0.09%
                                                    let flash_loan_fee_usd = flash_loan_amount_usd * flash_loan_fee_rate;
                                                    
                                                    // Calculate estimated profit
                                                    let estimated_profit_usd = flash_loan_amount_usd * (combined_rate - 1.0);
                                                    
                                                    // Estimate gas cost based on current gas prices
                                                    let estimated_gas_cost_usd = self.estimate_gas_cost(&gas_info, "TRIANGULAR_ARBITRAGE");
                                                    
                                                    // Calculate net profit after fees and gas
                                                    let net_profit_usd = estimated_profit_usd - flash_loan_fee_usd - estimated_gas_cost_usd;
                                                    
                                                    // Only consider profitable opportunities after fees and gas costs
                                                    if net_profit_usd > 0.0 {
                                                        let confidence = self.calculate_confidence(profit_percent, net_profit_usd);
                                                        
                                                        // Create a triangular arbitrage opportunity
                                                        let opportunity = TriangularArbitrageOpportunity {
                                                            token_a: token_a.clone(),
                                                            token_b: token_b.clone(),
                                                            token_c: token_c.clone(),
                                                            dex_ab: dex_ab.clone(),
                                                            dex_bc: dex_bc.clone(),
                                                            dex_ca: dex_ca.clone(),
                                                            price_ab: pair_ab.price,
                                                            price_bc: pair_bc.price,
                                                            price_ca: pair_ca.price,
                                                            expected_profit_percent: profit_percent,
                                                            flash_loan_amount_usd,
                                                            estimated_profit_usd,
                                                            estimated_gas_cost_usd,
                                                            flash_loan_fee_usd,
                                                            net_profit_usd,
                                                            confidence,
                                                        };
                                                        
                                                        opportunities.push(opportunity);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Sort by confidence and profit
        opportunities.sort_by(|a, b| {
            let confidence_cmp = b.confidence.partial_cmp(&a.confidence).unwrap();
            if confidence_cmp == std::cmp::Ordering::Equal {
                b.net_profit_usd.partial_cmp(&a.net_profit_usd).unwrap()
            } else {
                confidence_cmp
            }
        });
        
        Ok(opportunities)
    }
    
    // Generate a triangular arbitrage strategy
    pub async fn generate_strategy(&self) -> Result<Option<StrategyResult>, SendError> {
        // Detect triangular arbitrage opportunities
        let opportunities = self.detect_opportunities().await?;
        
        if opportunities.is_empty() {
            return Ok(None);
        }
        
        // Take the best opportunity (already sorted by confidence and profit)
        let best_opp = &opportunities[0];
        
        // Only generate a strategy if the confidence is above the threshold
        if best_opp.confidence < self.config.min_confidence_score as f64 {
            return Ok(None);
        }
        
        // Select a flash loan provider
        let flash_provider = if !self.flash_providers.is_empty() {
            &self.flash_providers[0]
        } else {
            return Err("No flash loan providers configured".into());
        };
        
        // Create atomic multi-step transaction sequence for triangular arbitrage
        let mut actions = Vec::new();
        
        // Step 1: Flash loan borrow
        actions.push(TradingAction {
            action_type: ActionType::Buy, // Used for flash loan borrow
            asset: best_opp.token_a.clone(),
            amount: format!("{} {}", best_opp.flash_loan_amount_usd, best_opp.token_a),
            reason: format!("Flash borrow {} {} from {}", best_opp.flash_loan_amount_usd, best_opp.token_a, flash_provider.0),
            target_address: flash_provider.1.clone(),
            action_data: format!("flashLoan(amount={})", best_opp.flash_loan_amount_usd),
            gas_price: None,
            nonce: None,
        });
        
        // Step 2: Trade A -> B on DEX_AB
        let amount_a = best_opp.flash_loan_amount_usd;
        let amount_b = amount_a * best_opp.price_ab;
        actions.push(TradingAction {
            action_type: ActionType::Buy,
            asset: best_opp.token_b.clone(),
            amount: format!("{} {}", amount_b, best_opp.token_b),
            reason: format!(
                "Trade {} {} for {} {} on {}",
                amount_a, best_opp.token_a,
                amount_b, best_opp.token_b,
                best_opp.dex_ab
            ),
            target_address: format!("0x{:x}", H160::from_str(&best_opp.dex_ab).unwrap_or_default()),
            action_data: format!("swap({},{})", best_opp.token_a, best_opp.token_b),
            gas_price: None,
            nonce: None,
        });
        
        // Step 3: Trade B -> C on DEX_BC
        let amount_c = amount_b * best_opp.price_bc;
        actions.push(TradingAction {
            action_type: ActionType::Buy,
            asset: best_opp.token_c.clone(),
            amount: format!("{} {}", amount_c, best_opp.token_c),
            reason: format!(
                "Trade {} {} for {} {} on {}",
                amount_b, best_opp.token_b,
                amount_c, best_opp.token_c,
                best_opp.dex_bc
            ),
            target_address: format!("0x{:x}", H160::from_str(&best_opp.dex_bc).unwrap_or_default()),
            action_data: format!("swap({},{})", best_opp.token_b, best_opp.token_c),
            gas_price: None,
            nonce: None,
        });
        
        // Step 4: Trade C -> A on DEX_CA
        let amount_a_final = amount_c * best_opp.price_ca;
        actions.push(TradingAction {
            action_type: ActionType::Buy,
            asset: best_opp.token_a.clone(),
            amount: format!("{} {}", amount_a_final, best_opp.token_a),
            reason: format!(
                "Trade {} {} for {} {} on {}",
                amount_c, best_opp.token_c,
                amount_a_final, best_opp.token_a,
                best_opp.dex_ca
            ),
            target_address: format!("0x{:x}", H160::from_str(&best_opp.dex_ca).unwrap_or_default()),
            action_data: format!("swap({},{})", best_opp.token_c, best_opp.token_a),
            gas_price: None,
            nonce: None,
        });
        
        // Step 5: Flash loan repay
        let repay_amount = best_opp.flash_loan_amount_usd + best_opp.flash_loan_fee_usd;
        actions.push(TradingAction {
            action_type: ActionType::Sell,
            asset: best_opp.token_a.clone(),
            amount: format!("{} {}", repay_amount, best_opp.token_a),
            reason: format!("Flash repay {} {} to {} (includes fee)", repay_amount, best_opp.token_a, flash_provider.0),
            target_address: flash_provider.1.clone(),
            action_data: format!("repay(amount={})", repay_amount),
            gas_price: None,
            nonce: None,
        });
        
        // Create the strategy result
        let strategy_result = StrategyResult {
            market_analysis: format!(
                "Found a triangular arbitrage opportunity across three DEXes: {}, {}, and {}. \
                The path is: {} -> {} -> {} -> {}. \
                This creates a {:.2}% profit opportunity which can be exploited with a flash loan.",
                best_opp.dex_ab, best_opp.dex_bc, best_opp.dex_ca,
                best_opp.token_a, best_opp.token_b, best_opp.token_c, best_opp.token_a,
                best_opp.expected_profit_percent
            ),
            strategy: format!(
                "Triangular Arbitrage: Borrow ${:.2} in {}, trade for {} on {}, then to {} on {}, \
                finally back to {} on {}, repay flash loan and keep profit.",
                best_opp.flash_loan_amount_usd, best_opp.token_a, 
                best_opp.token_b, best_opp.dex_ab,
                best_opp.token_c, best_opp.dex_bc,
                best_opp.token_a, best_opp.dex_ca
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
        
        // For this example, we'll estimate AVAX price at $25
        // In a real implementation, this would come from the data provider
        let avax_price_usd = 25.0;
        
        // Gas amounts for different transaction types
        let gas_amount = match tx_type {
            "TRIANGULAR_ARBITRAGE" => 800000, // Triangular arbitrage uses more gas due to additional steps
            "FLASH_ARBITRAGE" => 500000,
            _ => 200000, // Default gas amount
        };
        
        // Calculate cost in USD
        let cost_in_avax = (gas_amount as f64) * (gas_price_wei as f64) / 1_000_000_000_000_000_000.0;
        let cost_in_usd = cost_in_avax * avax_price_usd;
        
        cost_in_usd
    }
    
    // Calculate confidence score for the triangular arbitrage opportunity
    fn calculate_confidence(&self, profit_percent: f64, net_profit: f64) -> f64 {
        // Base confidence from profit percentage (max 0.4)
        let profit_pct_confidence = (profit_percent / 10.0).min(0.4);
        
        // Profit-based confidence (max 0.4)
        let profit_confidence = (net_profit / 1000.0).min(0.4);
        
        // Fixed confidence component (0.2)
        let base_confidence = 0.2;
        
        // Combine all confidence factors
        let confidence = base_confidence + profit_pct_confidence + profit_confidence;
        
        // Ensure confidence is between 0 and 1
        confidence.max(0.0).min(1.0)
    }
}

// Helper function to determine if a token is a stablecoin or major token
fn is_stable_or_major_token(token: &str) -> bool {
    let stables_and_majors = [
        "USDC", "USDT", "DAI", "AVAX", "ETH", "WETH", "WAVAX", "BTC", "WBTC", 
        "USDC.e", "USDT.e", "WETH.e", "WBTC.e", "BTC.b"
    ];
    
    stables_and_majors.iter().any(|&t| token.to_uppercase().contains(t))
}
