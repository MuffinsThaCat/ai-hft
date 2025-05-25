use std::error::Error;
use std::sync::Arc;
use std::collections::HashMap;
use std::env;
use serde::{Deserialize, Serialize};
use regex::Regex;

// Define a SendError type alias that's Send + Sync
type SendError = Box<dyn std::error::Error + Send + Sync>;

// Import the anthropic crate for API integration
#[allow(unused_imports)]
use anthropic::client::ClientBuilder;
#[allow(unused_imports)]
use anthropic::config::AnthropicConfig;
#[allow(unused_imports)]
use anthropic::types::CompleteRequestBuilder;
#[allow(unused_imports)]
use anthropic::{AI_PROMPT, HUMAN_PROMPT};

use crate::data::provider::DataProvider;
// Import model structs with aliases
use crate::models::strategy::{StrategyResult as ModelStrategyResult, TradingAction as ModelTradingAction};
use crate::reasoning::analyzer::{MarketAnalysis, RiskFactorType};
use crate::strategies::arbitrage::ArbitrageStrategy;
use crate::strategies::liquidation::LiquidationStrategy;
use crate::strategies::flash_arbitrage::FlashArbitrageStrategy;
use crate::strategies::triangular_arbitrage::TriangularArbitrageStrategy;
use crate::utils::config::{StrategyConfig, LLMConfig, SecurityConfig};

/// Represents the AI's reasoning about a potential trading strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyReasoning {
    pub strategy_id: String,
    pub strategy_type: String,
    pub reasoning_process: Vec<ReasoningStep>,
    pub confidence: f64,
    pub expected_profit_range: (f64, f64),
    pub risk_factors: Vec<RiskFactor>,
}

/// A step in the AI's reasoning process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    pub step_id: u32,
    pub observation: String,
    pub conclusion: String,
    pub supporting_data: Option<HashMap<String, String>>,
}

/// A risk factor identified by the AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub severity: u32, // 1-10 scale
    pub description: String,
    pub mitigation_strategy: Option<String>,
}

/// The main reasoning engine for AI-driven trading strategies
pub struct ReasoningEngine {
    data_provider: Arc<DataProvider>,
    arbitrage_strategy: ArbitrageStrategy,
    liquidation_strategy: LiquidationStrategy,
    flash_arbitrage_strategy: FlashArbitrageStrategy,
    triangular_arbitrage_strategy: TriangularArbitrageStrategy,
    strategy_config: StrategyConfig,
    llm_config: LLMConfig,
    security_config: SecurityConfig,
    last_analysis: Option<MarketAnalysis>,
    strategy_history: Vec<StrategyReasoning>,
}

impl ReasoningEngine {
    /// Helper method to extract patterns from the LLM response using regex
    fn extract_pattern(&self, text: &str, pattern: &str) -> Option<String> {
        let re = Regex::new(pattern).ok()?;
        re.captures(text).and_then(|cap| {
            cap.get(1).map(|m| m.as_str().to_string())
        })
    }
    // Conversion function to convert from manager's StrategyResult to model's StrategyResult
    fn convert_manager_strategy_result(&self, manager_result: crate::strategies::manager::StrategyResult) -> ModelStrategyResult {
        // Create model trading actions from manager trading actions
        let model_actions: Vec<ModelTradingAction> = manager_result.actions
            .iter()
            .map(|action| {
                ModelTradingAction {
                    action_type: match action.action_type {
                        crate::strategies::manager::ActionType::Buy => crate::models::strategy::ActionType::Buy,
                        crate::strategies::manager::ActionType::Sell => crate::models::strategy::ActionType::Sell,
                    },
                    asset: action.asset.clone(),
                    amount: action.amount.clone(),
                    reason: action.reason.clone(),
                    target_address: action.target_address.clone(),
                    action_data: action.action_data.clone(),
                    gas_price: action.gas_price.clone(),
                    nonce: action.nonce,
                }
            })
            .collect();
        
        // Create and return the model StrategyResult
        ModelStrategyResult {
            strategy_type: manager_result.strategy.clone(),
            description: manager_result.market_analysis.clone(),
            confidence: manager_result.confidence_score,
            actions: model_actions,
            expected_profit_usd: 0.0, // Default value, adjust as needed
            risk_level: 1, // Default value, adjust as needed
        }
    }
    
    pub fn new(
        data_provider: Arc<DataProvider>,
        arbitrage_strategy: ArbitrageStrategy,
        liquidation_strategy: LiquidationStrategy,
        flash_arbitrage_strategy: FlashArbitrageStrategy,
        triangular_arbitrage_strategy: TriangularArbitrageStrategy,
        strategy_config: &StrategyConfig,
        llm_config: &LLMConfig,
        security_config: &SecurityConfig,
    ) -> Self {
        Self {
            data_provider,
            arbitrage_strategy,
            liquidation_strategy,
            flash_arbitrage_strategy,
            triangular_arbitrage_strategy,
            strategy_config: strategy_config.clone(),
            llm_config: llm_config.clone(),
            security_config: security_config.clone(),
            last_analysis: None,
            strategy_history: Vec::new(),
        }
    }
    
    /// Generate strategy based on market analysis and AI reasoning
    pub async fn generate_strategy(&mut self) -> Result<Option<ModelStrategyResult>, SendError> {
        // Ensure we have a market analysis
        if self.last_analysis.is_none() {
            return Ok(None);
        }
        
        let analysis = self.last_analysis.as_ref().unwrap();
        
        // 1. Generate a prompt for the LLM
        let prompt = self.generate_strategy_prompt(&analysis)?;
        
        // 2. Process with LLM to get reasoning
        let llm_response = self.process_with_llm(&prompt).await?;
        
        // 3. Parse LLM response
        let reasoning = self.parse_llm_response(&llm_response)?;
        
        // 4. Store reasoning in history
        self.strategy_history.push(reasoning.clone());
        
        // 5. Execute the selected strategy based on reasoning
        self.execute_selected_strategy(&reasoning).await
    }
    
    /// Generate a prompt for the LLM to reason about strategy selection
    fn generate_strategy_prompt(&self, analysis: &MarketAnalysis) -> Result<String, SendError> {
        // Construct a prompt with market analysis data
        let prompt = format!(
            "You are an AI reasoning engine for a cryptocurrency trading system. Based on the following market data, reason about the optimal trading strategy:\n\n\
            Market Trend: {:?}\n\
            Volatility: {:?}\n\
            Opportunity Clusters: {}\n\
            Risk Factors: {}\n\n\
            Analyze this data and reason about which trading strategy would be most profitable. \
            Consider arbitrage, liquidation, or holding as options. \
            If you recommend a strategy, explain your reasoning, assign a confidence score (0-1), \
            and estimate the potential profit range in USD.",
            analysis.market_trend,
            analysis.volatility,
            analysis.opportunity_clusters.iter()
                .map(|c| format!("[{:?}]", c))
                .collect::<Vec<String>>()
                .join(", "),
            analysis.risk_factors.iter()
                .map(|r| format!("[{:?}: {}]", r.factor_type, r.severity))
                .collect::<Vec<String>>()
                .join(", ")
        );
        
        Ok(prompt)
    }
    
    /// Process prompt with LLM (Anthropic Claude)
    async fn process_with_llm(&self, prompt: &str) -> Result<String, SendError> {
        // Get API key from environment variable or config
        let api_key = env::var("ANTHROPIC_API_KEY")
            .map_err(|_| "ANTHROPIC_API_KEY environment variable not set")?;
            
        // Initialize the Anthropic client
        let client = ClientBuilder::default()
            .api_key(api_key)
            .build()?;
        
        // Create the system prompt
        let system_prompt = "You are an expert cryptocurrency trading assistant. You specialize in analyzing market conditions, \
            identifying arbitrage opportunities, and formulating effective trading strategies for cryptocurrency markets. \
            Respond in a clear, structured format with: Strategy Type, Confidence Score (0.0-1.0), \
            Expected Profit Range, and Risk Factors with severity ratings (1-10).";
        
        // Create the API call request for Claude model
        let complete_request = CompleteRequestBuilder::default()
            .prompt(format!("{HUMAN_PROMPT}{}{system_prompt}{AI_PROMPT}", prompt))
            .model("claude-2".to_string())
            .max_tokens_to_sample(1000_usize)
            .stop_sequences(vec![HUMAN_PROMPT.to_string()])
            .build()?;
        
        // Make the API call
        let response = client.complete(complete_request).await
            .map_err(|e| format!("Anthropic API error: {}", e))?;
        
        Ok(response.completion)
    }
    
    /// Parse LLM response into a structured reasoning
    fn parse_llm_response(&self, response: &str) -> Result<StrategyReasoning, SendError> {
        // Extract the key components from the structured response
        
        // Extract strategy type using regex
        let strategy_type = match self.extract_pattern(response, r"Strategy(?:\s+Type)?:\s*([\w\s]+)") {
            Some(s) => s.trim().to_string(),
            None => return Err("Could not extract strategy type from LLM response".into()),
        };
        
        // Extract confidence score
        let confidence = match self.extract_pattern(response, r"Confidence(?:\s+Score)?:\s*(0\.[0-9]+|1\.0|1)") {
            Some(s) => s.trim().parse::<f64>().unwrap_or(0.0),
            None => 0.0, // Default if not found
        };
        
        // Extract profit range
        let profit_range = self.extract_pattern(response, r"(?:Expected\s+)?Profit\s+Range:\s*([^\n]+)");
        
        // Extract reasoning steps
        let mut reasoning_steps = Vec::new();
        
        // Look for numbered steps or bullet points in the response
        for (i, line) in response.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.len() < 3 { continue; }
            
            // Match numbered points (1., 2., etc) or bullet points
            if (line.starts_with("- ") || line.starts_with("* ") || 
                (line.chars().next().unwrap().is_digit(10) && line.contains(".")))
                && !line.to_lowercase().contains("strategy:") 
                && !line.to_lowercase().contains("confidence:") 
                && !line.to_lowercase().contains("profit range:") 
                && !line.to_lowercase().contains("risk factor") {
                
                reasoning_steps.push(ReasoningStep {
                    step_id: i as u32,
                    observation: line.chars().skip_while(|c| !c.is_alphabetic()).collect::<String>().trim().to_string(),
                    conclusion: "Analysis based on market data".to_string(),
                    supporting_data: None,
                });
            }
        }
        
        // Extract risk factors
        let mut risk_factors = Vec::new();
        
        // Look for risk factors section
        if let Some(risk_section) = response.to_lowercase().find("risk factor") {
            let risk_text = &response[risk_section..]; 
            
            // Parse individual risk factors
            for line in risk_text.lines() {
                let line = line.trim();
                if line.is_empty() { continue; }
                
                // Match patterns like "Slippage (3)" or "Market Movement (4)"
                if let Some(cap) = regex::Regex::new(r"([\w\s]+)\s*\(([1-9]|10)\)").unwrap().captures(line) {
                    risk_factors.push(RiskFactor {
                        factor_type: match cap[1].trim().to_lowercase().as_str() {
                            s if s.contains("liquidity") => RiskFactorType::LiquidityRisk,
                            s if s.contains("volatility") => RiskFactorType::PriceVolatility,
                            s if s.contains("execution") || s.contains("smart contract") => RiskFactorType::SmartContractRisk,
                            s if s.contains("slippage") => RiskFactorType::Slippage,
                            s if s.contains("front") => RiskFactorType::FrontRunning,
                            _ => RiskFactorType::PriceVolatility,
                        },
                        severity: cap[2].parse::<u32>().unwrap_or(5),
                        description: cap[1].trim().to_string(),
                        mitigation_strategy: None,
                    });
                }
            }
        }
        
        // Determine the recommended action from the strategy type
        let recommended_action = match strategy_type.to_lowercase().as_str() {
            "arbitrage" => "Execute arbitrage between exchanges",
            "flash arbitrage" | "flash loan arbitrage" => "Execute flash loan arbitrage",
            "liquidation" => "Execute liquidation of underwater positions",
            "hold" => "Hold current positions",
            _ => "Monitor market conditions",
        };
        
        // Extract confidence (simplified)
        let confidence_str = response
            .lines()
            .find(|line| line.contains("Confidence:"))
            .map(|line| line.split(":").nth(1).unwrap_or("0.5").trim())
            .unwrap_or("0.5");
        let confidence = confidence_str.parse::<f64>().unwrap_or(0.5);
        
        // Extract profit range (simplified)
        let profit_range_str = response
            .lines()
            .find(|line| line.contains("Profit Range:"))
            .map(|line| line.split(":").nth(1).unwrap_or("$0-$0").trim())
            .unwrap_or("$0-$0");
        // Parse profit range (very simplified)
        let profit_range = if profit_range_str.contains("-") {
            let parts: Vec<&str> = profit_range_str.split("-").collect();
            let min = parts[0].trim().trim_start_matches("$").parse::<f64>().unwrap_or(0.0);
            let max = parts[1].trim().trim_start_matches("$").parse::<f64>().unwrap_or(0.0);
            (min, max)
        } else {
            (0.0, 0.0)
        };
        
        // Parse the timestamp from the current time
        let timestamp = chrono::Utc::now();
        
        // Enhance reasoning steps with more detailed conclusions
        let reasoning_steps_with_impacts = reasoning_steps.iter().enumerate().map(|(i, step)| {
            let mut step = step.clone();
            // Add more detailed conclusions based on the observation
            let obs_lower = step.observation.to_lowercase();
            step.conclusion = if obs_lower.contains("price") || obs_lower.contains("discrepanc") {
                format!("Identified potential {} opportunity", strategy_type)
            } else if obs_lower.contains("volatility") || obs_lower.contains("fluctuat") {
                "Market conditions suggest cautious approach".to_string()
            } else if obs_lower.contains("liquidity") {
                "Sufficient liquidity exists for this strategy".to_string()
            } else {
                "Analysis supports this trading approach".to_string()
            };
            step
        }).collect();
        
        // Add default mitigation strategies if none were provided
        let risk_factors_with_mitigations = risk_factors.iter().map(|factor| {
            let mut factor = factor.clone();
            if factor.mitigation_strategy.is_none() {
                // Add reasonable mitigation strategy based on the type of risk
                let mitigation = match factor.factor_type {
                    RiskFactorType::LiquidityRisk => "Split orders across multiple exchanges",
                    RiskFactorType::PriceVolatility => "Use limit orders with tight spreads",
                    RiskFactorType::Slippage => "Set appropriate slippage tolerances",
                    RiskFactorType::SmartContractRisk => "Use verified contracts and limit exposure",
                    _ => "Monitor closely and be ready to adjust",
                };
                factor.mitigation_strategy = Some(mitigation.to_string());
            }
            factor
        }).collect();
        
        // Format expected profit range as a string (e.g., "$100-$500")
        let profit_range_str = format!("${}-${}", profit_range.0, profit_range.1);
        
        // Create a unique strategy ID based on timestamp
        let strategy_id = format!("strat-{}", timestamp.timestamp());
        
        // Create and return the structured reasoning
        Ok(StrategyReasoning {
            strategy_id,
            strategy_type: strategy_type.to_string(),
            reasoning_process: reasoning_steps_with_impacts,
            confidence,
            expected_profit_range: profit_range,
            risk_factors: risk_factors_with_mitigations,
        })
    }
    
    
    
    /// Update the reasoning engine with new market analysis
    pub fn update_market_analysis(&mut self, analysis: MarketAnalysis) {
        self.last_analysis = Some(analysis);
    }
    
    /// Execute the selected strategy based on the reasoning
    async fn execute_selected_strategy(&self, reasoning: &StrategyReasoning) -> Result<Option<ModelStrategyResult>, SendError> {
        // Based on the strategy type from the reasoning, execute the appropriate strategy
        match reasoning.strategy_type.as_str() {
            "Arbitrage" => {
                // If the confidence is high enough, execute the arbitrage strategy
                if reasoning.confidence >= self.strategy_config.min_confidence_score as f64 {
                    // Execute the arbitrage strategy with the current parameters
                    let manager_result = self.arbitrage_strategy.generate_strategy().await?;
                    
                    // Convert and enhance the strategy result with reasoning
                    if let Some(manager_strategy) = manager_result {
                        // The arbitrage strategy returns a manager::StrategyResult
                        let mut model_strategy = self.convert_manager_strategy_result(manager_strategy);
                        // Add reasoning details to the strategy
                        self.enhance_strategy_with_reasoning(&mut model_strategy, reasoning);
                        Ok(Some(model_strategy))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            },
            "Liquidation" => {
                // If the confidence is high enough, execute the liquidation strategy
                if reasoning.confidence >= self.strategy_config.min_confidence_score as f64 {
                    // Execute the liquidation strategy with the current parameters
                    let model_result = self.liquidation_strategy.generate_strategy().await?;
                    
                    // Convert and enhance the strategy result with reasoning
                    if let Some(mut model_strategy) = model_result {
                        // The liquidation strategy already returns a models::strategy::StrategyResult (ModelStrategyResult)
                        // No conversion needed, just enhance with reasoning
                        self.enhance_strategy_with_reasoning(&mut model_strategy, reasoning);
                        Ok(Some(model_strategy))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            },
            "FlashArbitrage" => {
                // If the confidence is high enough, execute the flash arbitrage strategy
                if reasoning.confidence >= self.strategy_config.min_confidence_score as f64 {
                    // Execute the flash arbitrage strategy with the current parameters
                    let manager_result = self.flash_arbitrage_strategy.generate_strategy().await?;
                    
                    // Convert and enhance the strategy result with reasoning
                    if let Some(manager_strategy) = manager_result {
                        // The flash arbitrage strategy returns a manager::StrategyResult
                        let mut model_strategy = self.convert_manager_strategy_result(manager_strategy);
                        // Add reasoning details to the strategy
                        self.enhance_strategy_with_reasoning(&mut model_strategy, reasoning);
                        Ok(Some(model_strategy))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            },
            "TriangularArbitrage" => {
                // If the confidence is high enough, execute the triangular arbitrage strategy
                if reasoning.confidence >= self.strategy_config.min_confidence_score as f64 {
                    // Execute the triangular arbitrage strategy with the current parameters
                    let manager_result = self.triangular_arbitrage_strategy.generate_strategy().await?;
                    
                    // Convert and enhance the strategy result with reasoning
                    if let Some(manager_strategy) = manager_result {
                        // The triangular arbitrage strategy returns a manager::StrategyResult
                        let mut model_strategy = self.convert_manager_strategy_result(manager_strategy);
                        // Add reasoning details to the strategy
                        self.enhance_strategy_with_reasoning(&mut model_strategy, reasoning);
                        Ok(Some(model_strategy))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            },
            // Add other strategy types as they are implemented
            _ => Ok(None),
        }
    }
    
    /// Enhance a strategy result with AI reasoning details
    fn enhance_strategy_with_reasoning(&self, strategy: &mut ModelStrategyResult, reasoning: &StrategyReasoning) {
        // Add reasoning to the strategy description
        let reasoning_summary = reasoning.reasoning_process
            .iter()
            .map(|step| format!("{}. {}", step.step_id, step.conclusion))
            .collect::<Vec<String>>()
            .join(" ");
            
        // Add reasoning to description
        strategy.description = format!("{}\n\nReasoning: {}", strategy.description, reasoning_summary);
        
        // Update confidence score with reasoning-based confidence
        strategy.confidence = reasoning.confidence;
        
        // Update expected profit based on reasoning
        let avg_profit = (reasoning.expected_profit_range.0 + reasoning.expected_profit_range.1) / 2.0;
        strategy.expected_profit_usd = avg_profit;
        
        // Risk level could be derived from reasoning as well
        // For now, we'll keep the existing risk level
    }
    
    /// Get reasoning history for analysis
    pub fn get_strategy_history(&self) -> &Vec<StrategyReasoning> {
        &self.strategy_history
    }
}
