use std::sync::Arc;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::data::provider::DataProvider;
use crate::utils::config::LLMConfig;

// Define a SendError type alias that's Send + Sync
type SendError = Box<dyn std::error::Error + Send + Sync>;

/// Market data analysis including various indicators and metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketAnalysis {
    pub timestamp: DateTime<Utc>,
    pub market_trend: MarketTrend,
    pub volatility: VolatilityLevel,
    pub token_correlations: HashMap<String, HashMap<String, f64>>, // Token -> correlated tokens with correlation value
    pub liquidity_assessment: HashMap<String, LiquidityLevel>,     // DEX -> liquidity level
    pub sentiment_score: f64,                                      // -1.0 to 1.0 (negative to positive)
    pub risk_factors: Vec<RiskFactor>,
    pub opportunity_clusters: Vec<OpportunityCluster>,
    pub window_duration_seconds: u32,                             // Duration of the analysis window in seconds
}

/// Assessment of market direction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MarketTrend {
    StrongBullish,
    Bullish,
    Neutral,
    Bearish,
    StrongBearish,
    Mixed,
}

/// Assessment of market volatility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VolatilityLevel {
    VeryLow,
    Low,
    Moderate,
    High,
    VeryHigh,
}

/// Assessment of market liquidity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LiquidityLevel {
    VeryLow,
    Low,
    Moderate,
    High,
    VeryHigh,
}

/// Risk factors identified in the market
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub description: String,
    pub severity: f64,  // 0.0 to 1.0
    pub affected_assets: Vec<String>,
}

/// Types of risk factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskFactorType {
    PriceVolatility,
    LiquidityRisk,
    SmartContractRisk,
    RegulatoryRisk,
    MarketManipulation,
    Divergence,
    FrontRunning,
    Slippage,
    ImpermanentLoss,
}

/// Cluster of related trading opportunities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpportunityCluster {
    pub cluster_id: String,
    pub strategy_type: String,
    pub assets: Vec<String>,
    pub venues: Vec<String>,
    pub estimated_profit_range: (f64, f64),
    pub competition_level: CompetitionLevel,
    pub window_duration_seconds: u64,
}

/// Assessment of competition for a trading opportunity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompetitionLevel {
    VeryLow,
    Low,
    Moderate,
    High,
    VeryHigh,
}

/// The MarketAnalyzer uses AI reasoning to understand current market conditions
pub struct MarketAnalyzer {
    data_provider: Arc<DataProvider>,
    llm_config: LLMConfig,
    historical_analyses: Vec<MarketAnalysis>,
    max_history_items: usize,
}

impl MarketAnalyzer {
    pub fn new(data_provider: Arc<DataProvider>, llm_config: &LLMConfig) -> Self {
        Self {
            data_provider,
            llm_config: llm_config.clone(),
            historical_analyses: Vec::new(),
            max_history_items: 24,  // Store 24 hours of hourly analyses by default
        }
    }

    /// Analyze current market conditions using AI reasoning
    pub async fn analyze_market(&mut self) -> Result<MarketAnalysis, SendError> {
        // 1. Gather raw data
        let market_data = self.data_provider.get_formatted_market_data().await?;
        let gas_info = self.data_provider.get_gas_prices().await?;
        
        // 2. Generate prompt for LLM reasoning
        let prompt = self.generate_analysis_prompt(&market_data, &gas_info).await?;
        
        // 3. Process with LLM
        let llm_response = self.process_with_llm(&prompt).await?;
        
        // 4. Parse LLM response into structured analysis
        let analysis = self.parse_llm_response(&llm_response)?;
        
        // 5. Store in history and return
        self.add_to_history(analysis.clone());
        
        Ok(analysis)
    }
    
    /// Generate a prompt for the LLM to analyze market conditions
    async fn generate_analysis_prompt(&self, market_data: &str, gas_info: &crate::data::provider::GasInfo) -> Result<String, SendError> {
        let mut prompt = String::new();
        
        // Context and instruction
        prompt.push_str("You are an expert crypto market analyst. Analyze the following market data and provide insights.\n\n");
        
        // Market data section
        prompt.push_str("## Market Data\n");
        prompt.push_str(market_data);
        prompt.push_str("\n\n");
        
        // Gas information
        prompt.push_str("## Gas Information\n");
        prompt.push_str(&format!("Fast Gas Price: {} gwei\n", gas_info.fast));
        prompt.push_str(&format!("Standard Gas Price: {} gwei\n", gas_info.standard));
        prompt.push_str(&format!("Standard Gas Price: {} gwei\n", gas_info.standard)); // Using standard instead of slow
        prompt.push_str(&format!("Base Fee: {} gwei\n", gas_info.base_fee));
        prompt.push_str("\n\n");
        
        // Historical context if available
        if !self.historical_analyses.is_empty() {
            prompt.push_str("## Recent Market Trends\n");
            for (i, historical) in self.historical_analyses.iter().rev().take(3).enumerate() {
                prompt.push_str(&format!("Analysis from {} hours ago:\n", i+1));
                prompt.push_str(&format!("- Market Trend: {:?}\n", historical.market_trend));
                prompt.push_str(&format!("- Volatility: {:?}\n", historical.volatility));
                prompt.push_str(&format!("- Sentiment: {:.2}\n", historical.sentiment_score));
                prompt.push_str("\n");
            }
            prompt.push_str("\n");
        }
        
        // Analysis request
        prompt.push_str("## Analysis Request\n");
        prompt.push_str("Provide a comprehensive market analysis with the following components:\n");
        prompt.push_str("1. Overall market trend (StrongBullish, Bullish, Neutral, Bearish, StrongBearish, or Mixed)\n");
        prompt.push_str("2. Current volatility level (VeryLow, Low, Moderate, High, VeryHigh)\n");
        prompt.push_str("3. Token correlations (list at least 3 pairs of tokens with strong correlations)\n");
        prompt.push_str("4. Liquidity assessment for major DEXes\n");
        prompt.push_str("5. Market sentiment score (-1.0 to 1.0)\n");
        prompt.push_str("6. Risk factors (identify at least 2 specific risks in the current market)\n");
        prompt.push_str("7. Opportunity clusters (identify at least 2 clusters of trading opportunities)\n");
        prompt.push_str("\nFormat your response as a structured JSON object matching these categories.\n");
        
        Ok(prompt)
    }
    
    /// Process prompt with LLM to get market analysis
    async fn process_with_llm(&self, prompt: &str) -> Result<String, SendError> {
        // Create a system prompt to help Claude understand the task
        let system_prompt = r#"You are an expert crypto trading AI assistant. Your task is to analyze market data and provide structured analysis.
        Your response must be valid JSON with the following structure:
        {
            "market_trend": "Bullish" | "Bearish" | "Neutral" | "Mixed" | "StrongBullish" | "StrongBearish",
            "volatility": "VeryLow" | "Low" | "Moderate" | "High" | "VeryHigh",
            "token_correlations": { "TOKEN": {"OTHER_TOKEN": correlation_value, ...}, ... },
            "liquidity_assessment": { "DEX_NAME": "VeryLow" | "Low" | "Moderate" | "High" | "VeryHigh", ... },
            "sentiment_score": float_between_negative_one_and_one,
            "window_duration_seconds": integer_duration_in_seconds,
            "risk_factors": [
                {
                    "factor_type": "PriceVolatility" | "LiquidityRisk" | "SmartContractRisk" | "RegulatoryRisk" | "MarketManipulation" | "Divergence" | "FrontRunning" | "Slippage" | "ImpermanentLoss",
                    "description": "Description of the risk factor",
                    "severity": float_between_zero_and_one,
                    "affected_assets": ["asset_symbol", ...]
                },
                ...
            ],
            "opportunity_clusters": [
                {
                    "cluster_id": "unique_id_string",
                    "strategy_type": "Arbitrage" | "Liquidation" | "MarketMaking" | "Yield",
                    "assets": ["asset_symbol", ...],
                    "venues": ["venue_name", ...],
                    "estimated_profit_range": [min_profit_percentage, max_profit_percentage],
                    "competition_level": "VeryLow" | "Low" | "Moderate" | "High" | "VeryHigh",
                    "window_duration_seconds": integer_duration_in_seconds
                },
                ...
            ]
        }"#.to_string();
        
        // Combine the system prompt with the actual market data
        let full_prompt = format!("{}

MARKET DATA:
{}", system_prompt, prompt);
        
        // Create a properly scoped LLM client instance
        let client = crate::models::llm::LLMClient::new(&self.llm_config).await?;
        let llm_client = &client;
        
        // Call the appropriate LLM provider based on the configuration
        let response = match self.llm_config.provider.as_str() {
            "anthropic" => llm_client.call_anthropic(&full_prompt).await?,
            "openai" => llm_client.call_openai(&full_prompt).await?,
            _ => return Err(format!("Unsupported LLM provider: {}", self.llm_config.provider).into()),
        };
        
        // The response should be a JSON string that matches our MarketAnalysis structure
        Ok(response)
    }
    
    /// Parse LLM response into structured MarketAnalysis
    fn parse_llm_response(&self, llm_response: &str) -> Result<MarketAnalysis, SendError> {
        // First, attempt to extract JSON from the response if it contains other text
        let json_str = self.extract_json_from_response(llm_response);
        
        // Parse the JSON into a temporary Value
        let mut json_value: serde_json::Value = serde_json::from_str(&json_str)?;
        
        // Add the timestamp field if it doesn't exist
        if !json_value.as_object().unwrap().contains_key("timestamp") {
            // Create a timestamp in the correct format (RFC3339/ISO8601)
            let now = chrono::Utc::now();
            let timestamp_str = now.to_rfc3339();
            
            // Add it to the JSON value
            json_value["timestamp"] = serde_json::Value::String(timestamp_str);
        }
        
        // Add window_duration_seconds if it doesn't exist
        if !json_value.as_object().unwrap().contains_key("window_duration_seconds") {
            // Default to 3600 seconds (1 hour)
            json_value["window_duration_seconds"] = serde_json::Value::Number(serde_json::Number::from(3600));
        }
        
        // Now deserialize the updated JSON into a MarketAnalysis struct
        let analysis = serde_json::from_value(json_value)?;
        
        Ok(analysis)
    }
    
    /// Extract JSON from a potentially non-JSON response
    fn extract_json_from_response(&self, response: &str) -> String {
        // If the response is already valid JSON, return it directly
        if let Ok(_) = serde_json::from_str::<serde_json::Value>(response) {
            return response.to_string();
        }
        
        // Look for JSON content between curly braces
        if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                if end > start {
                    return response[start..=end].to_string();
                }
            }
        }
        
        // Look for JSON content between triple backticks
        let re = regex::Regex::new(r"```(?:json)?\s*\n?(.+?)\n?```").unwrap();
        if let Some(caps) = re.captures_iter(response)
            .filter_map(|cap| {
                let content = cap.get(1)?.as_str().trim();
                if content.starts_with('{') && content.ends_with('}') {
                    Some(content.to_string())
                } else {
                    None
                }
            })
            .next() {
            return caps;
        }
        
        // If no JSON found, return the original response (which will likely cause an error)
        response.to_string()
    }
    
    /// Add analysis to historical record
    fn add_to_history(&mut self, analysis: MarketAnalysis) {
        self.historical_analyses.push(analysis);
        
        // Trim history if needed
        if self.historical_analyses.len() > self.max_history_items {
            self.historical_analyses.remove(0);
        }
    }
    
    /// Get historical analyses for trend analysis
    pub fn get_historical_analyses(&self) -> &Vec<MarketAnalysis> {
        &self.historical_analyses
    }
}
