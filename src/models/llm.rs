use crate::utils::config::LLMConfig;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

// Define a SendError type alias that's Send + Sync
type SendError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
pub struct LLMClient {
    client: Client,
    config: LLMConfig,
    api_base_url: String,
}

// OpenAI API structures
#[derive(Debug, Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<Message>,
    temperature: f32,
    max_tokens: u32,
    top_p: f32,
    presence_penalty: f32,
    frequency_penalty: f32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenAIResponse {
    id: String,
    object: String,
    created: u64,
    model: String,
    choices: Vec<Choice>,
    usage: Usage,
}

#[derive(Debug, Deserialize)]
struct Choice {
    index: u32,
    message: Message,
    finish_reason: String,
}

#[derive(Debug, Deserialize)]
struct Usage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

// Anthropic API structures
#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    temperature: f32,
    messages: Vec<Message>,
    // Claude 4 may support additional parameters
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    id: String,
    model: String,
    content: Vec<AnthropicContent>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContent {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

// Custom error type for API calls
#[derive(Debug)]
enum ApiError {
    RateLimitExceeded,
    AuthenticationError,
    BadRequest(String),
    ServerError,
    NetworkError,
    DeserializationError(String),
    Other(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            Self::AuthenticationError => write!(f, "Authentication error"),
            Self::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            Self::ServerError => write!(f, "Server error"),
            Self::NetworkError => write!(f, "Network error"),
            Self::DeserializationError(msg) => write!(f, "Failed to deserialize response: {}", msg),
            Self::Other(msg) => write!(f, "Other error: {}", msg),
        }
    }
}

impl Error for ApiError {}

impl From<reqwest::Error> for ApiError {
    fn from(error: reqwest::Error) -> Self {
        if error.is_status() {
            match error.status() {
                Some(StatusCode::TOO_MANY_REQUESTS) => Self::RateLimitExceeded,
                Some(StatusCode::UNAUTHORIZED) => Self::AuthenticationError,
                Some(status) if status.is_client_error() => Self::BadRequest(format!("{}", status)),
                Some(status) if status.is_server_error() => Self::ServerError,
                _ => Self::Other(format!("{}", error)),
            }
        } else if error.is_timeout() || error.is_connect() {
            Self::NetworkError
        } else {
            Self::Other(format!("{}", error))
        }
    }
}

impl LLMClient {
    pub async fn new(config: &LLMConfig) -> Result<Arc<Self>, SendError> {
        let api_base_url = match config.provider.as_str() {
            "openai" => "https://api.openai.com/v1/chat/completions".to_string(),
            "anthropic" => "https://api.anthropic.com/v1/messages".to_string(),
            _ => return Err(format!("Unsupported LLM provider: {}", config.provider).into()),
        };

        // Create a client with custom timeouts
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        
        Ok(Arc::new(Self {
            client,
            config: config.clone(),
            api_base_url,
        }))
    }

    pub async fn get_trading_strategy(
        &self,
        market_data: &str,
        current_positions: &str,
        risk_parameters: &str,
    ) -> Result<String, SendError> {
        let prompt = format!(
            "You are an expert cryptocurrency trading algorithm specialized in Avalanche blockchain trading. \
            Analyze the following market data and suggest the optimal trading strategy for maximum profit.\n\n\
            MARKET DATA:\n{}\n\n\
            CURRENT POSITIONS:\n{}\n\n\
            RISK PARAMETERS:\n{}\n\n\
            Based on the market data and current positions, identify profitable trading opportunities \
            considering arbitrage between DEXes, favorable entry/exit points, and market trends.\n\n\
            Provide your analysis and trading strategy in the following JSON format:\n\
            {{\n\
              \"market_analysis\": \"Detailed analysis of current market conditions and trends\",\n\
              \"strategy\": \"Clear description of the trading strategy\",\n\
              \"actions\": [\n\
                {{ \"action\": \"BUY|SELL\", \"asset\": \"Asset symbol\", \"amount\": \"Amount to trade\", \"reason\": \"Reasoning behind this action\" }},\n\
                ...\n\
              ],\n\
              \"risk_assessment\": \"Assessment of strategy risks\",\n\
              \"confidence_score\": 0.0-1.0\n\
            }}\n\n\
            Be sure your confidence_score accurately reflects your certainty in the strategy, \
            and only recommend actions that have strong justification based on the data provided.",
            market_data, current_positions, risk_parameters
        );

        // Use retry logic for API calls
        let mut attempts = 0;
        let max_attempts = self.config.retry_attempts;
        let backoff_ms = self.config.backoff_ms;

        loop {
            attempts += 1;
            let result = match self.config.provider.as_str() {
                "openai" => self.call_openai(&prompt).await,
                "anthropic" => self.call_anthropic(&prompt).await,
                _ => Err(ApiError::Other(format!("Unsupported LLM provider: {}", self.config.provider)).into()),
            };

            match result {
                Ok(response) => return Ok(response),
                Err(e) => {
                    // Check if we should retry based on error type
                    if attempts >= max_attempts {
                        return Err(format!("Failed after {} attempts: {}", max_attempts, e).into());
                    }

                    let should_retry = match e.downcast_ref::<ApiError>() {
                        Some(ApiError::RateLimitExceeded) => true,
                        Some(ApiError::ServerError) => true,
                        Some(ApiError::NetworkError) => true,
                        _ => false,
                    };

                    if !should_retry {
                        return Err(e);
                    }

                    // Exponential backoff
                    let backoff = u64::from(backoff_ms) * 2u64.pow(u32::from(attempts - 1));
                    println!("API call failed with error: {}. Retrying in {}ms (attempt {}/{})", 
                        e, backoff, attempts, max_attempts);
                    time::sleep(Duration::from_millis(backoff as u64)).await;
                }
            }
        }
    }

    pub async fn analyze_market_opportunity(
        &self,
        dex_pair_info: &str,
        gas_prices: &str,
    ) -> Result<String, SendError> {
        let prompt = format!(
            "You are an expert in DeFi arbitrage and market making. \
            Analyze the following DEX pair information and gas prices to identify potential \
            arbitrage or market making opportunities.\n\n\
            DEX PAIR INFO:\n{}\n\n\
            GAS PRICES:\n{}\n\n\
            Provide your analysis in the following JSON format:\n\
            {{\n\
              \"opportunity_type\": \"ARBITRAGE|MARKET_MAKING|NONE\",\n\
              \"profit_potential\": \"Estimated profit in USD\",\n\
              \"execution_strategy\": \"Step-by-step execution plan\",\n\
              \"gas_cost_estimate\": \"Estimated gas cost in USD\",\n\
              \"net_profit\": \"Profit after gas costs\",\n\
              \"confidence\": 0.0-1.0\n\
            }}",
            dex_pair_info, gas_prices
        );

        // Use the same retry logic as get_trading_strategy
        let mut attempts = 0;
        let max_attempts = self.config.retry_attempts;
        let backoff_ms = self.config.backoff_ms;

        loop {
            attempts += 1;
            let result = match self.config.provider.as_str() {
                "openai" => self.call_openai(&prompt).await,
                "anthropic" => self.call_anthropic(&prompt).await,
                _ => Err(ApiError::Other(format!("Unsupported LLM provider: {}", self.config.provider)).into()),
            };

            match result {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempts >= max_attempts {
                        return Err(format!("Failed after {} attempts: {}", max_attempts, e).into());
                    }

                    let should_retry = match e.downcast_ref::<ApiError>() {
                        Some(ApiError::RateLimitExceeded) => true,
                        Some(ApiError::ServerError) => true,
                        Some(ApiError::NetworkError) => true,
                        _ => false,
                    };

                    if !should_retry {
                        return Err(e);
                    }

                    let backoff = u64::from(backoff_ms) * 2u64.pow(u32::from(attempts - 1));
                    println!("API call failed with error: {}. Retrying in {}ms (attempt {}/{})", 
                        e, backoff, attempts, max_attempts);
                    time::sleep(Duration::from_millis(backoff as u64)).await;
                }
            }
        }
    }

    pub async fn call_openai(&self, prompt: &str) -> Result<String, SendError> {
        let request = OpenAIRequest {
            model: self.config.model.clone(),
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            temperature: self.config.temperature,
            max_tokens: self.config.max_tokens,
            top_p: 1.0,                // Default value
            presence_penalty: 0.0,      // Default value
            frequency_penalty: 0.0,     // Default value
        };

        let response_result = self.client
            .post(&self.api_base_url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .json(&request)
            .send()
            .await;

        let response = match response_result {
            Ok(resp) => resp,
            Err(e) => return Err(ApiError::from(e).into()),
        };

        // Check status code
        let status = response.status();
        if !status.is_success() {
            match status.as_u16() {
                429 => return Err(ApiError::RateLimitExceeded.into()),
                401 | 403 => return Err(ApiError::AuthenticationError.into()),
                400..=499 => {
                    let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                    return Err(ApiError::BadRequest(error_text).into());
                },
                500..=599 => return Err(ApiError::ServerError.into()),
                _ => return Err(ApiError::Other(format!("Unexpected status code: {}", status)).into()),
            }
        }

        // Parse response
        let parsed_response = match response.json::<OpenAIResponse>().await {
            Ok(parsed) => parsed,
            Err(e) => return Err(ApiError::DeserializationError(e.to_string()).into()),
        };

        if let Some(choice) = parsed_response.choices.first() {
            Ok(choice.message.content.clone())
        } else {
            Err(ApiError::Other("No response choices from OpenAI API".to_string()).into())
        }
    }

    pub async fn call_anthropic(&self, prompt: &str) -> Result<String, SendError> {
        let request = AnthropicRequest {
            model: self.config.model.clone(), // Should be set to "claude-4.0" in config
            max_tokens: self.config.max_tokens,
            temperature: self.config.temperature,
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            stream: false, // We don't need streaming for trading agent
        };

        let response_result = self.client
            .post(&self.api_base_url)
            .header("Content-Type", "application/json")
            .header("x-api-key", &self.config.api_key)
            .header("anthropic-version", "2023-06-01") // Latest API version for Claude 4
            .json(&request)
            .send()
            .await;

        let response = match response_result {
            Ok(resp) => resp,
            Err(e) => return Err(ApiError::from(e).into()),
        };

        // Check status code
        let status = response.status();
        if !status.is_success() {
            match status.as_u16() {
                429 => return Err(ApiError::RateLimitExceeded.into()),
                401 | 403 => return Err(ApiError::AuthenticationError.into()),
                400..=499 => {
                    let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                    return Err(ApiError::BadRequest(error_text).into());
                },
                500..=599 => return Err(ApiError::ServerError.into()),
                _ => return Err(ApiError::Other(format!("Unexpected status code: {}", status)).into()),
            }
        }

        // Parse response
        let parsed_response = match response.json::<AnthropicResponse>().await {
            Ok(parsed) => parsed,
            Err(e) => return Err(ApiError::DeserializationError(e.to_string()).into()),
        };

        // Extract the text from the first content block of type "text"
        for content in parsed_response.content {
            if content.content_type == "text" {
                return Ok(content.text);
            }
        }

        Err(ApiError::Other("No text content in Anthropic API response".to_string()).into())
    }
}
