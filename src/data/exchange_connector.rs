use crate::models::error::{AgentError, AgentResult};
use crate::models::trading::{OrderBook, PricePoint, Opportunity, MarketData};
use ethers::prelude::*;
use serde::{Deserialize, Serialize};
use log::{info, warn, error, debug};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use reqwest::Client;

/// Exchange connector for fetching real-time market data
pub struct ExchangeConnector {
    /// HTTP client for API requests
    client: Client,
    /// Last update timestamp for each market
    last_updates: HashMap<String, Instant>,
    /// Cached order books to reduce API calls
    order_book_cache: Arc<RwLock<HashMap<String, (OrderBook, Instant)>>>,
    /// API rate limit settings
    rate_limits: RateLimits,
    /// Connection health metrics
    health_metrics: Arc<RwLock<HealthMetrics>>,
}

/// Rate limit settings for each exchange
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RateLimits {
    /// Minimum time between API calls in milliseconds
    min_request_interval_ms: HashMap<String, u64>,
    /// Maximum requests per minute
    max_requests_per_minute: HashMap<String, u32>,
    /// Current request count per minute
    current_request_count: HashMap<String, u32>,
    /// Timestamp when counters were last reset
    counter_reset_time: HashMap<String, Instant>,
}

/// Health metrics for the exchange connector
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct HealthMetrics {
    /// Total number of successful API calls
    pub successful_calls: u64,
    /// Total number of failed API calls
    pub failed_calls: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Connectivity status for each exchange
    pub exchange_status: HashMap<String, bool>,
    /// Last error message for each exchange
    pub last_error: HashMap<String, String>,
    /// Timestamp of last successful update for each exchange
    pub last_successful_update: HashMap<String, String>,
}

impl ExchangeConnector {
    /// Create a new exchange connector
    pub fn new() -> Self {
        // Configure HTTP client with reasonable timeouts for high-frequency trading
        let client = Client::builder()
            .timeout(Duration::from_millis(500))  // 500ms timeout for API calls
            .connect_timeout(Duration::from_millis(200))  // 200ms connection timeout
            .pool_max_idle_per_host(20)  // Keep connections alive for performance
            .build()
            .expect("Failed to build HTTP client");
        
        // Initialize rate limits for major exchanges
        let mut min_request_interval_ms = HashMap::new();
        min_request_interval_ms.insert("uniswap".to_string(), 200);  // 200ms between requests
        min_request_interval_ms.insert("sushiswap".to_string(), 250);
        min_request_interval_ms.insert("traderjoe".to_string(), 200);
        min_request_interval_ms.insert("pangolin".to_string(), 300);
        
        let mut max_requests_per_minute = HashMap::new();
        max_requests_per_minute.insert("uniswap".to_string(), 100);  // 100 requests per minute
        max_requests_per_minute.insert("sushiswap".to_string(), 80);
        max_requests_per_minute.insert("traderjoe".to_string(), 100);
        max_requests_per_minute.insert("pangolin".to_string(), 60);
        
        let rate_limits = RateLimits {
            min_request_interval_ms,
            max_requests_per_minute,
            current_request_count: HashMap::new(),
            counter_reset_time: HashMap::new(),
        };
        
        Self {
            client,
            last_updates: HashMap::new(),
            order_book_cache: Arc::new(RwLock::new(HashMap::new())),
            rate_limits,
            health_metrics: Arc::new(RwLock::new(HealthMetrics::default())),
        }
    }
    
    /// Get real-time order book from an exchange
    pub async fn get_order_book(&self, exchange: &str, token_pair: &str) -> AgentResult<OrderBook> {
        // Check if we can make a request (rate limiting)
        self.check_rate_limit(exchange).await?;
        
        // Check if we have a recent cache entry
        let should_fetch = {
            let cache = self.order_book_cache.read().await;
            let cache_key = format!("{}:{}", exchange, token_pair);
            
            match cache.get(&cache_key) {
                Some((_, timestamp)) => {
                    // Only use cache if it's less than 200ms old for high-frequency trading
                    timestamp.elapsed() > Duration::from_millis(200)
                }
                None => true
            }
        };
        
        if should_fetch {
            // Fetch real data from exchange
            let start_time = Instant::now();
            let result = match exchange.to_lowercase().as_str() {
                "uniswap" => self.fetch_uniswap_order_book(token_pair).await,
                "sushiswap" => self.fetch_sushiswap_order_book(token_pair).await,
                "traderjoe" => self.fetch_traderjoe_order_book(token_pair).await,
                "pangolin" => self.fetch_pangolin_order_book(token_pair).await,
                _ => Err(AgentError::DataProviderError(format!("Unsupported exchange: {}", exchange)))
            };
            
            // Update metrics
            let elapsed = start_time.elapsed();
            self.update_metrics(exchange, result.is_ok(), elapsed.as_millis() as f64).await;
            
            match result {
                Ok(order_book) => {
                    // Update cache
                    let cache_key = format!("{}:{}", exchange, token_pair);
                    let mut cache = self.order_book_cache.write().await;
                    cache.insert(cache_key, (order_book.clone(), Instant::now()));
                    
                    Ok(order_book)
                }
                Err(e) => {
                    // If we have a cached version, use it even if it's a bit old
                    let cache_key = format!("{}:{}", exchange, token_pair);
                    let cache = self.order_book_cache.read().await;
                    
                    if let Some((cached_book, timestamp)) = cache.get(&cache_key) {
                        if timestamp.elapsed() < Duration::from_secs(10) {
                            warn!("Using cached order book for {}/{} due to error: {}", 
                                exchange, token_pair, e);
                            return Ok(cached_book.clone());
                        }
                    }
                    
                    Err(e)
                }
            }
        } else {
            // Use cached data
            let cache_key = format!("{}:{}", exchange, token_pair);
            let cache = self.order_book_cache.read().await;
            let (cached_book, _) = cache.get(&cache_key).unwrap();
            
            Ok(cached_book.clone())
        }
    }
    
    /// Check for cross-exchange arbitrage opportunities
    pub async fn find_arbitrage_opportunities(&self, 
        base_token: &str, 
        quote_token: &str,
        exchanges: &[&str]
    ) -> AgentResult<Vec<Opportunity>> {
        let mut opportunities = Vec::new();
        let token_pair = format!("{}/{}", base_token, quote_token);
        
        let mut best_bid = (0.0, "");
        let mut best_ask = (f64::MAX, "");
        
        // Find best bid and ask across exchanges
        for &exchange in exchanges {
            match self.get_order_book(exchange, &token_pair).await {
                Ok(order_book) => {
                    // Get best bid (highest buy price)
                    if let Some(bid) = order_book.bids.first() {
                        if bid.price > best_bid.0 {
                            best_bid = (bid.price, exchange);
                        }
                    }
                    
                    // Get best ask (lowest sell price)
                    if let Some(ask) = order_book.asks.first() {
                        if ask.price < best_ask.0 {
                            best_ask = (ask.price, exchange);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to get order book for {}: {}", exchange, e);
                    continue;
                }
            }
        }
        
        // Check if there's an arbitrage opportunity
        if best_bid.0 > best_ask.0 && best_bid.1 != best_ask.1 {
            let profit_percent = (best_bid.0 - best_ask.0) / best_ask.0 * 100.0;
            
            // Only consider opportunities with significant profit
            if profit_percent > 0.5 {  // More than 0.5% profit
                let market_data = MarketData {
                    buy_exchange: best_ask.1.to_string(),
                    sell_exchange: best_bid.1.to_string(),
                    buy_price: best_ask.0,
                    sell_price: best_bid.0,
                    timestamp: chrono::Utc::now(),
                };
                
                let opportunity = Opportunity {
                    base_token: base_token.to_string(),
                    quote_token: quote_token.to_string(),
                    profit_percent,
                    market_data,
                    opportunity_id: format!("arb-{}-{}-{}-{}", 
                        base_token, quote_token, best_ask.1, best_bid.1),
                    expires_at: chrono::Utc::now() + chrono::Duration::milliseconds(500),
                };
                
                opportunities.push(opportunity);
            }
        }
        
        Ok(opportunities)
    }
    
    /// Get health metrics for the connector
    pub async fn get_health_metrics(&self) -> HealthMetrics {
        self.health_metrics.read().await.clone()
    }
    
    /// Check if we're within rate limits
    async fn check_rate_limit(&self, exchange: &str) -> AgentResult<()> {
        let exchange = exchange.to_lowercase();
        
        // Check minimum interval between requests
        if let Some(last_update) = self.last_updates.get(&exchange) {
            if let Some(min_interval) = self.rate_limits.min_request_interval_ms.get(&exchange) {
                let elapsed = last_update.elapsed();
                if elapsed < Duration::from_millis(*min_interval) {
                    // Wait until we can make the next request
                    let wait_time = *min_interval - elapsed.as_millis() as u64;
                    tokio::time::sleep(Duration::from_millis(wait_time)).await;
                }
            }
        }
        
        // Check requests per minute limit
        let reset_interval = Duration::from_secs(60);
        let current_time = Instant::now();
        
        if let Some(reset_time) = self.rate_limits.counter_reset_time.get(&exchange) {
            if reset_time.elapsed() >= reset_interval {
                // Reset counter if a minute has passed
                self.rate_limits.counter_reset_time.insert(exchange.clone(), current_time);
                self.rate_limits.current_request_count.insert(exchange.clone(), 1);
            } else if let Some(count) = self.rate_limits.current_request_count.get(&exchange) {
                if let Some(max_count) = self.rate_limits.max_requests_per_minute.get(&exchange) {
                    if *count >= *max_count {
                        // We've reached the rate limit, wait until the next minute
                        let wait_time = reset_interval - reset_time.elapsed();
                        warn!("Rate limit reached for {}, waiting {:?}", exchange, wait_time);
                        tokio::time::sleep(wait_time).await;
                        
                        // Reset counter
                        self.rate_limits.counter_reset_time.insert(exchange.clone(), Instant::now());
                        self.rate_limits.current_request_count.insert(exchange.clone(), 1);
                    } else {
                        // Increment counter
                        self.rate_limits.current_request_count.insert(exchange.clone(), count + 1);
                    }
                }
            }
        } else {
            // First request to this exchange
            self.rate_limits.counter_reset_time.insert(exchange.clone(), current_time);
            self.rate_limits.current_request_count.insert(exchange.clone(), 1);
        }
        
        Ok(())
    }
    
    /// Update health metrics
    async fn update_metrics(&self, exchange: &str, success: bool, response_time_ms: f64) {
        let mut metrics = self.health_metrics.write().await;
        
        if success {
            metrics.successful_calls += 1;
            metrics.exchange_status.insert(exchange.to_string(), true);
            metrics.last_successful_update.insert(
                exchange.to_string(), 
                chrono::Utc::now().to_rfc3339()
            );
        } else {
            metrics.failed_calls += 1;
            metrics.exchange_status.insert(exchange.to_string(), false);
        }
        
        // Update average response time
        let total_calls = metrics.successful_calls + metrics.failed_calls;
        metrics.avg_response_time_ms = (metrics.avg_response_time_ms * (total_calls - 1) as f64 
            + response_time_ms) / total_calls as f64;
    }
    
    /// Fetch order book from Uniswap
    async fn fetch_uniswap_order_book(&self, token_pair: &str) -> AgentResult<OrderBook> {
        debug!("Fetching Uniswap order book for {}", token_pair);
        
        // In a real implementation, this would make API calls to Uniswap's GraphQL API
        // or connect to their smart contracts directly
        
        // Simplified example for demonstration:
        let (base_token, quote_token) = Self::parse_token_pair(token_pair)?;
        
        // This is where you would make the actual API call
        let url = format!("https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3");
        let query = self.build_uniswap_query(base_token, quote_token);
        
        // Simulating successful response for now
        let bids = vec![
            PricePoint { price: 4010.50, quantity: 1.5 },
            PricePoint { price: 4010.25, quantity: 2.3 },
            PricePoint { price: 4010.00, quantity: 3.8 },
        ];
        
        let asks = vec![
            PricePoint { price: 4011.00, quantity: 2.1 },
            PricePoint { price: 4011.25, quantity: 1.7 },
            PricePoint { price: 4011.50, quantity: 4.2 },
        ];
        
        Ok(OrderBook {
            exchange: "uniswap".to_string(),
            base_token: base_token.to_string(),
            quote_token: quote_token.to_string(),
            bids,
            asks,
            timestamp: chrono::Utc::now(),
        })
    }
    
    /// Fetch order book from SushiSwap
    async fn fetch_sushiswap_order_book(&self, token_pair: &str) -> AgentResult<OrderBook> {
        debug!("Fetching SushiSwap order book for {}", token_pair);
        
        // Similar implementation as Uniswap, but with SushiSwap-specific API
        
        // Simplified example for demonstration:
        let (base_token, quote_token) = Self::parse_token_pair(token_pair)?;
        
        // Simulating successful response for now
        let bids = vec![
            PricePoint { price: 4009.75, quantity: 1.2 },
            PricePoint { price: 4009.50, quantity: 2.1 },
            PricePoint { price: 4009.25, quantity: 3.3 },
        ];
        
        let asks = vec![
            PricePoint { price: 4010.50, quantity: 1.8 },
            PricePoint { price: 4010.75, quantity: 2.5 },
            PricePoint { price: 4011.00, quantity: 3.9 },
        ];
        
        Ok(OrderBook {
            exchange: "sushiswap".to_string(),
            base_token: base_token.to_string(),
            quote_token: quote_token.to_string(),
            bids,
            asks,
            timestamp: chrono::Utc::now(),
        })
    }
    
    /// Fetch order book from TraderJoe
    async fn fetch_traderjoe_order_book(&self, token_pair: &str) -> AgentResult<OrderBook> {
        debug!("Fetching TraderJoe order book for {}", token_pair);
        
        // TraderJoe-specific API implementation
        
        // Simplified example for demonstration:
        let (base_token, quote_token) = Self::parse_token_pair(token_pair)?;
        
        // Simulating successful response for now
        let bids = vec![
            PricePoint { price: 4010.80, quantity: 1.3 },
            PricePoint { price: 4010.60, quantity: 2.2 },
            PricePoint { price: 4010.40, quantity: 3.5 },
        ];
        
        let asks = vec![
            PricePoint { price: 4011.20, quantity: 1.9 },
            PricePoint { price: 4011.40, quantity: 2.4 },
            PricePoint { price: 4011.60, quantity: 3.7 },
        ];
        
        Ok(OrderBook {
            exchange: "traderjoe".to_string(),
            base_token: base_token.to_string(),
            quote_token: quote_token.to_string(),
            bids,
            asks,
            timestamp: chrono::Utc::now(),
        })
    }
    
    /// Fetch order book from Pangolin
    async fn fetch_pangolin_order_book(&self, token_pair: &str) -> AgentResult<OrderBook> {
        debug!("Fetching Pangolin order book for {}", token_pair);
        
        // Pangolin-specific API implementation
        
        // Simplified example for demonstration:
        let (base_token, quote_token) = Self::parse_token_pair(token_pair)?;
        
        // Simulating successful response for now
        let bids = vec![
            PricePoint { price: 4009.90, quantity: 1.4 },
            PricePoint { price: 4009.70, quantity: 2.3 },
            PricePoint { price: 4009.50, quantity: 3.6 },
        ];
        
        let asks = vec![
            PricePoint { price: 4010.30, quantity: 1.7 },
            PricePoint { price: 4010.50, quantity: 2.6 },
            PricePoint { price: 4010.70, quantity: 3.8 },
        ];
        
        Ok(OrderBook {
            exchange: "pangolin".to_string(),
            base_token: base_token.to_string(),
            quote_token: quote_token.to_string(),
            bids,
            asks,
            timestamp: chrono::Utc::now(),
        })
    }
    
    /// Parse token pair string (e.g., "ETH/USDC")
    fn parse_token_pair(token_pair: &str) -> AgentResult<(&str, &str)> {
        let parts: Vec<&str> = token_pair.split('/').collect();
        if parts.len() != 2 {
            return Err(AgentError::DataProviderError(
                format!("Invalid token pair format: {}", token_pair)
            ));
        }
        
        Ok((parts[0], parts[1]))
    }
    
    /// Build GraphQL query for Uniswap
    fn build_uniswap_query(&self, base_token: &str, quote_token: &str) -> String {
        // In a real implementation, this would construct a proper GraphQL query
        // This is just a placeholder
        format!(r#"
            {{
              pools(where: {{
                token0: "{}", 
                token1: "{}"
              }}) {{
                id
                token0Price
                token1Price
                volumeUSD
                liquidity
              }}
            }}
        "#, base_token, quote_token)
    }
}
