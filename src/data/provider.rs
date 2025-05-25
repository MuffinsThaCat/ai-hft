use crate::utils::config::DataConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
// Define a SendError type alias that's Send + Sync
pub type SendError = Box<dyn std::error::Error + Send + Sync>;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time;
use ethers::{providers::{Http, Provider, Middleware}, types::{H160, U256, transaction::eip2718::TypedTransaction}};

// Real market data structures
#[derive(Debug, Clone, Deserialize)]
pub struct CoinGeckoMarketData {
    pub id: String,
    pub symbol: String,
    pub name: String,
    #[serde(default)]
    pub current_price: HashMap<String, f64>,
    #[serde(default)]
    pub market_cap: HashMap<String, f64>,
    #[serde(default)]
    pub total_volume: HashMap<String, f64>,
    pub price_change_percentage_24h: Option<f64>,
    pub price_change_percentage_7d: Option<f64>,
    pub last_updated: String,
    // Fallback fields in case API structure changes
    #[serde(rename = "market_data", default)]
    pub market_data: Option<CoinGeckoNestedMarketData>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CoinGeckoNestedMarketData {
    #[serde(default)]
    pub current_price: HashMap<String, f64>,
    #[serde(default)]
    pub market_cap: HashMap<String, f64>,
    #[serde(default)]
    pub total_volume: HashMap<String, f64>,
    pub price_change_percentage_24h: Option<f64>,
    pub price_change_percentage_7d: Option<f64>,
    pub high_24h: HashMap<String, f64>,
    pub low_24h: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketData {
    pub symbol: String,
    pub price: f64,
    pub volume_24h: f64,
    pub change_24h: f64,
    pub high_24h: Option<f64>,
    pub low_24h: Option<f64>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBookData {
    pub symbol: String,
    pub bids: Vec<(f64, f64)>,  // (price, amount)
    pub asks: Vec<(f64, f64)>,  // (price, amount)
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DEXPair {
    pub dex: String,
    pub pair_address: String,
    pub token0: String,
    pub token1: String,
    pub reserves0: f64,
    pub reserves1: f64,
    pub price: f64,
    pub liquidity_usd: f64,
}

// Avalanche C-Chain specific types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasInfo {
    pub standard: u64,
    pub fast: u64,
    pub rapid: u64,
    pub base_fee: u64,
    pub priority_fee: u64,
}

#[derive(Debug, Clone)]
pub struct DataProvider {
    client: Client,
    config: DataConfig,
    cache: Arc<Mutex<HashMap<String, (Instant, String)>>>,
    provider: Provider<Http>,
    // Rate limiting state
    last_request_time: Arc<Mutex<HashMap<String, Instant>>>,
    request_counts: Arc<Mutex<HashMap<String, (usize, Instant)>>>,
}

impl DataProvider {
    // Create a new DataProvider instance
    fn create_instance(config: DataConfig, provider: Provider<Http>) -> Self {
        DataProvider {
            client: Client::new(),
            config,
            cache: Arc::new(Mutex::new(HashMap::new())),
            provider,
            last_request_time: Arc::new(Mutex::new(HashMap::new())),
            request_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    // Public constructor that returns Arc<Self>
    pub async fn new(config: &DataConfig) -> Result<Arc<Self>, SendError> {
        // Create HTTP provider for Avalanche C-Chain
        let provider = Provider::<Http>::try_from(&config.avalanche_rpc_url)?;
        
        // Create DataProvider
        let data_provider = Arc::new(Self::create_instance(config.clone(), provider));
        
        // Start background data refresh task
        let provider_clone = data_provider.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_millis(provider_clone.config.update_interval_ms));
            loop {
                interval.tick().await;
                // Refresh cache in background
                if let Err(e) = provider_clone.refresh_cache().await {
                    eprintln!("Error refreshing data cache: {}", e);
                }
            }
        });
        
        Ok(data_provider)
    }
    
    // Rate limiting helper - returns how long to wait before making a request
    async fn get_rate_limit_delay(&self, endpoint: &str) -> Duration {
        let mut last_request_times = self.last_request_time.lock().unwrap();
        let mut request_counts = self.request_counts.lock().unwrap();
        
        let now = Instant::now();
        let endpoint_key = endpoint.to_string();
        
        // Basic rate limiting: 1 request per second per endpoint by default
        let min_interval = Duration::from_millis(1000);
        
        // Check if we need to wait due to basic rate limiting
        let wait_time = if let Some(last_time) = last_request_times.get(&endpoint_key) {
            let elapsed = now.duration_since(*last_time);
            if elapsed < min_interval {
                min_interval - elapsed
            } else {
                Duration::from_millis(0)
            }
        } else {
            Duration::from_millis(0)
        };
        
        // Update last request time
        last_request_times.insert(endpoint_key.clone(), now);
        
        // Check if we're approaching the rate limit (e.g., 50 requests per minute for CoinGecko)
        let default_value = (0, now);
        let (count, window_start) = request_counts.get(&endpoint_key).unwrap_or(&default_value);
        
        // If the time window has passed, reset the counter
        let window_duration = Duration::from_secs(60); // 1 minute window
        let new_count;
        let new_window_start;
        
        if now.duration_since(*window_start) > window_duration {
            new_count = 1;
            new_window_start = now;
        } else {
            new_count = count + 1;
            new_window_start = *window_start;
            
            // If we're getting close to the limit, add an exponential backoff
            if new_count > 40 { // CoinGecko has a limit of 50 requests per minute
                let backoff = Duration::from_millis((new_count - 40) as u64 * 500); // Exponential backoff
                return if backoff > wait_time { backoff } else { wait_time };
            }
        }
        
        request_counts.insert(endpoint_key, (new_count, new_window_start));
        wait_time
    }
    
    // Make a rate-limited API request with retries
    async fn rate_limited_request(&self, url: &str, endpoint_key: &str) -> Result<String, SendError> {
        let max_retries = 5;
        let mut retry_count = 0;
        
        loop {
            // Apply rate limiting
            let delay = self.get_rate_limit_delay(endpoint_key).await;
            if !delay.is_zero() {
                log::debug!("Rate limiting applied for {}: waiting {:?}", endpoint_key, delay);
                time::sleep(delay).await;
            }
            
            // Make the request
            let response = self.client.get(url)
                .header("Accept", "application/json")
                .send()
                .await;
                
            match response {
                Ok(res) => {
                    if res.status().is_success() {
                        return Ok(res.text().await?);
                    } else if res.status().as_u16() == 429 {
                        // Too many requests - implement exponential backoff
                        retry_count += 1;
                        if retry_count > max_retries {
                            return Err(format!("API request failed after {} retries with status: {}", 
                                max_retries, res.status()).into());
                        }
                        
                        let retry_delay = Duration::from_millis(2u64.pow(retry_count as u32) * 1000);
                        log::warn!("Rate limit exceeded for {}. Retrying in {:?} (attempt {}/{})", 
                            endpoint_key, retry_delay, retry_count, max_retries);
                        time::sleep(retry_delay).await;
                        continue;
                    } else {
                        return Err(format!("API request failed with status: {}", res.status()).into());
                    }
                },
                Err(e) => {
                    // Handle network errors with retries
                    retry_count += 1;
                    if retry_count > max_retries {
                        return Err(format!("API request failed after {} retries: {}", max_retries, e).into());
                    }
                    
                    let retry_delay = Duration::from_millis(2u64.pow(retry_count as u32) * 1000);
                    log::warn!("Network error for {}: {}. Retrying in {:?} (attempt {}/{})", 
                        endpoint_key, e, retry_delay, retry_count, max_retries);
                    time::sleep(retry_delay).await;
                }
            }
        }
    }
    
    pub async fn get_market_data(&self, symbol: &str) -> Result<MarketData, SendError> {
        let cache_key = format!("market:{}", symbol);
        
        // Check cache first
        if let Some(data) = self.get_from_cache(&cache_key) {
            let market_data: MarketData = serde_json::from_str(&data)?;
            return Ok(market_data);
        }
        
        // Fetch from API if not in cache
        let market_data = self.fetch_market_data(symbol).await?;
        
        // Update cache
        self.update_cache(&cache_key, &serde_json::to_string(&market_data)?);
        
        Ok(market_data)
    }
    
    pub async fn get_dex_pair(&self, dex: &str, pair_address: &str) -> Result<DEXPair, SendError> {
        let cache_key = format!("dex_pair:{}:{}", dex, pair_address);
        
        // Check cache first
        if let Some(data) = self.get_from_cache(&cache_key) {
            let pair: DEXPair = serde_json::from_str(&data)?;
            return Ok(pair);
        }
        
        // Fetch from blockchain if not in cache
        let pair = self.fetch_dex_pair(dex, pair_address).await?;
        
        // Update cache
        self.update_cache(&cache_key, &serde_json::to_string(&pair)?);
        
        Ok(pair)
    }
    
    pub async fn get_gas_prices(&self) -> Result<GasInfo, SendError> {
        let cache_key = "gas_prices";
        
        // Check cache first
        if let Some(data) = self.get_from_cache(cache_key) {
            let gas_info: GasInfo = serde_json::from_str(&data)?;
            return Ok(gas_info);
        }
        
        // Fetch from blockchain if not in cache
        let gas_info = self.fetch_gas_prices().await?;
        
        // Update cache
        self.update_cache(cache_key, &serde_json::to_string(&gas_info)?);
        
        Ok(gas_info)
    }
    
    async fn fetch_market_data(&self, symbol: &str) -> Result<MarketData, SendError> {
        // Format for CoinGecko API
        let coin_id = match symbol.to_lowercase().as_str() {
            "avax/usd" | "avax" => "avalanche-2",
            "eth/usd" | "eth" => "ethereum",
            "btc/usd" | "btc" => "bitcoin",
            _ => return Err(format!("Unsupported symbol: {}", symbol).into()),
        };
        
        // Call CoinGecko API with rate limiting and retries
        let url = format!(
            "https://api.coingecko.com/api/v3/coins/{}?localization=false&tickers=false&market_data=true&community_data=false&developer_data=false",
            coin_id
        );
        
        let endpoint_key = format!("coingecko_coin_{}", coin_id);
        let response_text = self.rate_limited_request(&url, &endpoint_key).await?;
        
        // Log the response for debugging in case of future API changes
        log::debug!("CoinGecko API response length: {} bytes", response_text.len());
        log::debug!("CoinGecko API response: {}", response_text);
        
        // Try to parse the response
        let coin_data: CoinGeckoMarketData = match serde_json::from_str(&response_text) {
            Ok(data) => data,
            Err(e) => {
                log::error!("Failed to parse CoinGecko response: {}, Response: {}", e, response_text);
                return Err(format!("Error parsing API response: {}", e).into());
            }
        };
        
        // Extract symbol from the response
        let clean_symbol = symbol.split('/').next().unwrap_or(symbol).to_uppercase();
        
        // Get price data, handling both old and new API formats
        let price = if !coin_data.current_price.is_empty() {
            *coin_data.current_price.get("usd").unwrap_or(&0.0)
        } else if let Some(market_data) = &coin_data.market_data {
            *market_data.current_price.get("usd").unwrap_or(&0.0)
        } else {
            log::warn!("No price data found for {}, defaulting to 0", symbol);
            0.0
        };
        
        // Get volume data, handling both old and new API formats
        let volume = if !coin_data.total_volume.is_empty() {
            *coin_data.total_volume.get("usd").unwrap_or(&0.0)
        } else if let Some(market_data) = &coin_data.market_data {
            *market_data.total_volume.get("usd").unwrap_or(&0.0)
        } else {
            0.0
        };
        
        // Get price change data, handling both old and new API formats
        let change = coin_data.price_change_percentage_24h.unwrap_or_else(|| {
            if let Some(market_data) = &coin_data.market_data {
                market_data.price_change_percentage_24h.unwrap_or(0.0)
            } else {
                0.0
            }
        });
        
        // Get high/low data if available in nested market_data
        let high_24h = if let Some(market_data) = &coin_data.market_data {
            market_data.high_24h.get("usd").copied()
        } else {
            None
        };
        
        let low_24h = if let Some(market_data) = &coin_data.market_data {
            market_data.low_24h.get("usd").copied()
        } else {
            None
        };
        
        // Create market data
        let market_data = MarketData {
            symbol: clean_symbol,
            price,
            volume_24h: volume,
            change_24h: change,
            high_24h,
            low_24h,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        
        Ok(market_data)
    }
    
    async fn fetch_dex_pair(&self, dex: &str, pair_address: &str) -> Result<DEXPair, SendError> {
        // Convert address string to ethers H160 type
        let pair_addr = pair_address.parse::<H160>()?;
        
        // This is a simplified implementation - in reality, you would:
        // 1. Use the specific DEX contract ABI
        // 2. Call getReserves() on the pair contract
        // 3. Get token0 and token1 addresses
        // 4. Calculate price based on reserves
        
        // For now, let's make a simplified implementation for Trader Joe's pairs on Avalanche
        
        // ABI for getReserves function on Trader Joe pairs
        let reserves_data = hex::decode("0902f1ac")?; // getReserves() signature
        
        // Call the contract
        let tx = ethers::types::TransactionRequest::new()
            .to(pair_addr)
            .data(reserves_data);
        let typed_tx: TypedTransaction = tx.into();
        let reserves_result = self.provider.call_raw(&typed_tx).await?;
        
        // Parse reserves (this is simplified - in reality, you'd use ethers contract bindings)
        let reserve0 = U256::from_big_endian(&reserves_result[..32]);
        let reserve1 = U256::from_big_endian(&reserves_result[32..64]);
        
        // For demonstration, using fixed values for tokens and decimals
        // In real implementation, you would query token addresses and decimals
        let reserve0_f64 = reserve0.as_u128() as f64 / 1e18; // Assuming 18 decimals
        let reserve1_f64 = reserve1.as_u128() as f64 / 1e6;  // Assuming 6 decimals (e.g., USDC)
        
        let price = reserve1_f64 / reserve0_f64;
        let liquidity_usd = 2.0 * reserve1_f64; // Simplified liquidity calculation
        
        let pair = DEXPair {
            dex: dex.to_string(),
            pair_address: pair_address.to_string(),
            token0: "AVAX".to_string(), // Simplified - would query from contract
            token1: "USDC".to_string(), // Simplified - would query from contract
            reserves0: reserve0_f64,
            reserves1: reserve1_f64,
            price,
            liquidity_usd,
        };
        
        Ok(pair)
    }
    
    async fn fetch_gas_prices(&self) -> Result<GasInfo, SendError> {
        // Get latest block to extract base fee
        let latest_block = self.provider.get_block(ethers::types::BlockNumber::Latest).await?;
        
        // Extract base fee from latest block
        let base_fee = match latest_block {
            Some(block) => block.base_fee_per_gas.unwrap_or_default().as_u64() / 1_000_000_000, // Convert to Gwei
            None => return Err("Failed to get latest block".into()),
        };
        
        // Use a simple approach for priority fee estimation since we're not using full middleware
        let priority_fee = 1; // Default to 1 Gwei as a safe priority fee
        
        // Calculate fee tiers
        let standard = base_fee + priority_fee;
        let fast = base_fee + priority_fee * 2;
        let rapid = base_fee + priority_fee * 3;
        
        Ok(GasInfo {
            standard,
            fast,
            rapid,
            base_fee,
            priority_fee,
        })
    }
    
    fn get_from_cache(&self, key: &str) -> Option<String> {
        let cache = self.cache.lock().unwrap();
        if let Some((timestamp, data)) = cache.get(key) {
            // Check if data is still fresh
            if timestamp.elapsed() < Duration::from_secs(self.config.cache_expiry_seconds) {
                return Some(data.clone());
            }
        }
        None
    }
    fn update_cache(&self, key: &str, data: &str) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(key.to_string(), (Instant::now(), data.to_string()));
    }
    
    async fn refresh_cache(&self) -> Result<(), SendError> {
        // Refresh market data for common pairs
        for symbol in ["AVAX/USD", "ETH/USD", "BTC/USD"].iter() {
            if let Ok(data) = self.fetch_market_data(symbol).await {
                let cache_key = format!("market:{}", symbol);
                self.update_cache(&cache_key, &serde_json::to_string(&data)?);
            }
        }
        
        // Refresh gas prices
        if let Ok(gas_info) = self.fetch_gas_prices().await {
            self.update_cache("gas_prices", &serde_json::to_string(&gas_info)?);
        }
        
        // Refresh key DEX pairs
        let trader_joe_avax_usdc = "0xf4003f4efbe8691b60249e6afbd307abe7758adb"; // Example Trader Joe AVAX/USDC pair
        if let Ok(pair) = self.fetch_dex_pair("trader_joe", trader_joe_avax_usdc).await {
            let cache_key = format!("dex_pair:{}:{}", "trader_joe", trader_joe_avax_usdc);
            self.update_cache(&cache_key, &serde_json::to_string(&pair)?);
        }
        
        Ok(())
    }
    
    // Get token price from CoinGecko or other sources
    pub async fn get_token_price(&self, token_symbol: &str) -> Result<f64, SendError> {
        // First check if we have price in cache
        let cache_key = format!("token_price_{}", token_symbol.to_lowercase());
        if let Some(cached_data) = self.get_from_cache(&cache_key) {
            if let Ok(price) = cached_data.parse::<f64>() {
                return Ok(price);
            }
        }
        
        // If not in cache, fetch from CoinGecko
        let url = format!("https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd", token_symbol.to_lowercase());
        let client = Client::new();
        let response = client.get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await?
            .json::<HashMap<String, HashMap<String, f64>>>()
            .await?;
        
        // Extract price and update cache
        if let Some(token_data) = response.get(&token_symbol.to_lowercase()) {
            if let Some(price) = token_data.get("usd") {
                self.update_cache(&cache_key, &price.to_string());
                return Ok(*price);
            }
        }
        
        // Fallback default prices for common tokens if API fails
        let default_price = match token_symbol.to_lowercase().as_str() {
            "avax" => 35.0,
            "eth" => 3500.0,
            "btc" => 60000.0,
            "usdc" => 1.0,
            "usdt" => 1.0,
            "dai" => 1.0,
            _ => 10.0, // Default fallback price
        };
        
        Ok(default_price)
    }

    // Get all market data as a formatted string for LLM consumption
    pub async fn get_formatted_market_data(&self) -> Result<String, SendError> {
        let mut formatted_data = String::new();
        
        // Add market data for key assets
        formatted_data.push_str("# Market Data\n\n");
        for symbol in ["AVAX/USD", "ETH/USD", "BTC/USD"].iter() {
            match self.get_market_data(symbol).await {
                Ok(data) => {
                    formatted_data.push_str(&format!("## {}\n", symbol));
                    formatted_data.push_str(&format!("- Price: ${:.2}\n", data.price));
                    formatted_data.push_str(&format!("- 24h Change: {:.2}%\n", data.change_24h));
                    formatted_data.push_str(&format!("- 24h Volume: ${:.2}\n\n", data.volume_24h));
                }
                Err(e) => {
                    formatted_data.push_str(&format!("## {} - Error: {}\n\n", symbol, e));
                }
            }
        }
        
        // Add DEX data
        formatted_data.push_str("# DEX Data\n\n");
        let trader_joe_avax_usdc = "0xf4003f4efbe8691b60249e6afbd307abe7758adb"; // Example Trader Joe AVAX/USDC pair
        match self.get_dex_pair("trader_joe", trader_joe_avax_usdc).await {
            Ok(pair) => {
                formatted_data.push_str(&format!("## Trader Joe AVAX/USDC\n"));
                formatted_data.push_str(&format!("- Price: ${:.4}\n", pair.price));
                formatted_data.push_str(&format!("- Liquidity: ${:.2}\n", pair.liquidity_usd));
                formatted_data.push_str(&format!("- Reserves: {:.2} AVAX / {:.2} USDC\n\n", 
                    pair.reserves0, pair.reserves1));
            }
            Err(e) => {
                formatted_data.push_str(&format!("## Trader Joe AVAX/USDC - Error: {}\n\n", e));
            }
        }
        
        // Add gas prices
        formatted_data.push_str("# Gas Prices (Gwei)\n\n");
        match self.get_gas_prices().await {
            Ok(gas) => {
                formatted_data.push_str(&format!("- Standard: {}\n", gas.standard));
                formatted_data.push_str(&format!("- Fast: {}\n", gas.fast));
                formatted_data.push_str(&format!("- Rapid: {}\n", gas.rapid));
                formatted_data.push_str(&format!("- Base Fee: {}\n", gas.base_fee));
                formatted_data.push_str(&format!("- Priority Fee: {}\n", gas.priority_fee));
            }
            Err(e) => {
                formatted_data.push_str(&format!("Gas Price Error: {}\n", e));
            }
        }
        
        Ok(formatted_data)
    }
}
