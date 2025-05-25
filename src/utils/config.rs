use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub data: DataConfig,
    pub llm: LLMConfig,
    pub strategies: StrategyConfig,
    pub execution: ExecutionConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DataConfig {
    pub providers: Vec<String>,
    pub provider_type: Option<String>, // "coingecko" or "ccip"
    pub update_interval_ms: u64,
    pub cache_expiry_seconds: u64,    // renamed for clarity
    pub avalanche_rpc_url: String,
    pub ccip_router_address: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LLMConfig {
    pub provider: String,
    pub api_key: String,
    pub model: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub retry_delay_ms: u32,
    pub retry_attempts: u32,
    pub backoff_ms: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StrategyConfig {
    pub active_strategies: Vec<String>,
    pub risk_level: u8,
    pub max_position_size: String,
    pub max_slippage_bps: u16,
    pub min_confidence_score: f32,
    pub high_frequency: Option<HighFrequencyConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ExecutionConfig {
    pub relayer_url: String,
    pub avalanche_rpc_url: String,
    pub stateless_vm_url: String,
    pub max_gas_price_gwei: u64,
    pub confirmation_blocks: u8,
    pub bundle_timeout_ms: u64,
    pub retry_attempts: u8,
    pub wallet_key: String,
    pub wallet_address: String,
    pub max_risk_score: u8,
    pub witness_generation_timeout_ms: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HighFrequencyConfig {
    pub enabled: bool,
    pub monitored_dexes: Vec<String>,
    pub trading_pairs: Vec<TradingPair>,
    pub min_profit_multiplier: f64,
    pub max_slippage_percent: f64,
    pub max_trade_size_usd: f64,
    pub min_block_confirmations: u8,
    pub scan_interval_ms: u64,
    pub gas_boost_percent: u8,
    pub wallet_address: String,
    pub security_verification_enabled: bool,
    pub max_risk_score: u8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TradingPair {
    pub token_a: String,
    pub token_b: String,
    pub trade_amount: String,
    pub min_profit_threshold_percent: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub verification_mode: String,
    pub verify_contracts: bool,
    pub max_risk_score: u8,
    pub verify_reentrancy: bool,
    pub verify_integer_underflow: bool,
    pub verify_integer_overflow: bool,
    pub verify_unchecked_calls: bool,
    pub verify_upgradability: bool,
    pub verify_mev_vulnerability: bool,
    pub verify_cross_contract_reentrancy: bool,
    pub verify_precision_loss: bool,
    pub verify_gas_griefing: bool,
    pub cache_verification_results: bool,
    pub verification_cache_duration_s: u64,
}

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&content)?;
    
    // Replace environment variables in wallet configuration
    if config.execution.wallet_key.starts_with("${WALLET_KEY}") {
        if let Ok(wallet_key) = std::env::var("WALLET_KEY") {
            config.execution.wallet_key = wallet_key;
        }
    }
    
    if config.execution.wallet_address.starts_with("${WALLET_ADDRESS}") {
        if let Ok(wallet_address) = std::env::var("WALLET_ADDRESS") {
            config.execution.wallet_address = wallet_address;
        }
    }
    
    Ok(config)
}
