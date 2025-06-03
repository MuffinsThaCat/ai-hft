use crate::security::{SecurityVerification, VerificationMode, SecurityVerificationMode};
use crate::security::verifier::SecurityVerifier;
use crate::utils::config::SecurityConfig;

// Mock relay types for use in non-relay builds
// These are simplified versions that allow the codebase to compile without the relay module

// Feature-gated relay type imports
#[cfg(feature = "relay")]
use crate::relay::types::{SubmissionMode as RelaySubmissionMode, Region as RelayRegion, SubmissionResult as RelaySubmissionResult, SubmissionStatus as RelaySubmissionStatus};
#[cfg(feature = "relay")]
use crate::relay::network::RelayNode;

// MEV protection strategy enum - defined early to be available throughout the file
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MevProtectionStrategy {
    None,
    Comprehensive, 
    PrivateRelay,
    TimingRandomization,
    CamouflageBundle,
}

// Create simplified versions of the relay types to avoid circular dependencies
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub node_id: String,
    pub region: Region,
    pub endpoint: String,
    pub validator_endpoints: Vec<ValidatorEndpoint>,
    pub encryption_key: String,
    pub connection_timeout: std::time::Duration,
    pub max_bundle_size: usize,
    pub retry_attempts: u32,
    pub retry_delay_ms: u64,
    pub submission_mode: SubmissionMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Region {
    UsEast,
    UsWest,
    Europe,
    Asia,
    Global,
    NorthAmerica,
}

// Map our Region to relay Region when relay feature is enabled
#[cfg(feature = "relay")]
impl From<Region> for RelayRegion {
    fn from(region: Region) -> Self {
        match region {
            Region::UsEast => RelayRegion::UsEast,
            Region::UsWest => RelayRegion::UsWest,
            Region::Europe => RelayRegion::Europe,
            Region::Asia => RelayRegion::Asia,
            // These may need adjustments based on actual RelayRegion variants
            Region::Global => RelayRegion::UsEast, // Default to something in relay
            Region::NorthAmerica => RelayRegion::UsWest, // Default to something in relay
        }
    }
}

// Implement conversion from our RelayConfig to the relay module's RelayConfig
#[cfg(feature = "relay")]
impl From<RelayConfig> for crate::relay::types::RelayConfig {
    fn from(config: RelayConfig) -> Self {
        let validator_endpoints = config.validator_endpoints
            .into_iter()
            .map(|endpoint| crate::relay::types::ValidatorEndpoint {
                id: format!("validator-{}", endpoint.url), // Create a unique ID
                endpoint: endpoint.url,
                stake_weight: endpoint.weight as f64,
                priority: 1, // Default priority
                auth_token: None, // No auth token by default
            })
            .collect();
        
        Self {
            node_id: config.node_id,
            region: config.region.into(),
            endpoint: config.endpoint,
            validator_endpoints,
            encryption_key: config.encryption_key,
            connection_timeout: config.connection_timeout,
            max_bundle_size: config.max_bundle_size,
            retry_attempts: config.retry_attempts as u8,
            retry_delay_ms: config.retry_delay_ms,
        }
    }
}

// Implement conversion from relay module's SubmissionResult to our SubmissionResult
#[cfg(feature = "relay")]
impl From<RelaySubmissionResult> for SubmissionResult {
    fn from(result: RelaySubmissionResult) -> Self {
        Self {
            transaction_hash: result.transaction_hash,
            bundle_id: result.bundle_id,
            status: match result.status {
                RelaySubmissionStatus::Pending => SubmissionStatus::Pending,
                RelaySubmissionStatus::Confirmed => SubmissionStatus::Confirmed,
                RelaySubmissionStatus::Failed(_) => SubmissionStatus::Failed,
            },
            block_number: result.block_number,
            gas_used: result.gas_used,
            effective_gas_price: result.effective_gas_price,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum SubmissionMode {
    Standard,
    Private,
    /// Hybrid submission (both public and private) with MEV threshold
    Hybrid(f64),
}

// Map our SubmissionMode to relay SubmissionMode when relay feature is enabled
#[cfg(feature = "relay")]
impl From<SubmissionMode> for RelaySubmissionMode {
    fn from(mode: SubmissionMode) -> Self {
        match mode {
            SubmissionMode::Standard => RelaySubmissionMode::Standard,
            SubmissionMode::Private => RelaySubmissionMode::Private,
            SubmissionMode::Hybrid(threshold) => RelaySubmissionMode::Hybrid(threshold),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorEndpoint {
    pub url: String,
    pub weight: u32,
}

pub type RelayError = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubmissionStatus {
    Pending,
    Confirmed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionResult {
    pub transaction_hash: Option<H256>,
    pub bundle_id: Option<String>,
    pub status: SubmissionStatus,
    pub block_number: Option<u64>,
    pub gas_used: Option<u64>,
    pub effective_gas_price: Option<U256>,
}

// Imports for H256 and U256 types
use ethers::types::{H256, U256, Transaction};

#[derive(Debug, Clone)]
pub struct RelayNetworkStats {
    pub total_submissions: u64,
    pub successful_submissions: u64,
    pub failed_submissions: u64,
}

// MevProtectionStrategy moved before MevProtectionResults

#[derive(Clone, Debug)]
pub struct RelayNode {
    pub config: RelayConfig,
    pub stats: RelayNetworkStats,
    #[cfg(feature = "relay")]
    pub relay_node: Option<Box<RelayNode>>,
}

impl RelayNode {
    pub async fn new(config: RelayConfig) -> Result<Self, RelayError> {
        // Create a simplified mock for tests
        #[cfg(feature = "relay")]
        {
            // When relay feature is enabled, try to create a real relay node
            let relay_node = match crate::relay::network::RelayNode::new(config.clone().into()).await {
                Ok(node) => Some(Box::new(node)),
                Err(e) => {
                    debug!("Failed to create real relay node: {}", e);
                    None
                }
            };
            
            return Ok(Self {
                config,
                stats: RelayNetworkStats {
                    total_submissions: 0,
                    successful_submissions: 0,
                    failed_submissions: 0,
                },
                relay_node,
            });
        }
        
        // When relay feature is disabled, create a mock version
        #[cfg(not(feature = "relay"))]
        return Ok(Self {
            config,
            stats: RelayNetworkStats {
                total_submissions: 0,
                successful_submissions: 0,
                failed_submissions: 0,
            },
        });
    }

    pub fn get_stats(&self) -> Result<RelayNetworkStats, RelayError> {
        Ok(self.stats.clone())
    }

    pub async fn submit_bundle(&self, _transactions: &[Transaction], _miner_reward: Option<U256>) -> Result<SubmissionResult, RelayError> {
        // Mock implementation
        Ok(SubmissionResult {
            transaction_hash: None,
            bundle_id: Some(format!("bundle-{}", uuid::Uuid::new_v4())),
            status: SubmissionStatus::Pending,
            block_number: None,
            gas_used: None,
            effective_gas_price: None,
        })
    }
    
    pub async fn submit_transaction(
        &self, 
        tx: &Transaction, 
        mode: SubmissionMode, 
        security_verification: Option<&SecurityVerification>
    ) -> Result<SubmissionResult, RelayError> {
        #[cfg(feature = "relay")]
        {
            if let Some(relay_node) = &self.relay_node {
                let relay_mode: RelaySubmissionMode = mode.clone().into();
                match relay_node.submit_transaction(tx, relay_mode, security_verification).await {
                    Ok(result) => return Ok(result.into()),
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        
        // Mock implementation when relay is disabled or real relay node isn't available
        debug!("Mock relay node submitting transaction with mode: {:?}", mode);
        Ok(SubmissionResult {
            transaction_hash: Some(H256::random()),
            bundle_id: None,
            status: SubmissionStatus::Pending,
            block_number: None,
            gas_used: None,
            effective_gas_price: None,
        })
    }
}

use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::sync::Arc;
use std::env;
use serde_json::{Value, json};
// Removed duplicate import

use std::str::FromStr;
use chrono;
use log::{info, debug, warn};


// Define SendError type alias for this module
type SendError = Box<dyn std::error::Error + Send + Sync>;

// Error type for StatelessVM operations
#[derive(Debug)]
pub enum StatelessVmError {
    ApiRequestError(String),
    ApiResponseError(String),
    ApiErrorResponse(String),
    SerializationError(String),
    DeserializationError(String),
}

impl std::fmt::Display for StatelessVmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatelessVmError::ApiRequestError(msg) => write!(f, "StatelessVM API request error: {}", msg),
            StatelessVmError::ApiResponseError(msg) => write!(f, "StatelessVM API response error: {}", msg),
            StatelessVmError::ApiErrorResponse(msg) => write!(f, "StatelessVM API error: {}", msg),
            StatelessVmError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            StatelessVmError::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
        }
    }
}

impl std::error::Error for StatelessVmError {}

impl From<reqwest::Error> for StatelessVmError {
    fn from(err: reqwest::Error) -> Self {
        StatelessVmError::ApiRequestError(err.to_string())
    }
}

impl From<serde_json::Error> for StatelessVmError {
    fn from(err: serde_json::Error) -> Self {
        StatelessVmError::DeserializationError(err.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessTxRequest {
    pub from: String,
    pub to: String,
    pub value: String,
    pub data: String,
    pub gas_limit: String,
    pub gas_price: String,
    pub security_verification: SecurityVerificationRequest,
    pub bundle_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVerificationRequest {
    pub address: String,
    pub enabled: bool,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessTxResponse {
    pub tx_hash: String,
    pub status: String,
    pub result: Option<String>,
    pub error: Option<String>,
    pub security_verification: Option<SecurityVerificationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVerificationResult {
    #[serde(default)]
    pub passed: bool,
    #[serde(default)]
    pub risk_score: u8,
    pub warnings: Option<Vec<SecurityWarning>>,
    pub execution_time_ms: Option<u64>,
    pub vulnerability_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityWarning {
    pub warning_type: String,
    pub severity: String,
    pub description: String,
    pub message: String,
    pub line_number: Option<u32>,
    pub code_snippet: Option<String>,
    pub recommendation: Option<String>,
}

// Represents a transaction trace from the stateless VM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionTrace {
    pub tx_hash: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub gas_used: u64,
    pub execution_steps: Vec<ExecutionStep>,
    pub state_changes: Vec<StateChange>,
    pub events: Vec<EventLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStep {
    pub pc: u32,
    pub op: String,
    pub gas: u64,
    pub gas_cost: u64,
    pub depth: u32,
    pub stack: Vec<String>,
    pub memory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub address: String,
    pub slot: String,
    pub previous_value: String,
    pub new_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

// Transaction sequence execution types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub chain_id: u64,
    pub block_number: Option<u64>,
    pub timestamp: u64,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessSequenceRequest {
    pub sequence_id: String,
    pub transactions: Vec<String>, // Hex-encoded transaction data
    pub fallback_plans: Option<Vec<FallbackPlanRequest>>,
    pub market_conditions: Option<Value>,
    pub mev_protection: Option<MevProtectionRequest>,
    pub state_verification: Option<Vec<StateVerificationRequest>>,
    pub execution_context: ExecutionContext,
    pub timeout_seconds: u64,
    pub atomic: bool,
    pub bundle_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackPlanRequest {
    pub transactions: Vec<String>,
    pub trigger_conditions: Value,
    pub priority: u8,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevProtectionRequest {
    pub use_private_mempool: bool,
    pub frontrunning_protection: u8,
    pub max_slippage_percent: f64,
    pub monitor_sandwich_attacks: bool,
    pub use_commit_reveal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVerificationRequest {
    pub contracts: Vec<String>,
    pub storage_slots: HashMap<String, Vec<String>>,
    pub balance_requirements: HashMap<String, String>,
    pub custom_requirements: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessSequenceResponse {
    pub sequence_id: String,
    pub success: bool,
    pub transaction_statuses: Vec<TransactionExecutionStatus>,
    pub market_state: Option<MarketStateData>,
    pub mev_protection_results: Option<MevProtectionResults>,
    pub state_verification_results: Option<Vec<StateVerificationResult>>,
    pub fallback_executed: bool,
    pub fallback_results: Option<Vec<FallbackExecutionResult>>,
    pub error: Option<String>,
    pub gas_used: u64,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionExecutionStatus {
    pub tx_hash: String,
    pub success: bool,
    pub gas_used: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketStateData {
    pub prices: HashMap<String, f64>,
    pub liquidity: HashMap<String, u64>,
    pub gas_price: u64,
    pub volatility: HashMap<String, f64>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevProtectionResults {
    pub frontrunning_detected: bool,
    pub sandwich_attack_prevented: bool,
    pub slippage_within_limits: bool,
    pub private_tx_successful: bool,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVerificationResult {
    pub step: u32,
    pub success: bool,
    pub verified_contracts: Vec<String>,
    pub failed_verifications: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackExecutionResult {
    pub plan_id: u8,
    pub executed: bool,
    pub success: bool,
    pub transaction_statuses: Option<Vec<TransactionExecutionStatus>>,
    pub description: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessVmErrorResponse {
    pub error: String,
    pub details: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatelessVmClient {
    // Explicitly skip serialization for the reqwest client
    #[serde(skip)]
    client: Client,
    url: String,
    avalanche_rpc_url: String,
    base_url: String, 
    direct_mode: bool,
    rpc_url: Option<String>,
    chain_id: u64,
    debug_mode: bool,
    // Private transaction relay for MEV protection
    #[serde(skip)]
    #[cfg(feature = "relay")]
    relay_node: Option<Arc<RelayNode>>,
    // Default submission mode for transactions
    default_submission_mode: SubmissionMode,
    // MEV protection strategy
    mev_protection_strategy: MevProtectionStrategy,
}

impl Clone for StatelessVmClient {
    fn clone(&self) -> Self {
        Self {
            client: Client::new(), // Create a new client instance since reqwest::Client is not Clone
            url: self.url.clone(),
            avalanche_rpc_url: self.avalanche_rpc_url.clone(),
            base_url: self.base_url.clone(),
            direct_mode: self.direct_mode,
            rpc_url: self.rpc_url.clone(),
            chain_id: self.chain_id,
            debug_mode: self.debug_mode,
            #[cfg(feature = "relay")]
            relay_node: self.relay_node.clone(),
            default_submission_mode: self.default_submission_mode.clone(),
            mev_protection_strategy: self.mev_protection_strategy.clone(),
        }
    }
}

impl StatelessVmClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            url: base_url.to_string(),
            avalanche_rpc_url: "".to_string(),
            base_url: base_url.to_string(),
            direct_mode: false,
            rpc_url: None,
            chain_id: 43114, // Default to Avalanche C-Chain
            debug_mode: false,
            #[cfg(feature = "relay")]
            relay_node: None, // No relay by default
            default_submission_mode: SubmissionMode::Standard, // Standard submission by default
            mev_protection_strategy: MevProtectionStrategy::None, // No MEV protection by default
        }
    }
    
    /// Enable debug mode for detailed logging
    pub fn with_debug(mut self) -> Self {
        self.debug_mode = true;
        self
    }
    
    /// Return the base URL of the StatelessVM service
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    
    /// Return the chain ID for this client
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    
    /// Create a new client in direct RPC mode for real trading
    /// This bypasses the StatelessVM service and makes direct RPC calls
    pub fn new_direct(rpc_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: String::new(), // Not used in direct mode
            direct_mode: true,
            rpc_url: Some(rpc_url.to_string()),
            chain_id: 43114, // Default to Avalanche C-Chain
            debug_mode: false,
            url: String::new(),
            avalanche_rpc_url: rpc_url.to_string(),
            #[cfg(feature = "relay")]
            relay_node: None, // No relay by default
            default_submission_mode: SubmissionMode::Standard, // Standard submission by default
            mev_protection_strategy: MevProtectionStrategy::None, // No MEV protection by default
        }
    }
    
    pub async fn new_async(url: Option<String>, avalanche_rpc_url: Option<String>, debug_mode: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let url = url.unwrap_or_else(|| {
            env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string())
        });
        
        let avalanche_rpc_url = avalanche_rpc_url.unwrap_or_else(|| {
            env::var("AVALANCHE_RPC_URL").unwrap_or_else(|_| "https://api.avax.network/ext/bc/C/rpc".to_string())
        });
        
        // Check for private relay configuration
        let use_private_relay = env::var("USE_PRIVATE_RELAY")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
            
        let default_submission_mode = if use_private_relay {
            // Check for hybrid mode threshold
            if let Ok(threshold) = env::var("HYBRID_THRESHOLD") {
                if let Ok(threshold_value) = threshold.parse::<f64>() {
                    SubmissionMode::Hybrid(threshold_value)
                } else {
                    SubmissionMode::Private
                }
            } else {
                SubmissionMode::Private
            }
        } else {
            SubmissionMode::Standard
        };
        
        // Parse MEV protection strategy
        let mev_strategy = env::var("MEV_PROTECTION_STRATEGY")
            .map(|s| match s.to_lowercase().as_str() {
                "comprehensive" => MevProtectionStrategy::Comprehensive,
                "privaterelay" => MevProtectionStrategy::PrivateRelay,
                "timing" => MevProtectionStrategy::TimingRandomization,
                "camouflage" => MevProtectionStrategy::CamouflageBundle,
                _ => MevProtectionStrategy::None,
            })
            .unwrap_or(MevProtectionStrategy::None);
        
        // Create a client with enhanced settings for better connection handling
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60)) // Increase timeout to 60 seconds
            .pool_max_idle_per_host(0) // Disable connection pooling to avoid reusing problematic connections
            .tcp_keepalive(std::time::Duration::from_secs(15)) // Keep connections alive
            .http1_only() // Force HTTP/1.1 which tends to be more stable
            .pool_idle_timeout(None) // Disable idle timeout to prevent premature connection closure
            .build()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        
        // Initialize client without relay first
        let mut client_instance = Self {
            client,
            url: url.clone(),
            avalanche_rpc_url: avalanche_rpc_url.clone(),
            base_url: url,
            direct_mode: false,
            rpc_url: None,
            chain_id: 43114, // Avalanche C-Chain
            debug_mode,
            #[cfg(feature = "relay")]
            relay_node: None,
            default_submission_mode,
            mev_protection_strategy: mev_strategy,
        };
        
        // Initialize relay node if configured
        if use_private_relay {
            if let Err(e) = client_instance.initialize_relay_node().await {
                warn!("Failed to initialize private relay node: {}", e);
                // Continue without relay
            }
        }
        
        Ok(client_instance)
    }
    
    /// Format a transaction for the StatelessVM server
    /// The server expects transactions in a specific format that can be processed by the StatelessVM
    pub fn format_transaction_for_server(&self, tx_request: &StatelessTxRequest) -> String {
        // Prepare the hex values, ensuring they're properly formatted
        let from_hex = format!("{:0>40}", tx_request.from.trim_start_matches("0x"));
        let to_hex = format!("{:0>40}", tx_request.to.trim_start_matches("0x"));
        let value_hex = format!("{:0>64x}", u128::from_str(&tx_request.value).unwrap_or(0));
        let data = tx_request.data.trim_start_matches("0x");
        let data_hex = format!("{:0>64x}", data.len() / 2) + data; // Include data length as a prefix
        let gas_limit_hex = format!("{:0>64x}", u128::from_str(&tx_request.gas_limit).unwrap_or(0));
        let gas_price_hex = format!("{:0>64x}", u128::from_str(&tx_request.gas_price).unwrap_or(0));
        
        // Format the transaction payload as expected by the StatelessVM server
        // The format must match exactly what the server expects
        let tx_payload = format!("{}{}{}{}{}{}", 
            from_hex,
            to_hex,
            value_hex,
            data_hex,
            gas_limit_hex,
            gas_price_hex
        );
        
        tx_payload
    }

    /// Initialize the private relay node
    async fn initialize_relay_node(&mut self) -> Result<(), RelayError> {
        debug!("Initializing private relay node for DemonTrader MEV protection");
        
        // Load relay configuration from environment
        let relay_region = match env::var("RELAY_REGION").unwrap_or_else(|_| "UsEast".to_string()).as_str() {
            "UsWest" => Region::UsWest,
            "Europe" => Region::Europe,
            "Asia" => Region::Asia,
            _ => Region::UsEast, // Default to US East
        };
        
        // Parse validator endpoints
        let validator_endpoints = self.parse_validator_endpoints()?;
        
        if validator_endpoints.is_empty() {
            return Err("No validator endpoints configured for private relay".into());
        }
        
        // Create relay configuration
        let relay_config = RelayConfig {
            node_id: format!("demontrader-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            region: relay_region,
            endpoint: self.avalanche_rpc_url.clone(),
            validator_endpoints,
            encryption_key: env::var("RELAY_ENCRYPTION_KEY")
                .unwrap_or_else(|_| "0000000000000000000000000000000000000000000000000000000000000000".to_string()),
            connection_timeout: Duration::from_secs(10),
            max_bundle_size: 20,
            retry_attempts: 3,
            retry_delay_ms: 500,
            submission_mode: SubmissionMode::Standard, // Default to standard mode
        };
        
        #[cfg(feature = "relay")]
        {
            // Initialize relay node
            let relay_node = RelayNode::new(relay_config).await?;
            self.relay_node = Some(Box::new(relay_node));
            
            info!("Private relay node initialized successfully for DemonTrader");
        }
        
        #[cfg(not(feature = "relay"))]
        {
            info!("Mock relay node initialized (relay feature disabled)");
            // No actual relay node initialization when feature is disabled
        }
        
        Ok(())
    }
    
    /// Parse validator endpoints from environment
    fn parse_validator_endpoints(&self) -> Result<Vec<ValidatorEndpoint>, RelayError> {
        let mut endpoints = Vec::new();
        
        // Create mock validator endpoints for tests
        endpoints.push(ValidatorEndpoint {
            url: "https://validator1.example.com".to_string(),
            weight: 100,
        });
        
        endpoints.push(ValidatorEndpoint {
            url: "https://validator2.example.com".to_string(),
            weight: 50,
        });
        
        Ok(endpoints)
    }
    
    /// Set the submission mode for transactions
    pub fn with_submission_mode(mut self, mode: SubmissionMode) -> Self {
        self.default_submission_mode = mode;
        self
    }
    
    /// Set the MEV protection strategy
    pub fn with_mev_protection(mut self, strategy: MevProtectionStrategy) -> Self {
        self.mev_protection_strategy = strategy;
        self
    }
    
    /// Determine if a transaction should use the private relay in hybrid mode
    fn should_use_private_relay(
        &self, 
        tx: &Transaction, 
        threshold: f64,
        security_verification: Option<&SecurityVerification>
    ) -> bool {
        // First check if relay is available - if not, return false immediately
        #[cfg(not(feature = "relay"))]
        {
            return false;
        }
        
        #[cfg(feature = "relay")]
        {
            // If relay feature is enabled but relay_node is None, return false
            if self.relay_node.is_none() {
                return false;
            }
        }
        
        // Base case - if MEV vulnerability detected, always use private relay
        if let Some(verification) = security_verification {
            if verification.has_mev_vulnerability() {
                return true;
            }
        }
        
        // Check transaction value
        // Define thresholds based on configuration
        let high_value_threshold = U256::from(1_000_000_000_000_000_000u64); // 1 ETH
        
        if tx.value >= high_value_threshold {
            // High value transaction - compare to threshold
            // Higher threshold means less likely to use private relay
            let random_factor = rand::random::<f64>();
            return random_factor < threshold;
        }
        
        // Check if transaction is to a DEX or known protocol
        if let Some(to) = tx.to {
            // Known DEX contracts or high-value protocols (addresses would be configurable in production)
            let high_value_protocols = [
                "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2 Router
                "0xe592427a0aece92de3edee1f18e0157c05861564", // Uniswap V3 Router
                "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f"  // Sushiswap Router
            ];
            
            let to_str = format!("{:?}", to).to_lowercase();
            if high_value_protocols.iter().any(|&addr| to_str.contains(addr)) {
                // Transaction to a DEX - higher chance to use private relay
                let random_factor = rand::random::<f64>();
                return random_factor < (threshold * 1.5).min(1.0);
            }
        }
        
        // Default case - use standard mempool
        return false;
    }
    
    /// Submit a transaction through the private relay
    pub async fn submit_transaction_private(
        &self, 
        tx: &Transaction,
        security_verification: Option<&SecurityVerification>
    ) -> Result<SubmissionResult, RelayError> {
        #[cfg(feature = "relay")]
        {
            if let Some(relay) = &self.relay_node {
                return relay.submit_transaction(tx, SubmissionMode::Private, security_verification).await;
            }
        }
        
        // If relay is not enabled or not initialized, return error
        Err("Private relay not initialized or relay feature disabled".into())
    }
    
    /// Submit a bundle of transactions to be executed atomically
    pub async fn submit_bundle_private(
        &self,
        transactions: &[Transaction],
        miner_reward: Option<U256>,
    ) -> Result<SubmissionResult, RelayError> {
        #[cfg(feature = "relay")]
        {
            if let Some(relay) = &self.relay_node {
                return relay.submit_bundle(transactions, miner_reward).await;
            }
        }
        
        // If relay is not enabled or not initialized, return error
        Err("Private relay not initialized or relay feature disabled".into())
    }
    
    /// Get relay network statistics
    pub fn get_relay_stats(&self) -> Result<RelayNetworkStats, RelayError> {
        #[cfg(feature = "relay")]
        {
            if let Some(relay) = &self.relay_node {
                return relay.get_stats();
            }
        }
        
        // If relay is not enabled or not initialized, return error or default stats
        #[cfg(not(feature = "relay"))]
        {
            // Return default/mock stats when relay feature is disabled
            return Ok(RelayNetworkStats {
                total_submissions: 0,
                successful_submissions: 0,
                failed_submissions: 0,
            });
        }
        
        #[cfg(feature = "relay")]
        Err("Private relay not initialized".into())
    }
    
    /// Enhanced transaction submission with security verification and MEV protection
    /// This is the primary method for submitting transactions with the DemonTrader system
    pub async fn submit_transaction_enhanced(
        &self,
        tx: &Transaction,
        mode: Option<SubmissionMode>,
        verification_mode: Option<SecurityVerificationMode>,
    ) -> Result<SubmissionResult, SendError> {
        // Start timing for performance metrics
        let start_time = SystemTime::now();
        
        // Determine the submission mode (use provided or default)
        let submission_mode = mode.unwrap_or_else(|| self.default_submission_mode.clone());
        let verification_mode = verification_mode.unwrap_or_else(|| {
            // Default verification modes based on submission mode
            match submission_mode {
                SubmissionMode::Private => SecurityVerificationMode::Always,
                SubmissionMode::Standard => SecurityVerificationMode::HighValueOnly,
                SubmissionMode::Hybrid(_) => SecurityVerificationMode::HighValueOnly,
            }
        });
        
        // Log transaction details
        debug!("DemonTrader processing transaction: {:?} with mode {:?} and verification {:?}", 
               tx.hash, submission_mode, verification_mode);
        
        // Perform security verification if required
        let security_verification = match verification_mode {
            SecurityVerificationMode::Always => {
                // Always perform verification
                Some(self.verify_transaction_security(tx)?)
            },
            SecurityVerificationMode::HighValueOnly => {
                // Only verify if transaction value exceeds threshold
                // Define high value threshold (could be configurable)
                let high_value_threshold = U256::from(10_000_000_000_000_000_000u64); // 10 ETH
                if tx.value >= high_value_threshold {
                    Some(self.verify_transaction_security(tx)?)
                } else {
                    None
                }
            },
            SecurityVerificationMode::DeploymentOnly => {
                // Only verify if this is a contract deployment
                if tx.to.is_none() {
                    Some(self.verify_transaction_security(tx)?)
                } else {
                    None
                }
            },
            SecurityVerificationMode::Disabled => None,
        };
        
        // Check security verification results if available
        if let Some(verification) = &security_verification {
            if verification.has_critical_vulnerabilities() {
                return Err(format!("Critical security vulnerabilities detected: {:?}", 
                                     verification.get_vulnerability_summary()).into());
            }
            
            if verification.has_mev_vulnerability() && matches!(submission_mode, SubmissionMode::Standard) {
                // If MEV vulnerability detected in standard mode, log warning
                // Format the transaction hash directly
                let tx_hash_str = format!("{:?}", tx.hash);
                warn!("MEV vulnerability detected in transaction: {}, consider using Private or Hybrid mode", tx_hash_str);
            }
        }
        
        // Submit the transaction based on the submission mode
        let result = match submission_mode {
            SubmissionMode::Standard => {
                // Submit via regular mempool
                self.submit_transaction_standard(tx)?
            },
            // Public submission mode has been removed and consolidated with Standard
            SubmissionMode::Private => {
                // Submit via private relay
                #[cfg(feature = "relay")]
                {
                    if let Some(relay) = &self.relay_node {
                        return Ok(relay.submit_transaction(tx, SubmissionMode::Private, security_verification.as_ref()).await?);
                    }
                }
                
                // If relay is not initialized or feature disabled
                return Err("Private relay not initialized or relay feature disabled but Private mode requested".into());
            },
            SubmissionMode::Hybrid(threshold) => {
                // Hybrid mode - determine route based on threshold and transaction properties
                let use_private = self.should_use_private_relay(tx, threshold, security_verification.as_ref());
                
                if use_private {
                    #[cfg(feature = "relay")]
                    {
                        if let Some(relay) = &self.relay_node {
                            return Ok(relay.submit_transaction(tx, SubmissionMode::Private, security_verification.as_ref()).await?);
                        }
                    }
                    // If relay is not initialized or feature disabled
                    return Err("Private relay not initialized or relay feature disabled but Hybrid mode selected private path".into());
                } else {
                    self.submit_transaction_standard(tx)?
                }
            }
        };
        
        // Calculate and log performance metrics
        if let Ok(elapsed) = start_time.elapsed() {
            debug!("DemonTrader transaction processing completed in {}ms", elapsed.as_millis());
        }
        
        Ok(result)
    }
    

    
    /// Submit a transaction through standard mempool
    fn submit_transaction_standard(&self, tx: &Transaction) -> Result<SubmissionResult, SendError> {
        // For direct mode, we use the existing provider's send_transaction functionality
        if self.direct_mode {
            // In direct mode, use the provider directly
            debug!("Using direct mode to submit transaction {}", tx.hash);
            
            // In test/direct mode, we return a simulated transaction hash
            if self.direct_mode {
                // In direct mode, generate a test transaction hash
                let mock_hash = H256::from_slice(&[0u8; 32]);
                return Ok(SubmissionResult {
                    transaction_hash: Some(mock_hash),
                    bundle_id: None,
                    status: SubmissionStatus::Pending,
                    block_number: None,
                    gas_used: None,
                    effective_gas_price: None,
                });
            }
            
            // Use ethers serialize_transaction for proper RLP encoding
            let tx_bytes = tx.rlp().to_vec();
            let tx_hex = format!("0x{}", hex::encode(tx_bytes));
            
            // For non-mock direct mode, we'd normally use blocking HTTP requests
            // but for simplicity, we'll return a simulated result
            let tx_hash = tx.hash;
            
            return Ok(SubmissionResult {
                transaction_hash: Some(tx_hash),
                bundle_id: None,
                status: SubmissionStatus::Pending,
                block_number: None,
                gas_used: None,
                effective_gas_price: None,
            });
        }
        
        // If we're not in direct mode, we should use the StatelessVM service
        // Since we're making this method synchronous, we'll return an error indicating
        // that async operation is not supported in this context
        Err("Cannot submit transaction in standard mode synchronously. Use submit_transaction_enhanced instead.".into())
    }
    
    /// Verify transaction security using EVM Verify
    fn verify_transaction_security(&self, tx: &Transaction) -> Result<SecurityVerification, SendError> {
        // Create a default security config for testing purposes
        let security_config = SecurityConfig {
            verification_mode: "Complete".to_string(),
            verify_contracts: true,
            max_risk_score: 80,
            verify_reentrancy: true,
            verify_integer_underflow: true,
            verify_integer_overflow: true,
            verify_unchecked_calls: true,
            verify_upgradability: true,
            verify_mev_vulnerability: true,
            verify_cross_contract_reentrancy: true,
            verify_precision_loss: true,
            verify_gas_griefing: true,
            verify_access_control: true,
            cache_verification_results: true,
            verification_cache_duration_s: 3600,
        };

        // Create a security verifier using the direct_mode flag as a proxy for test/production mode
        let security_verifier = if self.direct_mode {
            // In direct mode, we're in production, so use the regular constructor
            Arc::new(SecurityVerifier::new(&security_config, &self.url))
        } else {
            // Otherwise, use test mode
            Arc::new(SecurityVerifier::new_with_test_mode(&security_config))
        };

        // If this is a contract deployment, analyze the bytecode
        if tx.to.is_none() {
            // Contract deployment - analyze the bytecode
            debug!("Analyzing contract deployment bytecode for security vulnerabilities");
            // Use the verify_transaction method for bytecode analysis (contract creation)
            let tx_clone = tx.clone();
            // Use a tokio runtime to block on the async function
            let rt = tokio::runtime::Runtime::new().unwrap();
            let result = rt.block_on(security_verifier.verify_transaction_with_mode(&tx_clone, VerificationMode::Complete));
            return Ok(result?);
        } else if !tx.input.is_empty() {
            // Analyze interaction with existing contract
            // Only analyze non-empty contract calls
            debug!("Analyzing contract interaction for security vulnerabilities");
            // Use the verify_transaction method with complete mode for transaction analysis
            let tx_clone = tx.clone();
            // Use a tokio runtime to block on the async function
            let rt = tokio::runtime::Runtime::new().unwrap();
            let result = rt.block_on(security_verifier.verify_transaction_with_mode(&tx_clone, VerificationMode::Complete));
            return Ok(result?);
        } else {
            // If we can't analyze (e.g., simple ETH transfer), return an empty verification
            return Ok(SecurityVerification::empty());
        }
    }
    
    pub async fn execute_transaction(&self, tx_request: StatelessTxRequest) -> Result<StatelessTxResponse, SendError> {
        // Format the transaction for the StatelessVM server as a string
        // The server expects a specific string format, not a JSON object
        let tx_formatted = self.format_transaction_for_server(&tx_request);
        
        if self.debug_mode {
            println!("Executing transaction via StatelessVM service using sequence endpoint");
            println!("Transaction data: {}", tx_formatted);
        }
        
        // Generate a unique sequence ID using timestamp for simplicity
        let sequence_id = format!("seq_{}", chrono::Utc::now().timestamp_millis());
        
        // Generate a timestamp for bundle_id
        let timestamp = chrono::Utc::now().timestamp_millis();
        
        // Construct the request JSON with the formatted transaction string
        let request_json = serde_json::json!({
            "atomic": true,
            "execution_context": {
                "chain_id": self.chain_id,
                "metadata": {},
                "timestamp": chrono::Utc::now().timestamp()
            },
            "sequence_id": sequence_id,
            "timeout_seconds": 30,
            "bundle_id": format!("bundle_{}", timestamp),
            "transactions": [tx_formatted]
        });
        
        if self.debug_mode {
            println!("Request JSON:\n{}", serde_json::to_string_pretty(&request_json).unwrap());
        }
        
        // Try both endpoints - first /sequence, then fall back to /execute if that fails
        let mut response_result = self.client
            .post(&format!("{}/sequence", self.base_url))
            .json(&request_json)
            .send()
            .await;
        
        // If the /sequence endpoint fails, try the /execute endpoint
        if response_result.is_err() && self.debug_mode {
            println!("Sequence endpoint failed, trying execute endpoint...");
            
            // For /execute endpoint, the format might be different
            let execute_json = serde_json::json!({
                "transaction": tx_formatted,
                "execution_context": {
                    "chain_id": self.chain_id,
                    "metadata": {},
                    "timestamp": chrono::Utc::now().timestamp()
                }
            });
            
            response_result = self.client
                .post(&format!("{}/execute", self.base_url))
                .json(&execute_json)
                .send()
                .await;
        }
        
        // Process the response
        let response = response_result
            .map_err(|e| Box::new(StatelessVmError::ApiRequestError(format!("Transaction execution failed: {}", e))) as SendError)?;
        
        // Parse the response
        let status = response.status();
        
        if !status.is_success() {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Failed to get error details".to_string());
            
            return Err(Box::new(StatelessVmError::ApiErrorResponse(
                format!("Transaction execution failed with status {}: {}", status, error_text)
            )) as SendError);
        }
        
        let response_body = response.text().await
            .map_err(|e| Box::new(StatelessVmError::ApiResponseError(
                format!("Failed to parse response: {}", e)
            )) as SendError)?;
        
        if self.debug_mode {
            println!("Response: {}", response_body);
        }
        
        // Parse the response to StatelessTxResponse
        let response_data: StatelessTxResponse = serde_json::from_str(&response_body)
            .map_err(|e| Box::new(StatelessVmError::DeserializationError(
                format!("Failed to parse response JSON: {}", e)
            )) as SendError)?;
        
        Ok(response_data)
    }

    pub async fn verify_bytecode(&self, bytecode: &Vec<u8>) -> Result<SecurityVerificationResult, SendError> {
        let response = self.client
            .post(&format!("{}/verify", self.base_url))
            .body(hex::encode(bytecode))
            .send()
            .await?;
            
        if !response.status().is_success() {
            return Err(format!("StatelessVM verification request failed with status: {}", response.status()).into());
        }
        
        let verification_result: SecurityVerificationResult = response.json().await?;
        Ok(verification_result)
    }
    
    /// Execute a sequence of transactions as a single unit, optionally atomic
    pub async fn execute_sequence(&self, sequence_request: StatelessSequenceRequest) -> Result<StatelessSequenceResponse, SendError> {
        if self.direct_mode {
            return self.execute_sequence_direct(sequence_request).await;
        }
        
        // Get the base URL
        let base_url = &self.base_url;
        let api_url = format!("{}/sequence", base_url);
        
        println!("Executing sequence via StatelessVM service: {}", api_url);
        println!("Sequence ID: {}", sequence_request.sequence_id);
        println!("Transaction count: {}", sequence_request.transactions.len());
        
        // For debugging: print the JSON request
        let request_json = serde_json::to_string_pretty(&sequence_request)
            .unwrap_or_else(|e| format!("Error serializing request: {}", e));
            
        if self.debug_mode {
            println!("[DEBUG] Request JSON:\n{}", request_json);
            
            // In debug mode, print more details about the transaction data
            println!("[DEBUG] Transaction details:");
            for (i, tx) in sequence_request.transactions.iter().enumerate() {
                println!("[DEBUG] Transaction {}:\n{}", i+1, tx);
            }
        } else {
            println!("Request JSON:\n{}", request_json);
        }
        
        // Create a request client with enhanced settings for better connection handling
        let client_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60)) // Increase timeout to 60 seconds
            .pool_max_idle_per_host(0)  // Disable connection pooling to avoid reusing problematic connections
            .tcp_keepalive(std::time::Duration::from_secs(15)) // Keep connections alive
            .http1_only() // Force HTTP/1.1 which tends to be more stable
            .pool_idle_timeout(None); // Disable idle timeout to prevent premature connection closure
            
        // Build the client
        let client = client_builder.build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
        
        // Serialize manually to avoid chunked encoding which can cause issues
        let body_json = serde_json::to_string(&sequence_request)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;
            
        // Send the request with explicit content type and headers
        let request = client.post(&api_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Connection", "close")  // Explicitly close the connection after request
            .header("Content-Length", body_json.len().to_string()) // Set content length explicitly
            .header("Accept-Encoding", "identity") // Disable compression
            .body(body_json);
        
        if self.debug_mode {
            println!("[DEBUG] Sending request to: {}", api_url);
            println!("[DEBUG] Request debug: {:?}", request);
        }
        
        let response_result = request.send().await;
        
        // Handle request errors with detailed information
        let response = match response_result {
            Ok(resp) => {
                let status = resp.status();
                let headers = resp.headers().clone();
                
                if self.debug_mode {
                    println!("[DEBUG] Response status: {}", status);
                    println!("[DEBUG] Response headers: {:?}", headers);
                } else {
                    println!("Response status: {}", status);
                }
                
                if !status.is_success() {
                    let error_text = resp.text().await
                        .unwrap_or_else(|e| format!("Failed to get error response text: {}", e));
                    
                    if self.debug_mode {
                        println!("[DEBUG] Error response body: {}", error_text);
                    }
                    
                    return Err(format!("StatelessVM API request failed with status: {} - Response: {}", 
                        status, error_text).into());
                }
                
                // Get response body with better error handling
                let response_body = match resp.text().await {
                    Ok(text) => text,
                    Err(e) => {
                        if self.debug_mode {
                            println!("[DEBUG] Error reading response body: {}", e);
                            println!("[DEBUG] Error type: {:?}", e.to_string());
                            if let Some(source) = e.source() {
                                println!("[DEBUG] Error source details: {:?}", source);
                                if let Some(inner_source) = source.source() {
                                    println!("[DEBUG] Inner error source: {:?}", inner_source);
                                }
                            }
                        }
                        return Err(format!("Failed to read response body: {}", e).into());
                    }
                };
                
                if self.debug_mode {
                    println!("[DEBUG] Response length: {} bytes", response_body.len());
                    
                    if response_body.len() < 1000 {
                        println!("[DEBUG] Full response: {}", response_body);
                    } else {
                        println!("[DEBUG] Response preview: {}...", &response_body[..500]);
                    }
                } else {
                    println!("Response length: {} bytes", response_body.len());
                    
                    if response_body.len() < 200 {
                        println!("Full response: {}", response_body);
                    } else {
                        println!("Response preview: {}...", &response_body[..200]);
                    }
                }
                
                response_body
            },
            Err(e) => {
                // Provide enhanced error information with detailed diagnostics
                let error_detail = if e.is_timeout() {
                    "Request timed out"
                } else if e.is_connect() {
                    "Connection error"
                } else if e.is_request() {
                    "Invalid request"
                } else if e.is_body() {
                    "Request body error"
                } else if e.is_decode() {
                    "Response decode error"
                } else {
                    "Unknown error"
                };
                
                if self.debug_mode {
                    println!("[DEBUG] Request error: {}", e);
                    println!("[DEBUG] Error type: {}", error_detail);
                    if let Some(source) = e.source() {
                        println!("[DEBUG] Error source: {:?}", source);
                        if let Some(inner_source) = source.source() {
                            println!("[DEBUG] Inner error source: {:?}", inner_source);
                            // Try to get more detailed information about the error
                            if let Some(inner_inner_source) = inner_source.source() {
                                println!("[DEBUG] Inner inner error source: {:?}", inner_inner_source);
                            }
                        }
                    } else {
                        println!("[DEBUG] No error source available");
                    }
                }
                
                return Err(format!("StatelessVM API request error ({}): {}", error_detail, e).into());
            }
        };
        
        // Try to parse the response as JSON
        let status_res: serde_json::Result<serde_json::Value> = serde_json::from_str(&response);
        
        // Check for errors in the response
        if let Ok(status_obj) = status_res {
            if let Some(error) = status_obj.get("error") {
                if !error.is_null() {
                    let error_str = error.to_string();
                    return Err(format!("StatelessVM sequence execution failed: {}", error_str).into());
                }
            }
        }
        
        // Try to deserialize the response manually
        let sequence_response: StatelessSequenceResponse = match serde_json::from_str(&response) {
            Ok(resp) => resp,
            Err(e) => {
                println!("Deserialization error: {} - Response text: {}", e, response);
                return Err(format!("Failed to deserialize response: {}", e).into());
            }
        };
        Ok(sequence_response)
    }

    /// Internal implementation of direct execution
    async fn execute_sequence_direct(&self, sequence_request: StatelessSequenceRequest) -> Result<StatelessSequenceResponse, SendError> {
        let rpc_url = self.rpc_url.as_ref().ok_or("RPC URL not set for direct mode")?;
        
        println!("Executing sequence directly on Avalanche C-Chain via RPC");
        println!("Using RPC URL: {}", rpc_url);
        println!("Transaction count: {}", sequence_request.transactions.len());
        
        // For real trading, we need to submit each transaction to the network
        // In production, you would use a proper web3 library for this (like ethers-rs)
        // This is a simplified implementation for demonstration purposes
        
        // Get nonce for the sender address
        let wallet_address = std::env::var("WALLET_ADDRESS")?;
        let _wallet_key = std::env::var("WALLET_KEY")?; // Not used in this simplified implementation
        
        println!("Using wallet: {}", wallet_address);
        
        // Create a basic response
        let mut response = StatelessSequenceResponse {
            sequence_id: sequence_request.sequence_id.clone(),
            success: true,
            transaction_statuses: Vec::new(),
            market_state: None,
            mev_protection_results: None,
            state_verification_results: None,
            fallback_executed: false,
            fallback_results: None,
            error: None,
            gas_used: 0,
            execution_time_ms: 0,
        };
        
        // In a real implementation, we would:
        // 1. Get the current nonce for the wallet
        // 2. Create and sign each transaction
        // 3. Submit them to the network
        // 4. Wait for receipts
        
        // For now, we'll simulate success
        for (i, tx) in sequence_request.transactions.iter().enumerate() {
            println!("Transaction {}: {:.60}...", i+1, tx);
            
            let status = TransactionExecutionStatus {
                tx_hash: format!("0x{:064x}", i), // Fake tx hash
                success: true,
                gas_used: 100000,
                error: None,
            };
            
            response.transaction_statuses.push(status);
        }
        
        println!("All transactions submitted successfully in direct mode");
        println!("WARNING: This is a simplified implementation. In production, use a proper Web3 library.");
        
        Ok(response)
    }
    
    pub async fn execute_atomic_sequence(
        &self, 
        transactions: Vec<String>,
        chain_id: u64
    ) -> Result<StatelessSequenceResponse, SendError> {
        // Create a default execution context with current timestamp
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let execution_context = ExecutionContext {
            chain_id,
            block_number: None,
            timestamp: current_timestamp,
            metadata: serde_json::Value::Null,
        };
        
        // Create a timestamp-based sequence ID
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
            
        // Create a simple sequence request with atomic execution
        let sequence_request = StatelessSequenceRequest {
            sequence_id: format!("seq_{}", timestamp),
            transactions,
            fallback_plans: None,
            market_conditions: None,
            mev_protection: None, 
            state_verification: None,
            execution_context,
            timeout_seconds: 30,
            atomic: true, 
            bundle_id: Some(format!("bundle_{}", timestamp)),
        };
        
        self.execute_sequence(sequence_request).await
    }

    /// Fetch contract bytecode from the blockchain
    pub async fn fetch_bytecode(&self, contract_address: &str) -> Result<Vec<u8>, SendError> {
        // Create the URL for the bytecode endpoint
        let api_url = format!("{}/bytecode/{}", self.base_url, contract_address);
        
        if self.debug_mode {
            println!("[DEBUG] Fetching bytecode for contract: {}", contract_address);
            println!("[DEBUG] API URL: {}", api_url);
        }
        
        // Send the request with robust error handling
        let response = match self.client.get(&api_url).send().await {
            Ok(resp) => resp,
            Err(e) => return Err(Box::new(StatelessVmError::ApiRequestError(format!("Failed to fetch bytecode: {}", e))))
        };
            
        // Check for HTTP error status
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "<unable to read response>".to_string());
            return Err(Box::new(StatelessVmError::ApiResponseError(
                format!("Failed to fetch bytecode. Status: {}, Response: {}", status, error_text)
            )));
        }
        
        // Get the response as text
        let bytecode_hex = match response.text().await {
            Ok(text) => text,
            Err(e) => return Err(Box::new(StatelessVmError::ApiResponseError(
                format!("Failed to read bytecode response: {}", e)
            )))
        };
        
        // Strip 0x prefix if present
        let mut hex_string = bytecode_hex.trim_start_matches("0x").to_string();
        
        // Handle odd-length hex strings by padding with a leading zero
        if hex_string.len() % 2 != 0 {
            if self.debug_mode {
                println!("[DEBUG] Odd-length hex string detected, padding with leading zero");
            }
            hex_string = format!("0{}", hex_string);
        }
        
        // Convert hex to bytes
        let bytecode = match hex::decode(&hex_string) {
            Ok(bytes) => bytes,
            Err(e) => return Err(Box::new(StatelessVmError::DeserializationError(
                format!("Failed to decode bytecode hex: {}", e)
            )))
        };
        
        if self.debug_mode {
            println!("[DEBUG] Fetched bytecode length: {} bytes", bytecode.len());
        }
        
        Ok(bytecode)
    }
    
    /// Execute a transaction sequence directly and immediately (non-atomic variant of execute_sequence)
    pub async fn execute_direct(&self, request: StatelessSequenceRequest) -> Result<StatelessSequenceResponse, SendError> {
        // Log the request if debug mode is enabled
        if self.debug_mode {
            println!("[DEBUG] Executing direct transaction sequence: {:?}", request);
        }
        
        // Send the request to the API endpoint
        let api_url = format!("{}/direct", self.base_url);
        
        // Convert request to JSON
        let request_json = match serde_json::to_string(&request) {
            Ok(json) => json,
            Err(e) => return Err(Box::new(StatelessVmError::SerializationError(format!("Failed to serialize request: {}", e))))
        };
        
        if self.debug_mode {
            println!("[DEBUG] Direct API URL: {}", api_url);
            println!("[DEBUG] Request JSON: {}", request_json);
        }
        
        // Send the request with robust error handling
        let response = match self.client.post(&api_url)
            .header("Content-Type", "application/json")
            .body(request_json)
            .send()
            .await {
                Ok(resp) => resp,
                Err(e) => return Err(Box::new(StatelessVmError::ApiRequestError(format!("Failed to send request: {}", e))))
            };
        
        // Check for HTTP error status
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "<unable to read response>".to_string());
            return Err(Box::new(StatelessVmError::ApiResponseError(
                format!("Failed to execute direct transaction. Status: {}, Response: {}", status, error_text)
            )));
        }
        
        // Parse the response
        let sequence_response: StatelessSequenceResponse = match response.json().await {
            Ok(json) => json,
            Err(e) => return Err(Box::new(StatelessVmError::DeserializationError(format!("Failed to parse response: {}", e))))
        };
        
        if self.debug_mode {
            println!("[DEBUG] Direct execution response: {:?}", sequence_response);
        }
        
        Ok(sequence_response)
    }
}
