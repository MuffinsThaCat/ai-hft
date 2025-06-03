use serde::{Deserialize, Serialize};
use std::time::Duration;
use ethers::types::{Transaction, H256, U256, Address};
use std::sync::Arc;

pub type TransactionHash = H256;
pub type RelayError = Box<dyn std::error::Error + Send + Sync>;

/// Available regions for relay nodes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Region {
    UsEast,
    UsWest,
    Europe,
    Asia,
}

/// Configuration for a relay node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub node_id: String,
    pub region: Region,
    pub endpoint: String,
    pub validator_endpoints: Vec<ValidatorEndpoint>,
    pub encryption_key: String,
    pub connection_timeout: Duration,
    pub max_bundle_size: usize,
    pub retry_attempts: u8,
    pub retry_delay_ms: u64,
}

/// Validator connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEndpoint {
    pub id: String,
    pub endpoint: String,
    pub stake_weight: f64,
    pub priority: u8,
    pub auth_token: Option<String>,
}

/// Encrypted transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTransaction {
    pub encrypted_data: Vec<u8>,
    pub public_metadata: TransactionMetadata,
    pub sender: Option<Address>,
    pub nonce: Option<U256>,
}

/// Public metadata for encrypted transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMetadata {
    pub gas_limit: u64,
    pub gas_price: U256,
    pub priority_fee: Option<U256>,
    pub value: U256,
    pub size_bytes: usize,
    pub expires_at: u64,
}

/// Types of transaction submission modes
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SubmissionMode {
    /// Standard public mempool submission
    Standard,
    /// Private relay only submission
    Private,
    /// Hybrid submission with threshold-based routing
    Hybrid(f64), // Threshold value for private routing
}

/// Bundle of transactions to be executed atomically
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionBundle {
    pub bundle_id: String,
    pub transactions: Vec<EncryptedTransaction>,
    pub miner_reward: Option<U256>,
    pub target_block: Option<u64>,
    pub timestamps: BundleTimestamps,
    pub status: BundleStatus,
}

/// Timestamps for bundle tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleTimestamps {
    pub created_at: u64,
    pub submitted_at: Option<u64>,
    pub confirmed_at: Option<u64>,
    pub expires_at: u64,
}

/// Status of a transaction bundle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BundleStatus {
    Created,
    Validating,
    Submitted,
    Accepted,
    Rejected(String),
    Confirmed,
    Failed(String),
    Expired,
}

/// Result of a transaction submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionResult {
    pub transaction_hash: Option<TransactionHash>,
    pub bundle_id: Option<String>,
    pub status: SubmissionStatus,
    pub block_number: Option<u64>,
    pub gas_used: Option<u64>,
    pub effective_gas_price: Option<U256>,
}

/// Status of a transaction submission
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SubmissionStatus {
    Pending,
    Confirmed,
    Failed(String),
}

/// MEV protection strategy options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MevProtectionStrategy {
    /// No protection, standard submission
    None,
    /// Basic private relay
    PrivateRelay,
    /// Timing-based protection (randomization)
    TimingRandomization,
    /// Bundle with dummy transactions to obscure intent
    CamouflageBundle,
    /// Full protection with all available strategies
    Comprehensive,
}

/// Relay network statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayNetworkStats {
    pub total_transactions_submitted: u64,
    pub total_bundles_submitted: u64,
    pub successful_transactions: u64,
    pub failed_transactions: u64,
    pub average_confirmation_time_ms: u64,
    pub average_latency_ms: u64,
    pub total_gas_saved: U256,
    pub total_validator_rewards: U256,
}
