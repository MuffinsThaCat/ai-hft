use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use ethers::prelude::*;

/// Price point represents a price and quantity at a specific level in the order book
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricePoint {
    /// Price of the token
    pub price: f64,
    /// Quantity available at this price
    pub quantity: f64,
}

/// Order book structure containing bids and asks for a token pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBook {
    /// Exchange name
    pub exchange: String,
    /// Base token symbol (e.g., ETH in ETH/USDC)
    pub base_token: String,
    /// Quote token symbol (e.g., USDC in ETH/USDC)
    pub quote_token: String,
    /// List of bid (buy) orders sorted by price descending
    pub bids: Vec<PricePoint>,
    /// List of ask (sell) orders sorted by price ascending
    pub asks: Vec<PricePoint>,
    /// Timestamp when the order book was retrieved
    pub timestamp: DateTime<Utc>,
}

/// Trading opportunity identified by the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Opportunity {
    /// Base token symbol
    pub base_token: String,
    /// Quote token symbol
    pub quote_token: String,
    /// Expected profit percentage
    pub profit_percent: f64,
    /// Market data associated with this opportunity
    pub market_data: MarketData,
    /// Unique identifier for this opportunity
    pub opportunity_id: String,
    /// Time when this opportunity expires
    pub expires_at: DateTime<Utc>,
}

/// Market data associated with a trading opportunity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketData {
    /// Exchange where to buy
    pub buy_exchange: String,
    /// Exchange where to sell
    pub sell_exchange: String,
    /// Buy price
    pub buy_price: f64,
    /// Sell price
    pub sell_price: f64,
    /// Timestamp of the market data
    pub timestamp: DateTime<Utc>,
}

/// Gas information for estimating transaction costs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasInfo {
    /// Current gas price in GWEI
    pub gas_price_gwei: f64,
    /// Estimated gas used for the transaction
    pub estimated_gas: u64,
    /// Gas price in USD
    pub gas_price_usd: f64,
}

/// Transaction record for a completed trade
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    /// Transaction hash
    pub tx_hash: H256,
    /// Block number where the transaction was included
    pub block_number: Option<u64>,
    /// Transaction type (buy, sell, swap, etc.)
    pub tx_type: TransactionType,
    /// Base token symbol
    pub base_token: String,
    /// Quote token symbol
    pub quote_token: String,
    /// Amount of base token traded
    pub base_amount: f64,
    /// Amount of quote token traded
    pub quote_amount: f64,
    /// Exchange where the transaction was executed
    pub exchange: String,
    /// Gas used for the transaction
    pub gas_used: u64,
    /// Gas price in GWEI
    pub gas_price_gwei: f64,
    /// Transaction cost in USD
    pub tx_cost_usd: f64,
    /// Profit or loss in USD
    pub profit_loss_usd: f64,
    /// Timestamp when the transaction was executed
    pub timestamp: DateTime<Utc>,
    /// StatelessVM execution metrics if applicable
    pub statelessvm_metrics: Option<StatelessVmMetrics>,
}

/// Types of transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    /// Buy transaction
    Buy,
    /// Sell transaction
    Sell,
    /// Swap transaction
    Swap,
    /// Arbitrage transaction
    Arbitrage,
    /// Liquidity provision
    LiquidityProvide,
    /// Liquidity removal
    LiquidityRemove,
}

/// Performance metrics for StatelessVM execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessVmMetrics {
    /// Time taken to generate witness in milliseconds
    pub witness_generation_time_ms: u64,
    /// Time taken to submit transaction in milliseconds
    pub tx_submission_time_ms: u64,
    /// Total execution time in milliseconds
    pub total_execution_time_ms: u64,
    /// Whether security verification was performed
    pub security_verification_performed: bool,
    /// Security verification result if performed
    pub security_verification_result: Option<SecurityVerificationResult>,
}

/// Result of security verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVerificationResult {
    /// Whether verification passed
    pub passed: bool,
    /// Risk score (0-100)
    pub risk_score: u8,
    /// List of security issues found
    pub issues: Vec<SecurityIssue>,
}

/// Security issue identified during verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    /// Issue type
    pub issue_type: SecurityIssueType,
    /// Issue description
    pub description: String,
    /// Issue severity (1-5)
    pub severity: u8,
}

/// Types of security issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityIssueType {
    /// Reentrancy vulnerability
    Reentrancy,
    /// Integer underflow
    IntegerUnderflow,
    /// Integer overflow
    IntegerOverflow,
    /// Unchecked calls
    UncheckedCalls,
    /// Upgradability issue
    UpgradabilityIssue,
    /// MEV vulnerability
    MevVulnerability,
    /// Cross-contract reentrancy
    CrossContractReentrancy,
    /// Precision loss
    PrecisionLoss,
    /// Gas griefing
    GasGriefing,
    /// Other issue
    Other,
}
