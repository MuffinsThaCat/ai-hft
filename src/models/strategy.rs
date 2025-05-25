use std::error::Error;
use ethers::types::{H160, U256};

#[derive(Debug, Clone)]
pub struct StrategyResult {
    pub strategy_type: String,
    pub description: String,
    pub confidence: f64,
    pub actions: Vec<TradingAction>,
    pub expected_profit_usd: f64,
    pub risk_level: u8,
}

// Represents a specific trading action as part of a strategy
#[derive(Debug, Clone)]
pub struct TradingAction {
    pub action_type: ActionType,
    pub asset: String,
    pub amount: String,
    pub reason: String,
    pub target_address: String,     // Contract address to interact with
    pub action_data: String,        // Encoded contract call data
    pub gas_price: Option<String>,  // Optional gas price override
    pub nonce: Option<u64>,         // Optional nonce override
}

// Types of actions that can be taken as part of a trading strategy
#[derive(Debug, Clone)]
pub enum ActionType {
    Buy,
    Sell,
    Swap,
    Liquidate,
    Borrow,
    Repay,
    Stake,
    Unstake,
    Flash,
}

// Legacy enum for backward compatibility - will eventually be replaced by TradingAction
#[derive(Debug, Clone)]
pub enum TradeAction {
    Buy {
        token_address: H160,
        amount: U256,
        price: f64,
        dex: String,
    },
    Sell {
        token_address: H160,
        amount: U256,
        price: f64,
        dex: String,
    },
    Arbitrage {
        token_address: H160,
        buy_dex: String,
        sell_dex: String,
        amount: U256,
        expected_profit: f64,
    },
    Liquidate {
        protocol: String,
        user_address: String,
        collateral_token: String,
        debt_token: String,
        collateral_amount: f64,
        debt_amount: f64,
    },
    None,
}

// Security verification modes (from memory about StatelessVM integration)
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityVerificationMode {
    Always,          // Always verify every transaction
    DeploymentOnly,  // Only verify during contract deployment
    HighValueOnly,   // Only verify transactions above a certain value threshold
    Disabled,        // No verification (use with caution)
}
