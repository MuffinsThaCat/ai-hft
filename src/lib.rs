// lib.rs - Main library entry point for ai_trading_agent

// Re-export modules that should be publicly accessible
pub mod data;
pub mod execution;
pub mod models;
pub mod reasoning;
pub mod security;
pub mod statelessvm;
pub mod strategies;
pub mod utils;
pub mod wallet;

// Optionally re-export important types for convenience
pub use models::error::{AgentError, AgentResult};
pub use models::strategy::StrategyResult;
pub use reasoning::engine::ReasoningEngine;
pub use security::verifier::SecurityVerifier;
pub use statelessvm::client::StatelessVmClient;
