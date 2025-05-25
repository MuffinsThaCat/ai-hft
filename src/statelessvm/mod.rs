// Export the client module directly
pub mod client;
pub mod client_new;

// Re-export the most commonly used types for convenience, but we encourage using
// direct imports from the client module for consistency

// DO NOT add new re-exports here. Use the client module directly instead.
// Example: use ai_trading_agent::statelessvm::client::StatelessVmClient;
