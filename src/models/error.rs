use std::error::Error as StdError;
use std::fmt;

/// A custom error type for the AI Trading Agent
#[derive(Debug)]
pub enum AgentError {
    DataError(String),
    StrategyError(String),
    ExecutionError(String),
    ConfigError(String),
    RpcError(String),
    WalletError(String),
    RiskLimitExceeded(String),
    GeneralError {
        message: String,
        source: Option<Box<dyn StdError + Send + Sync>>,
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::DataError(msg) => write!(f, "Data error: {}", msg),
            AgentError::StrategyError(msg) => write!(f, "Strategy error: {}", msg),
            AgentError::ExecutionError(msg) => write!(f, "Execution error: {}", msg),
            AgentError::ConfigError(msg) => write!(f, "Config error: {}", msg),
            AgentError::RpcError(msg) => write!(f, "RPC error: {}", msg),
            AgentError::WalletError(msg) => write!(f, "Wallet error: {}", msg),
            AgentError::RiskLimitExceeded(msg) => write!(f, "Risk limit exceeded: {}", msg),
            AgentError::GeneralError { message, .. } => write!(f, "Error: {}", message)
        }
    }
}

impl StdError for AgentError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            AgentError::GeneralError { source, .. } => source.as_ref().map(|e| e.as_ref() as &(dyn StdError + 'static)),
            _ => None
        }
    }
}

impl From<Box<dyn StdError + Send + Sync>> for AgentError {
    fn from(err: Box<dyn StdError + Send + Sync>) -> Self {
        AgentError::GeneralError {
            message: format!("{}", err),
            source: Some(err),
        }
    }
}

impl From<Box<dyn StdError>> for AgentError {
    fn from(err: Box<dyn StdError>) -> Self {
        let message = format!("{}", err);
        AgentError::GeneralError {
            message,
            source: None, // We can't safely convert the Box<dyn StdError> to Box<dyn StdError + Send + Sync>
        }
    }
}

impl From<String> for AgentError {
    fn from(message: String) -> Self {
        AgentError::GeneralError {
            message,
            source: None,
        }
    }
}

impl From<&str> for AgentError {
    fn from(message: &str) -> Self {
        AgentError::GeneralError {
            message: message.to_string(),
            source: None,
        }
    }
}

// Define a type alias for our Result type
pub type AgentResult<T> = Result<T, AgentError>;
