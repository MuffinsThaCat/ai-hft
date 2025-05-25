use crate::models::error::{AgentError, AgentResult};
use ethers::prelude::*;
use ethers::types::transaction::eip2718::TypedTransaction;
use std::sync::Arc;
use std::env;
use std::path::Path;
use std::fs;
use log::{info, warn, error};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Secure wallet module for the trading agent to handle private keys and transactions
pub struct WalletManager {
    /// The wallet provider, which can be either a local key or a hardware wallet
    wallet_provider: WalletProvider,
    /// The chain ID for signing transactions
    chain_id: u64,
    /// Transaction limits for risk management
    transaction_limits: TransactionLimits,
}

/// Types of wallet providers supported
enum WalletProvider {
    /// Local private key (encrypted at rest)
    LocalKey(Arc<RwLock<LocalSignerWallet>>),
    /// Hardware wallet (e.g., Ledger)
    #[allow(dead_code)]
    HardwareWallet(Arc<RwLock<HardwareWallet>>),
}

/// Wallet implementation using a local private key
struct LocalSignerWallet {
    /// The wallet instance from ethers
    wallet: LocalWallet,
    /// Path to the keystore file
    keystore_path: String,
}

/// Hardware wallet implementation
#[allow(dead_code)]
struct HardwareWallet {
    /// Address of the hardware wallet
    address: Address,
    /// Device path or identifier
    device_path: String,
    /// Whether the wallet is connected
    is_connected: bool,
}

/// Transaction limits for risk management
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionLimits {
    /// Maximum amount per transaction in USD
    pub max_transaction_amount_usd: f64,
    /// Maximum gas price in GWEI
    pub max_gas_price_gwei: f64,
    /// Maximum transactions per day
    pub max_daily_transactions: u32,
    /// Current transaction count for the day
    pub current_daily_transactions: u32,
}

impl WalletManager {
    /// Create a new wallet manager from environment or config
    pub async fn new() -> AgentResult<Self> {
        // Load chain ID from environment or use default (43114 for Avalanche C-Chain)
        let chain_id = env::var("CHAIN_ID")
            .ok()
            .and_then(|id| id.parse::<u64>().ok())
            .unwrap_or(43114);
        
        // Load transaction limits
        let transaction_limits = Self::load_transaction_limits()?;
        
        // Determine wallet type from environment
        let wallet_provider = if let Ok(private_key) = env::var("PRIVATE_KEY") {
            // Use private key directly (for testing/development)
            info!("Using wallet from private key environment variable");
            warn!("Using private key from environment variable is insecure - only use for testing");
            let wallet = Self::load_wallet_from_private_key(&private_key)?;
            
            WalletProvider::LocalKey(Arc::new(RwLock::new(LocalSignerWallet {
                wallet,
                keystore_path: "direct-private-key".to_string(),
            })))
        } else if let Ok(keystore_path) = env::var("KEYSTORE_PATH") {
            // Use local key wallet
            info!("Using local keystore wallet from {}", keystore_path);
            let password = Self::get_keystore_password()?;
            let wallet = Self::load_wallet_from_keystore(&keystore_path, &password).await?;
            
            WalletProvider::LocalKey(Arc::new(RwLock::new(LocalSignerWallet {
                wallet,
                keystore_path,
            })))
        } else if let Ok(device_path) = env::var("HARDWARE_WALLET_PATH") {
            // Hardware wallet not fully implemented yet
            warn!("Hardware wallet support is not fully implemented");
            return Err(AgentError::WalletError("Hardware wallet not implemented".to_string()));
        } else {
            // No wallet configuration found
            return Err(AgentError::WalletError("No wallet configuration found".to_string()));
        };
        
        Ok(Self {
            wallet_provider,
            chain_id,
            transaction_limits,
        })
    }
    
    /// Get the wallet address
    pub async fn get_address(&self) -> AgentResult<Address> {
        match &self.wallet_provider {
            WalletProvider::LocalKey(wallet) => {
                let wallet_guard = wallet.read().await;
                Ok(wallet_guard.wallet.address())
            },
            WalletProvider::HardwareWallet(wallet) => {
                let wallet_guard = wallet.read().await;
                Ok(wallet_guard.address)
            }
        }
    }
    
    /// Sign a transaction
    pub async fn sign_transaction(&self, tx: &TransactionRequest) -> AgentResult<Bytes> {
        // Check transaction against limits
        self.validate_transaction(tx).await?;
        
        match &self.wallet_provider {
            WalletProvider::LocalKey(wallet) => {
                let wallet_guard = wallet.read().await;
                // Convert to TypedTransaction
                let typed_tx: TypedTransaction = tx.clone().into();
                
                let signature = wallet_guard.wallet
                    .sign_transaction(&typed_tx)
                    .await
                    .map_err(|e| AgentError::WalletError(format!("Failed to sign transaction: {}", e)))?;
                
                // Convert signature to Bytes
                let signature_bytes = signature.to_vec().into();
                Ok(signature_bytes)
            },
            WalletProvider::HardwareWallet(_) => {
                Err(AgentError::WalletError("Hardware wallet signing not implemented".to_string()))
            }
        }
    }
    
    /// Create a transaction with proper nonce and gas settings
    pub async fn create_transaction<T: Into<NameOrAddress>>(
        &self,
        to: T,
        value: U256,
        data: Bytes,
        provider: Arc<Provider<Http>>,
    ) -> AgentResult<TransactionRequest> {
        let from = self.get_address().await?;
        let nonce = provider.get_transaction_count(from, None)
            .await
            .map_err(|e| AgentError::RpcError(format!("Failed to get nonce: {}", e)))?;
        
        let gas_price = provider.get_gas_price()
            .await
            .map_err(|e| AgentError::RpcError(format!("Failed to get gas price: {}", e)))?;
        
        // Ensure gas price is within limits
        let max_gas_price = U256::from((self.transaction_limits.max_gas_price_gwei * 1e9) as u64);
        let gas_price = if gas_price > max_gas_price {
            warn!("Gas price {} exceeds maximum {}, capping", gas_price, max_gas_price);
            max_gas_price
        } else {
            gas_price
        };
        
        let tx = TransactionRequest::new()
            .from(from)
            .to(to)
            .value(value)
            .data(data)
            .nonce(nonce)
            .gas_price(gas_price)
            .chain_id(self.chain_id);
        
        Ok(tx)
    }
    
    /// Validate a transaction against risk limits
    async fn validate_transaction(&self, tx: &TransactionRequest) -> AgentResult<()> {
        // Check if we've exceeded daily transaction limit
        if self.transaction_limits.current_daily_transactions >= self.transaction_limits.max_daily_transactions {
            return Err(AgentError::RiskLimitExceeded(
                format!("Daily transaction limit of {} reached", self.transaction_limits.max_daily_transactions)
            ));
        }
        
        // Check gas price if set
        if let Some(gas_price) = tx.gas_price {
            let max_gas_price = U256::from((self.transaction_limits.max_gas_price_gwei * 1e9) as u64);
            if gas_price > max_gas_price {
                return Err(AgentError::RiskLimitExceeded(
                    format!("Gas price {} exceeds maximum {}", gas_price, max_gas_price)
                ));
            }
        }
        
        // Check transaction value if set
        if let Some(value) = tx.value {
            // This is a simplification - would need oracle price in real implementation
            let eth_price_usd = 4000.0; // Example price
            let value_eth = ethers::utils::format_units(value, "ether")
                .map_err(|e| AgentError::WalletError(format!("Failed to format units: {}", e)))?
                .parse::<f64>()
                .map_err(|e| AgentError::WalletError(format!("Failed to parse value: {}", e)))?;
            
            let value_usd = value_eth * eth_price_usd;
            
            if value_usd > self.transaction_limits.max_transaction_amount_usd {
                return Err(AgentError::RiskLimitExceeded(
                    format!("Transaction value ${} exceeds maximum ${}", 
                        value_usd, self.transaction_limits.max_transaction_amount_usd)
                ));
            }
        }
        
        Ok(())
    }
    
    /// Increment the daily transaction counter
    pub async fn record_transaction(&mut self) -> AgentResult<()> {
        self.transaction_limits.current_daily_transactions += 1;
        self.save_transaction_limits()?;
        Ok(())
    }
    
    /// Reset daily transaction counter (would be called by a daily scheduled job)
    pub async fn reset_daily_counters(&mut self) -> AgentResult<()> {
        self.transaction_limits.current_daily_transactions = 0;
        self.save_transaction_limits()?;
        Ok(())
    }
    
    /// Load a wallet from keystore file
    async fn load_wallet_from_keystore(path: &str, password: &str) -> AgentResult<LocalWallet> {
        let keystore = fs::read_to_string(path)
            .map_err(|e| AgentError::WalletError(format!("Failed to read keystore file: {}", e)))?;
        
        let wallet = LocalWallet::decrypt_keystore(&keystore, password)
            .map_err(|e| AgentError::WalletError(format!("Failed to decrypt keystore: {}", e)))?
            .with_chain_id(43114u64); // Avalanche C-Chain
        
        info!("Loaded wallet with address: {}", wallet.address());
        Ok(wallet)
    }
    
    /// Load a wallet directly from a private key
    fn load_wallet_from_private_key(private_key: &str) -> AgentResult<LocalWallet> {
        // Remove 0x prefix if present
        let private_key = private_key.trim_start_matches("0x");
        
        // Parse the private key
        let private_key_bytes = hex::decode(private_key)
            .map_err(|e| AgentError::WalletError(format!("Failed to decode private key: {}", e)))?;
        
        // Create wallet from private key
        let wallet = LocalWallet::from_bytes(&private_key_bytes)
            .map_err(|e| AgentError::WalletError(format!("Failed to create wallet from private key: {}", e)))?
            .with_chain_id(43114u64); // Avalanche C-Chain
        
        info!("Loaded wallet with address: {}", wallet.address());
        Ok(wallet)
    }
    
    /// Get keystore password from environment or prompt
    fn get_keystore_password() -> AgentResult<String> {
        if let Ok(password) = env::var("KEYSTORE_PASSWORD") {
            warn!("Using keystore password from environment variable is insecure");
            Ok(password)
        } else {
            // In a real implementation, this would securely prompt the user
            // or use a secure password manager or hardware security module
            error!("No keystore password provided");
            Err(AgentError::WalletError("No keystore password provided".to_string()))
        }
    }
    
    /// Load transaction limits from config file or use defaults
    fn load_transaction_limits() -> AgentResult<TransactionLimits> {
        let config_path = env::var("CONFIG_DIR")
            .unwrap_or_else(|_| ".".to_string()) 
            + "/transaction_limits.json";
        
        if Path::new(&config_path).exists() {
            let config_str = fs::read_to_string(&config_path)
                .map_err(|e| AgentError::ConfigError(format!("Failed to read config: {}", e)))?;
            
            let limits: TransactionLimits = serde_json::from_str(&config_str)
                .map_err(|e| AgentError::ConfigError(format!("Failed to parse config: {}", e)))?;
            
            info!("Loaded transaction limits from {}", config_path);
            Ok(limits)
        } else {
            // Use default limits
            info!("Using default transaction limits");
            Ok(TransactionLimits {
                max_transaction_amount_usd: 1000.0, // $1000 max per transaction
                max_gas_price_gwei: 300.0,          // 300 GWEI max gas price
                max_daily_transactions: 100,        // 100 transactions per day
                current_daily_transactions: 0,      // Start with 0 for today
            })
        }
    }
    
    /// Save transaction limits to config file
    fn save_transaction_limits(&self) -> AgentResult<()> {
        let config_path = env::var("CONFIG_DIR")
            .unwrap_or_else(|_| ".".to_string()) 
            + "/transaction_limits.json";
        
        let config_str = serde_json::to_string_pretty(&self.transaction_limits)
            .map_err(|e| AgentError::ConfigError(format!("Failed to serialize config: {}", e)))?;
        
        fs::write(&config_path, config_str)
            .map_err(|e| AgentError::ConfigError(format!("Failed to write config: {}", e)))?;
        
        Ok(())
    }
}
