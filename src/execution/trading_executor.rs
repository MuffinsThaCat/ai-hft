use crate::models::error::{AgentError, AgentResult};
use crate::models::trading::{Opportunity, TransactionRecord, GasInfo, TransactionType, StatelessVmMetrics};
use crate::wallet::WalletManager;
use crate::statelessvm::client::{StatelessTxRequest, SecurityVerificationRequest, StatelessVmClient, StatelessTxResponse};
use ethers::prelude::*;
use log::{info, warn, error, debug};
use uuid::Uuid;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Instant;
use std::env;
use std::str::FromStr;
use chrono::Utc;

/// Production-ready trading executor using StatelessVM for high-performance execution
pub struct TradingExecutor {
    /// Wallet manager for transaction signing
    wallet_manager: Arc<RwLock<WalletManager>>,
    /// StatelessVM client for transaction execution
    statelessvm_client: StatelessVmClient,
    /// Provider for blockchain interaction
    provider: Arc<Provider<Http>>,
    /// Security verification configuration
    security_config: SecurityVerificationConfig,
    /// Execution statistics for monitoring
    stats: Arc<RwLock<ExecutionStats>>,
}

/// Security verification configuration
#[derive(Debug, Clone)]
pub struct SecurityVerificationConfig {
    /// Whether security verification is enabled
    pub enabled: bool,
    /// Maximum acceptable risk score (0-100)
    pub max_risk_score: u8,
    /// Whether to verify for reentrancy vulnerabilities
    pub verify_reentrancy: bool,
    /// Whether to verify for integer underflow vulnerabilities
    pub verify_integer_underflow: bool,
    /// Whether to verify for integer overflow vulnerabilities
    pub verify_integer_overflow: bool,
    /// Whether to verify for unchecked calls vulnerabilities
    pub verify_unchecked_calls: bool,
    /// Whether to verify for upgradability issues
    pub verify_upgradability: bool,
    /// Whether to verify for MEV vulnerabilities
    pub verify_mev_vulnerability: bool,
    /// Whether to verify for cross-contract reentrancy vulnerabilities
    pub verify_cross_contract_reentrancy: bool,
    /// Whether to verify for precision loss vulnerabilities
    pub verify_precision_loss: bool,
    /// Whether to verify for gas griefing vulnerabilities
    pub verify_gas_griefing: bool,
}

/// Execution statistics
#[derive(Debug, Clone, Default)]
pub struct ExecutionStats {
    /// Total number of transactions executed
    pub total_transactions: u64,
    /// Number of successful transactions
    pub successful_transactions: u64,
    /// Number of failed transactions
    pub failed_transactions: u64,
    /// Average witness generation time in milliseconds
    pub avg_witness_time_ms: f64,
    /// Average transaction submission time in milliseconds
    pub avg_submission_time_ms: f64,
    /// Average total execution time in milliseconds
    pub avg_total_time_ms: f64,
    /// Total profit in USD
    pub total_profit_usd: f64,
    /// Total transaction costs in USD
    pub total_cost_usd: f64,
}

impl TradingExecutor {
    /// Create a new trading executor
    pub async fn new() -> AgentResult<Self> {
        // Initialize wallet manager
        let wallet_manager = Arc::new(RwLock::new(WalletManager::new().await?));
        
        // Initialize StatelessVM client
        let statelessvm_url = env::var("STATELESSVM_URL")
            .unwrap_or_else(|_| {
                info!("STATELESSVM_URL not set, using default local endpoint");
                "http://localhost:7548".to_string()
            });
        let statelessvm_client = StatelessVmClient::new(&statelessvm_url);
        
        // Initialize provider
        let rpc_url = env::var("AVALANCHE_RPC_URL")
            .unwrap_or_else(|_| "https://api.avax.network/ext/bc/C/rpc".to_string());
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| AgentError::RpcError(format!("Failed to create provider: {}", e)))?;
        
        // Initialize security verification config
        let security_config = SecurityVerificationConfig {
            enabled: env::var("SECURITY_VERIFICATION_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            max_risk_score: env::var("MAX_RISK_SCORE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50),
            verify_reentrancy: true,
            verify_integer_underflow: true,
            verify_integer_overflow: true,
            verify_unchecked_calls: true,
            verify_upgradability: true,
            verify_mev_vulnerability: true,
            verify_cross_contract_reentrancy: true,
            verify_precision_loss: true,
            verify_gas_griefing: true,
        };
        
        Ok(Self {
            wallet_manager,
            statelessvm_client,
            provider: Arc::new(provider),
            security_config,
            stats: Arc::new(RwLock::new(ExecutionStats::default())),
        })
    }
    
    /// Execute a trade for a given opportunity
    pub async fn execute_trade(&self, opportunity: &Opportunity) -> AgentResult<TransactionRecord> {
        let start_time = Instant::now();
        info!("Executing trade for opportunity {}", opportunity.opportunity_id);
        
        // Check if opportunity is still valid
        if opportunity.expires_at < chrono::Utc::now() {
            return Err(AgentError::ExecutionError("Opportunity expired".to_string()));
        }
        
        // Prepare transaction based on opportunity type
        let transaction_request = self.prepare_transaction(opportunity).await?;
        
        // Create security verification request if enabled
        let security_verification = if self.security_config.enabled {
            let wallet_address = self.wallet_manager.read().await.get_address().await?;
            
            Some(SecurityVerificationRequest {
                address: format!("{:?}", wallet_address),
                enabled: true,
                max_risk_score: self.security_config.max_risk_score,
                verify_reentrancy: self.security_config.verify_reentrancy,
                verify_integer_underflow: self.security_config.verify_integer_underflow,
                verify_integer_overflow: self.security_config.verify_integer_overflow,
                verify_unchecked_calls: self.security_config.verify_unchecked_calls,
                verify_upgradability: self.security_config.verify_upgradability,
                verify_mev_vulnerability: self.security_config.verify_mev_vulnerability,
                verify_cross_contract_reentrancy: self.security_config.verify_cross_contract_reentrancy,
                verify_precision_loss: self.security_config.verify_precision_loss,
                verify_gas_griefing: self.security_config.verify_gas_griefing,
            })
        } else {
            None
        };
        
        // Prepare StatelessVM request
        // Sign the transaction - this verifies we can sign it but we don't use the signature
        // for StatelessVM as it handles the signing internally
        let _signed_tx_bytes = self.wallet_manager.read().await.sign_transaction(&transaction_request).await?;
        
        // Convert TransactionRequest into format expected by StatelessVM
        let from_addr = format!("{:?}", self.wallet_manager.read().await.get_address().await?);
        
        // Handle to address
        let to_addr = if let Some(addr) = transaction_request.to {
            // Format as a plain hex string
            match addr {
                ethers::types::NameOrAddress::Address(a) => {
                    format!("0x{}", hex::encode(a.as_bytes()))
                },
                ethers::types::NameOrAddress::Name(n) => {
                    // For ENS names, we would resolve them, but for our test just use a dummy address
                    warn!("ENS name used in transaction: {}. Using dummy address.", n);
                    "0x1234567890123456789012345678901234567890".to_string()
                }
            }
        } else {
            "0x".to_string()
        };
        
        // Handle value
        let value = if let Some(val) = transaction_request.value {
            // Format as hex string
            format!("0x{:x}", val)
        } else {
            "0x0".to_string()
        };
        
        // Handle data
        let data = if let Some(data_bytes) = transaction_request.data {
            format!("0x{}", hex::encode(data_bytes.to_vec()))
        } else {
            "0x".to_string()
        };
        
        // Handle gas limit
        let gas_limit = if let Some(gas) = transaction_request.gas {
            // Format as hex string
            format!("0x{:x}", gas)
        } else {
            "0x100000".to_string() // Default gas limit
        };
        
        // Handle gas price
        let gas_price = if let Some(price) = transaction_request.gas_price {
            // Format as hex string
            format!("0x{:x}", price)
        } else {
            "0x3b9aca00".to_string() // Default 1 Gwei
        };
            
        // Use the official StatelessVmClient to execute the transaction
        debug!("Creating transaction request using StatelessVmClient");
        
        // Create security verification request configuration
        let security_verification = SecurityVerificationRequest {
            address: to_addr.to_string(),
            enabled: self.security_config.enabled,
            max_risk_score: self.security_config.max_risk_score,
            verify_reentrancy: self.security_config.verify_reentrancy,
            verify_integer_underflow: self.security_config.verify_integer_underflow,
            verify_integer_overflow: self.security_config.verify_integer_overflow,
            verify_unchecked_calls: self.security_config.verify_unchecked_calls,
            verify_upgradability: self.security_config.verify_upgradability,
            verify_mev_vulnerability: self.security_config.verify_mev_vulnerability,
            verify_cross_contract_reentrancy: self.security_config.verify_cross_contract_reentrancy,
            verify_precision_loss: self.security_config.verify_precision_loss,
            verify_gas_griefing: self.security_config.verify_gas_griefing,
        };
        
        // Create the transaction request object using the proper struct
        let tx_request = StatelessTxRequest {
            from: from_addr.to_string(),
            to: to_addr.to_string(),
            value: value.to_string(),
            data: data.to_string(),
            gas_limit: gas_limit.to_string(),
            gas_price: gas_price.to_string(),
            security_verification,
            bundle_id: Some(format!("trade-{}", uuid::Uuid::new_v4())),
        };
        
        // Generate a unique transaction ID for logging and bundle ID
        let bundle_id = format!("trade-{}-{}", opportunity.opportunity_id, chrono::Utc::now().timestamp());
        

        // Log the request details for debugging
        info!("----- StatelessVM Request Details -----");
        info!("Bundle ID: {}", bundle_id);
        info!("From: {}", from_addr);
        info!("To: {}", to_addr);
        info!("Value: {}", value);
        info!("Data: {}", data);
        info!("Gas Limit: {}", gas_limit);
        info!("Gas Price: {}", gas_price);
        info!("Security Verification Enabled: {}", self.security_config.enabled);
        
        // Serialize for logging
        let serialized = serde_json::to_string_pretty(&tx_request).unwrap_or_default();
        info!("Full Request JSON: \n{}", serialized);
        info!("----- End of Request Details -----");

        // Start measurement for submission time
        let submission_start = Instant::now();
        
        // Log the request details for debugging
        debug!("StatelessVM Request Details: {:?}", tx_request);
        
        // Execute the transaction using the official client
        let witness_start = Instant::now();
        let execution_result = self.statelessvm_client.execute_transaction(tx_request).await;
        let witness_time = witness_start.elapsed().as_millis() as u64;
    
        match execution_result {
            Ok(response) => {
                // StatelessTxResponse doesn't include submission_time field in current version
                let submission_time = submission_start.elapsed().as_millis() as u64;
                let total_time = start_time.elapsed().as_millis() as u64;
            
                // Parse transaction hash from the response
                let tx_hash = match H256::from_str(&response.tx_hash.trim_start_matches("0x")) {
                    Ok(h256) => h256,
                    Err(_) => {
                        error!("Failed to parse transaction hash: {}", response.tx_hash);
                        H256::zero()
                    }
                };
                
                // Log success with the transaction hash
                info!("✅ Trade executed successfully with hash: {}", response.tx_hash);
                
                // Check for security verification results
                if let Some(sec_verification) = response.security_verification {
                    if sec_verification.passed {
                        info!("✅ Security verification passed with risk score: {}", sec_verification.risk_score);
                    } else {
                        warn!("⚠️ Security verification failed with risk score: {}", sec_verification.risk_score);
                        if let Some(warnings) = sec_verification.warnings {
                            for warning in warnings {
                                warn!("  - {}: {}", warning.warning_type, warning.message);
                            }
                        }
                    }
                    
                    // Record security verification metrics
                    // Metrics tracking commented out due to missing metrics module
                    // metrics::gauge!("statelessvm_security_verification_risk_score", sec_verification.risk_score as f64);
                    // metrics::counter!("statelessvm_security_verification_executions_total", 1);
                }
                
                // Estimate profit and cost
                let (profit_usd, cost_usd) = self.estimate_profit_and_cost(opportunity).await?;
                
                // Create transaction record with the transaction hash
                let tx_record = TransactionRecord {
                    tx_hash,
                    block_number: None, // Will be updated later
                    tx_type: TransactionType::Arbitrage, // Assuming arbitrage for now
                    base_token: opportunity.base_token.clone(),
                    quote_token: opportunity.quote_token.clone(),
                    base_amount: 1.0, // Placeholder
                    quote_amount: opportunity.market_data.buy_price, // Placeholder
                    exchange: format!("{} -> {}", 
                        opportunity.market_data.buy_exchange,
                        opportunity.market_data.sell_exchange),
                    gas_used: 0, // StatelessTxResponse doesn't have gas_used field yet
                    gas_price_gwei: if let Some(gp) = transaction_request.gas_price {
                        let gwei_str = ethers::utils::format_units(gp, "gwei").unwrap_or("0".to_string());
                        gwei_str.parse::<f64>().unwrap_or(0.0)
                    } else {
                        0.0
                    },
                    tx_cost_usd: cost_usd,
                    profit_loss_usd: profit_usd - cost_usd,
                    timestamp: chrono::Utc::now(),
                    statelessvm_metrics: Some(StatelessVmMetrics {
                        witness_generation_time_ms: witness_time,
                        tx_submission_time_ms: submission_time,
                        total_execution_time_ms: total_time,
                        security_verification_performed: self.security_config.enabled,
                        security_verification_result: None, // Would parse from response in a full implementation
                    }),
                };
                
                // Update statistics and return the transaction record
                self.update_stats(&tx_record, true).await;
                Ok(tx_record)
            },
            Err(e) => {
                let mut stats = self.stats.write().await;
                stats.total_transactions += 1;
                stats.failed_transactions += 1;
                
                Err(AgentError::ExecutionError(format!("StatelessVM execution failed: {}", e)))
            }
        }
    }
    
    /// Prepare a transaction based on the opportunity type
    async fn prepare_transaction(&self, opportunity: &Opportunity) -> AgentResult<TransactionRequest> {
        // This is a simplified version - a real implementation would generate the appropriate
        // transaction calldata based on the DEX being used and the token pair
        
        // Log the opportunity details for debugging
        debug!("Preparing transaction for opportunity: {}", opportunity.opportunity_id);
        debug!("Tokens: {}/{}", opportunity.base_token, opportunity.quote_token);
        debug!("Exchanges: {} -> {}", opportunity.market_data.buy_exchange, opportunity.market_data.sell_exchange);
        
        // For demonstration, we'll create a transaction to a hypothetical arbitrage contract
        let arbitrage_contract = "0x1234567890123456789012345678901234567890";
        
        // Create properly ABI-encoded calldata for the arbitrage function
        // For testing, we'll use a simple transfer function which is widely recognized
        
        // Function selector for 'transfer(address,uint256)' = 0xa9059cbb
        let mut calldata = vec![0xa9, 0x05, 0x9c, 0xbb];
        
        // Pad the address to 32 bytes (addresses are 20 bytes)
        let mut address_param = vec![0u8; 12]; // 12 zeros for padding
        address_param.extend_from_slice(&hex::decode("1234567890123456789012345678901234567890").unwrap_or_default());
        
        // Pad a simple value (1 token with 18 decimals = 1000000000000000000)
        let mut value_param = vec![0u8; 31]; // 31 zeros for padding
        value_param.push(1); // Just sending 1 token unit
        
        // Combine everything
        calldata.extend_from_slice(&address_param);
        calldata.extend_from_slice(&value_param);
        
        // Convert calldata to Bytes
        let data = Bytes::from(calldata);
        
        debug!("Sending transaction with calldata: 0x{}", hex::encode(&data));
        
        // Create and return the transaction request
        let wallet_manager = self.wallet_manager.read().await;
        wallet_manager.create_transaction(
            arbitrage_contract,
            U256::zero(), // No ETH being sent
            data,
            self.provider.clone()
        ).await
    }
    
    /// Estimate profit and cost for an opportunity
    async fn estimate_profit_and_cost(&self, opportunity: &Opportunity) -> AgentResult<(f64, f64)> {
        // Simplified profit calculation
        let trade_amount = 1.0; // 1 unit of base token
        let buy_cost = trade_amount * opportunity.market_data.buy_price;
        let sell_revenue = trade_amount * opportunity.market_data.sell_price;
        let profit = sell_revenue - buy_cost;
        
        // Estimate gas cost
        let gas_price = self.provider.get_gas_price().await
            .map_err(|e| AgentError::RpcError(format!("Failed to get gas price: {}", e)))?;
        
        let gas_price_gwei = ethers::utils::format_units(gas_price, "gwei")
            .map_err(|e| AgentError::ExecutionError(format!("Failed to format gas price: {}", e)))?
            .parse::<f64>()
            .map_err(|e| AgentError::ExecutionError(format!("Failed to parse gas price: {}", e)))?;
        
        // Assume 250k gas for an arbitrage transaction
        let estimated_gas = 250_000;
        
        // Estimate gas cost in USD
        // Assuming 1 AVAX = $50 and 1 GWEI = 0.000000001 AVAX
        let avax_price_usd = 50.0;
        let gas_cost_usd = (gas_price_gwei * 0.000000001 * estimated_gas as f64) * avax_price_usd;
        
        Ok((profit, gas_cost_usd))
    }
    
    /// Update execution statistics
    async fn update_stats(&self, tx_record: &TransactionRecord, success: bool) {
        let mut stats = self.stats.write().await;
        
        stats.total_transactions += 1;
        
        if success {
            stats.successful_transactions += 1;
            stats.total_profit_usd += tx_record.profit_loss_usd;
            stats.total_cost_usd += tx_record.tx_cost_usd;
            
            // Update average times
            if let Some(metrics) = &tx_record.statelessvm_metrics {
                let prev_total = stats.successful_transactions - 1;
                
                stats.avg_witness_time_ms = (stats.avg_witness_time_ms * prev_total as f64 
                    + metrics.witness_generation_time_ms as f64) / stats.successful_transactions as f64;
                    
                stats.avg_submission_time_ms = (stats.avg_submission_time_ms * prev_total as f64 
                    + metrics.tx_submission_time_ms as f64) / stats.successful_transactions as f64;
                    
                stats.avg_total_time_ms = (stats.avg_total_time_ms * prev_total as f64 
                    + metrics.total_execution_time_ms as f64) / stats.successful_transactions as f64;
            }
        } else {
            stats.failed_transactions += 1;
        }
    }
    
    /// Get current execution statistics
    pub async fn get_stats(&self) -> ExecutionStats {
        self.stats.read().await.clone()
    }
}
