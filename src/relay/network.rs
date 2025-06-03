use crate::relay::types::*;
use crate::relay::encryption::EncryptionService;
use crate::relay::bundle::BundleManager;
use crate::relay::validator::ValidatorConnection;
use crate::relay::metrics::RelayMetrics;
use crate::security::verifier::SecurityVerification;
use crate::security::{VulnerabilityType, Severity};
use ethers::types::{Transaction, H256, U256};
use ethers::providers::Middleware;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use log::{info, warn, error, debug};
use uuid::Uuid;
use rand::{thread_rng, Rng};

/// RelayNode represents a single node in the private transaction relay network
#[derive(Clone)]
pub struct RelayNode {
    /// Unique identifier for this relay node
    node_id: String,
    /// Geographic region where this node is located
    region: Region,
    /// Active connections to validators
    connections: Arc<RwLock<HashMap<String, Arc<ValidatorConnection>>>>,
    /// Performance metrics for this node
    metrics: Arc<Mutex<RelayMetrics>>,
    /// Configuration for this relay node
    config: RelayConfig,
    /// Encryption service for transaction privacy
    encryption: Arc<EncryptionService>,
    /// Bundle manager for transaction bundling
    bundle_manager: Arc<BundleManager>,
}

impl std::fmt::Debug for RelayNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayNode")
            .field("node_id", &self.node_id)
            .field("region", &self.region)
            .field("config", &self.config)
            .field("connections", &format!("Arc<RwLock<HashMap<String, Arc<ValidatorConnection>>>>({} connections)", 
                   self.connections.try_read().map(|c| c.len()).unwrap_or(0)))
            .field("metrics", &"Arc<Mutex<RelayMetrics>>")
            .field("encryption", &"Arc<EncryptionService>")
            .field("bundle_manager", &"Arc<BundleManager>")
            .finish()
    }
}

impl RelayNode {
    /// Create a new relay node with the given configuration
    pub async fn new(config: RelayConfig) -> Result<Self, RelayError> {
        let metrics = Arc::new(Mutex::new(RelayMetrics::new()));
        let encryption = Arc::new(EncryptionService::new(&config.encryption_key)?);
        let bundle_manager = Arc::new(BundleManager::new(config.max_bundle_size));
        let connections = Arc::new(RwLock::new(HashMap::new()));
        
        let node = Self {
            node_id: config.node_id.clone(),
            region: config.region.clone(),
            connections,
            metrics,
            config,
            encryption,
            bundle_manager,
        };
        
        // Initialize validator connections
        node.initialize_connections().await?;
        
        Ok(node)
    }
    
    /// Initialize connections to validators
    async fn initialize_connections(&self) -> Result<(), RelayError> {
        for endpoint in &self.config.validator_endpoints {
            let connection = ValidatorConnection::new(
                endpoint.clone(),
                self.metrics.clone(),
                self.encryption.clone(),
            ).await?;
            
            let mut connections = self.connections.write().await;
            connections.insert(endpoint.id.clone(), Arc::new(connection));
        }
        
        info!("Initialized {} validator connections", self.config.validator_endpoints.len());
        Ok(())
    }
    
    /// Submit a single transaction through the private relay
    pub async fn submit_transaction(
        &self,
        tx: &Transaction,
        mode: SubmissionMode,
        security_verification: Option<&SecurityVerification>,
    ) -> Result<SubmissionResult, RelayError> {
        let start_time = Instant::now();
        
        // Perform security verification if provided
        if let Some(verification_result) = security_verification {
            debug!("Performing security verification before submission");
            
            if !verification_result.is_safe() {
                // Check for specific vulnerability types based on the implementation in memories
                let mut critical_vulnerabilities = Vec::new();
                
                for vulnerability in verification_result {
                    match vulnerability.vulnerability_type {
                        VulnerabilityType::IntegerOverflow { .. } | 
                        VulnerabilityType::IntegerUnderflow { .. } | 
                        VulnerabilityType::MEV { .. } | 
                        VulnerabilityType::OracleManipulation { .. } | 
                        VulnerabilityType::GasGriefing { .. } | 
                        VulnerabilityType::CrossContractReentrancy { .. } => {
                            if vulnerability.severity == Severity::Critical || vulnerability.severity == Severity::High {
                                critical_vulnerabilities.push(vulnerability);
                            }
                        },
                        _ => {}
                    }
                }
                
                if !critical_vulnerabilities.is_empty() {
                    error!("Security verification failed: {} critical vulnerabilities detected", 
                           critical_vulnerabilities.len());
                    for vuln in critical_vulnerabilities.iter().take(3) { // Log first 3 only to avoid spamming
                        error!("- {:?} (Risk score: {})", vuln.vulnerability_type, vuln.risk_score);
                    }
                    return Err(format!("Transaction rejected due to {} security vulnerabilities", 
                                critical_vulnerabilities.len()).into());
                }
                
                warn!("Security verification detected non-critical vulnerabilities");
                debug!("{}", verification_result.get_vulnerability_summary());
            }
            
            debug!("Security verification passed or contained only low-severity issues");
        }
        
        match mode {
            SubmissionMode::Standard => {
                // Submit through standard mempool
                self.submit_standard_transaction(tx).await
            },
            SubmissionMode::Private => {
                // Submit only through private relay
                self.submit_private_transaction(tx).await
            },
            SubmissionMode::Hybrid(threshold) => {
                // Decide based on threshold
                let tx_value = tx.value;
                let threshold_wei = U256::from((threshold * 1e18) as u64); // Convert to wei
                
                if tx_value >= threshold_wei {
                    debug!("Transaction value {} exceeds hybrid threshold {}, using private relay", 
                           tx_value, threshold_wei);
                    self.submit_private_transaction(tx).await
                } else {
                    debug!("Transaction value {} below hybrid threshold {}, using standard mempool", 
                           tx_value, threshold_wei);
                    self.submit_standard_transaction(tx).await
                }
            }
        }
    }
    
    /// Submit a transaction via standard mempool using ethers to broadcast to the public network
    async fn submit_standard_transaction(&self, tx: &Transaction) -> Result<SubmissionResult, RelayError> {
        debug!("Submitting transaction to public mempool via ethers");
        
        // Record start time for metrics
        let start_time = Instant::now();
        
        // First check if we have any provider configuration in our validator connections
        // If not, we'll use a fallback public RPC endpoint
        let connections = self.connections.read().await;
        
        // Create a provider - we'll try to use the first connection's RPC URL if available
        // otherwise we'll use a fallback public node
        let provider = if let Some(connection) = connections.values().next() {
            let provider_url = connection.get_rpc_url().await?;
            ethers::providers::Provider::<ethers::providers::Http>::try_from(provider_url)
                .map_err(|e| format!("Failed to create provider: {}", e))?        
        } else {
            // Fallback to a public RPC if no connections are available
            // Note: In production, this should be configured from environment or config
            let fallback_url = "https://mainnet.infura.io/v3/your-infura-key";
            warn!("No validator connections available, using fallback RPC: {}", fallback_url);
            ethers::providers::Provider::<ethers::providers::Http>::try_from(fallback_url)
                .map_err(|e| format!("Failed to create fallback provider: {}", e))?
        };
        
        // Clone the transaction for submission
        // We need to ensure it's properly signed - this would be handled elsewhere
        // For now, we'll assume the transaction is already signed and ready to broadcast
        // Note: In ethers v2, v, r, s are always present but may be zero, so check if they're all non-zero
        if tx.v.is_zero() || tx.r.is_zero() || tx.s.is_zero() {
            return Err("Transaction is not signed and cannot be submitted to the mempool".into());
        }
        
        // Serialize the transaction to raw bytes using rlp
        // We need to create a signed transaction object that supports rlp encoding
        use ethers::utils::rlp::Encodable;
        use ethers::middleware::Middleware;
        
        // Create a signed transaction
        let signed_tx_bytes = tx.rlp();
        
        // Submit the raw transaction
        let pending_tx = match provider.send_raw_transaction(signed_tx_bytes).await {
            Ok(pending_tx) => pending_tx,
            Err(e) => return Err(format!("Failed to submit transaction to mempool: {}", e).into()),
        };
        
        // Extract the transaction hash from the pending transaction
        let tx_hash = pending_tx.tx_hash();
        
        debug!("Transaction submitted successfully with hash: {}", tx_hash);
        
        // Update metrics
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_transaction_submission(false, start_time.elapsed());
        }
        
        // Create and return submission result
        Ok(SubmissionResult {
            transaction_hash: Some(tx_hash),
            bundle_id: None,
            status: SubmissionStatus::Pending,
            block_number: None,
            gas_used: None,
            effective_gas_price: None,
        })
    }
    
    /// Submit a transaction via private relay
    async fn submit_private_transaction(&self, tx: &Transaction) -> Result<SubmissionResult, RelayError> {
        let start_time = Instant::now();
        debug!("Submitting transaction via private relay");
        
        // Encrypt the transaction
        let encrypted_tx = self.encryption.encrypt_transaction(tx)?;
        
        // Determine optimal validator(s) based on stake weight and performance
        let selected_validators = self.select_validators(1).await?;
        
        if selected_validators.is_empty() {
            return Err("No suitable validators available".into());
        }
        
        // Try each selected validator until one succeeds
        let mut last_error = None;
        
        for validator_id in selected_validators {
            let connections = self.connections.read().await;
            if let Some(connection) = connections.get(&validator_id) {
                match connection.submit_private(&encrypted_tx).await {
                    Ok(result) => {
                        // Update metrics
                        if let Ok(mut metrics) = self.metrics.lock() {
                            metrics.record_transaction_submission(true, start_time.elapsed());
                        }
                        
                        return Ok(result);
                    }
                    Err(e) => {
                        warn!("Failed to submit to validator {}: {}", validator_id, e);
                        last_error = Some(e);
                    }
                }
            }
        }
        
        // If we get here, all validators failed
        Err(last_error.unwrap_or_else(|| "All validators failed".into()))
    }
    
    /// Submit a bundle of transactions to be executed atomically
    pub async fn submit_bundle(
        &self,
        transactions: &[Transaction],
        miner_reward: Option<U256>,
    ) -> Result<SubmissionResult, RelayError> {
        debug!("Creating and submitting transaction bundle with {} transactions", transactions.len());
        
        // Create a new bundle
        let bundle_id = Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Encrypt each transaction in the bundle
        let mut encrypted_txs: Vec<EncryptedTransaction> = Vec::with_capacity(transactions.len());
        for tx in transactions {
            match self.encryption.encrypt_transaction(tx) {
                Ok(encrypted_tx) => {
                    encrypted_txs.push(encrypted_tx);
                },
                Err(e) => {
                    error!("Failed to encrypt transaction: {}", e);
                    return Err(format!("Transaction encryption failed: {}", e).into());
                }
            }
        }
        
        debug!("Successfully encrypted {} transactions for bundle {}", encrypted_txs.len(), bundle_id);
        
        let bundle = TransactionBundle {
            bundle_id: bundle_id.clone(),
            transactions: encrypted_txs,
            miner_reward,
            target_block: None,
            timestamps: BundleTimestamps {
                created_at: now,
                submitted_at: None,
                confirmed_at: None,
                expires_at: now + 120, // 2 minute expiration
            },
            status: BundleStatus::Created,
        };
        
        // Register bundle with manager
        self.bundle_manager.register_bundle(bundle).await?;
        
        // Select optimal validator for bundle submission
        let selected_validators = self.select_validators(3).await?;
        
        if selected_validators.is_empty() {
            return Err("No suitable validators available for bundle submission".into());
        }
        
        // Try each selected validator until one succeeds
        let mut last_error = None;
        
        for validator_id in selected_validators {
            let connections = self.connections.read().await;
            if let Some(connection) = connections.get(&validator_id) {
                match connection.submit_bundle(&bundle_id).await {
                    Ok(result) => {
                        // Update bundle status
                        self.bundle_manager.update_bundle_status(
                            &bundle_id, 
                            BundleStatus::Submitted,
                            Some(now),
                            None,
                        ).await?;
                        
                        return Ok(result);
                    }
                    Err(e) => {
                        warn!("Failed to submit bundle to validator {}: {}", validator_id, e);
                        last_error = Some(e);
                    }
                }
            }
        }
        
        // If we get here, all validators failed
        self.bundle_manager.update_bundle_status(
            &bundle_id, 
            BundleStatus::Failed("All validators failed".to_string()),
            None,
            None,
        ).await?;
        
        Err(last_error.unwrap_or_else(|| "All validators failed for bundle submission".into()))
    }
    
    /// Select optimal validators based on stake weight and performance metrics
    async fn select_validators(&self, count: usize) -> Result<Vec<String>, RelayError> {
        let connections = self.connections.read().await;
        
        if connections.is_empty() {
            return Err("No validator connections available".into());
        }
        
        // A simple selection algorithm based on priority and randomization
        // In a real implementation, this would be more sophisticated
        let mut validators: Vec<_> = connections.keys().cloned().collect();
        
        // Sort by priority (higher priority first)
        validators.sort_by(|a, b| {
            let a_priority = self.config.validator_endpoints
                .iter()
                .find(|e| e.id == *a)
                .map(|e| e.priority)
                .unwrap_or(0);
                
            let b_priority = self.config.validator_endpoints
                .iter()
                .find(|e| e.id == *b)
                .map(|e| e.priority)
                .unwrap_or(0);
                
            b_priority.cmp(&a_priority)
        });
        
        // Take the top 'count' validators with some randomization
        let mut rng = thread_rng();
        let mut selected = Vec::with_capacity(count);
        
        // Always include at least one high-priority validator if available
        if !validators.is_empty() {
            selected.push(validators.remove(0));
        }
        
        // Add remaining validators with some randomness
        while selected.len() < count && !validators.is_empty() {
            let idx = if validators.len() > 1 {
                rng.gen_range(0..validators.len())
            } else {
                0
            };
            
            selected.push(validators.remove(idx));
        }
        
        Ok(selected)
    }
    
    /// Get relay network statistics
    pub fn get_stats(&self) -> Result<RelayNetworkStats, RelayError> {
        if let Ok(metrics) = self.metrics.lock() {
            Ok(metrics.get_network_stats())
        } else {
            Err("Failed to get metrics lock".into())
        }
    }
}
