use crate::relay::types::*;
use ethers::types::{Transaction, H256, U256};
use reqwest::{Client, StatusCode};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};
use log::{info, warn, error, debug};
use std::time::Instant;
use serde_json::{json, Value};
use crate::relay::metrics::RelayMetrics;
use crate::relay::encryption::EncryptionService;

/// Connection to a specific Avalanche validator
pub struct ValidatorConnection {
    /// Validator endpoint configuration
    endpoint: ValidatorEndpoint,
    /// HTTP client for API requests
    client: Client,
    /// Performance metrics
    metrics: Arc<Mutex<RelayMetrics>>,
    /// Encryption service for secure communication
    encryption: Arc<EncryptionService>,
    /// Connection health status
    health: Arc<Mutex<ConnectionHealth>>,
}

/// Health status of validator connection
struct ConnectionHealth {
    last_success: Option<Instant>,
    last_failure: Option<Instant>,
    consecutive_failures: u32,
    average_latency_ms: u64,
    is_available: bool,
}

impl ConnectionHealth {
    fn new() -> Self {
        Self {
            last_success: None,
            last_failure: None,
            consecutive_failures: 0,
            average_latency_ms: 0,
            is_available: true,
        }
    }
}

impl ValidatorConnection {
    /// Create a new validator connection
    pub async fn new(
        endpoint: ValidatorEndpoint,
        metrics: Arc<Mutex<RelayMetrics>>,
        encryption: Arc<EncryptionService>,
    ) -> Result<Self, RelayError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
            
        let connection = Self {
            endpoint,
            client,
            metrics,
            encryption,
            health: Arc::new(Mutex::new(ConnectionHealth::new())),
        };
        
        // Check initial connection
        connection.check_health().await?;
        
        Ok(connection)
    }
    
    /// Check connection health
    async fn check_health(&self) -> Result<(), RelayError> {
        let start = Instant::now();
        
        match self.client
            .get(&format!("{}/ext/health", self.endpoint.endpoint))
            .send()
            .await
        {
            Ok(response) => {
                let elapsed = start.elapsed();
                let status = response.status();
                
                if status.is_success() {
                    if let Ok(mut health) = self.health.lock() {
                        health.last_success = Some(Instant::now());
                        health.consecutive_failures = 0;
                        health.is_available = true;
                        
                        // Update average latency (simple moving average)
                        let latency_ms = elapsed.as_millis() as u64;
                        if health.average_latency_ms == 0 {
                            health.average_latency_ms = latency_ms;
                        } else {
                            health.average_latency_ms = (health.average_latency_ms * 9 + latency_ms) / 10;
                        }
                    }
                    
                    debug!("Validator {} health check successful, latency: {:?}", 
                           self.endpoint.id, elapsed);
                    Ok(())
                } else {
                    self.record_failure();
                    Err(format!("Validator returned non-success status: {}", status).into())
                }
            },
            Err(e) => {
                self.record_failure();
                Err(format!("Failed to connect to validator {}: {}", self.endpoint.id, e).into())
            }
        }
    }
    
    /// Record a connection failure
    fn record_failure(&self) {
        if let Ok(mut health) = self.health.lock() {
            health.last_failure = Some(Instant::now());
            health.consecutive_failures += 1;
            
            // Mark as unavailable after 3 consecutive failures
            if health.consecutive_failures >= 3 {
                health.is_available = false;
                warn!("Validator {} marked as unavailable after {} consecutive failures", 
                      self.endpoint.id, health.consecutive_failures);
            }
        }
    }
    
    /// Submit a transaction through public mempool
    pub async fn submit_public(&self, tx: &Transaction) -> Result<SubmissionResult, RelayError> {
        debug!("Submitting transaction to public mempool via validator {}", self.endpoint.id);
        
        let start = Instant::now();
        
        // Convert transaction to RPC format
        let tx_data = self.format_transaction_for_rpc(tx)?;
        
        // Send RPC request
        let response = self.client
            .post(&self.endpoint.endpoint)
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "eth_sendRawTransaction",
                "params": [tx_data],
                "id": 1
            }))
            .send()
            .await?;
            
        let elapsed = start.elapsed();
        
        // Update metrics
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_validator_latency(&self.endpoint.id, elapsed);
        }
        
        if response.status().is_success() {
            let json: Value = response.json().await?;
            
            if let Some(error) = json.get("error") {
                let error_msg = error["message"].as_str().unwrap_or("Unknown error");
                return Err(format!("RPC error: {}", error_msg).into());
            }
            
            if let Some(result) = json.get("result") {
                if let Some(tx_hash) = result.as_str() {
                    let hash = H256::from_str(tx_hash).map_err(|e| format!("Invalid hash: {}", e))?;
                    
                    // Update metrics for successful submission
                    if let Ok(mut metrics) = self.metrics.lock() {
                        metrics.record_successful_submission(false);
                    }
                    
                    return Ok(SubmissionResult {
                        transaction_hash: Some(hash),
                        bundle_id: None,
                        status: SubmissionStatus::Pending,
                        block_number: None,
                        gas_used: None,
                        effective_gas_price: None,
                    });
                }
            }
            
            Err("Invalid RPC response format".into())
        } else {
            Err(format!("RPC request failed with status: {}", response.status()).into())
        }
    }
    
    /// Get the RPC URL for this validator connection
    pub async fn get_rpc_url(&self) -> Result<String, RelayError> {
        Ok(self.endpoint.endpoint.clone())
    }

    /// Submit an encrypted transaction through private channels
    pub async fn submit_private(&self, tx: &EncryptedTransaction) -> Result<SubmissionResult, RelayError> {
        debug!("Submitting private encrypted transaction to validator {}", self.endpoint.id);
        
        let start = Instant::now();
        
        // In a real implementation, this would use a secure channel to the validator
        // We're simulating it with a standard HTTP request
        
        // Prepare the request
        let request = json!({
            "jsonrpc": "2.0",
            "method": "private_sendTransaction",
            "params": [{
                "encrypted": base64::encode(&tx.encrypted_data),
                "metadata": {
                    "gasLimit": tx.public_metadata.gas_limit,
                    "gasPrice": tx.public_metadata.gas_price.to_string(),
                    "value": tx.public_metadata.value.to_string(),
                    "size": tx.public_metadata.size_bytes,
                    "expires": tx.public_metadata.expires_at
                }
            }],
            "id": 1
        });
        
        // Add authentication if available
        let mut req_builder = self.client.post(&self.endpoint.endpoint);
        if let Some(token) = &self.endpoint.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }
        
        // Send the request
        let response = req_builder
            .json(&request)
            .send()
            .await?;
            
        let elapsed = start.elapsed();
        
        // Update metrics
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_validator_latency(&self.endpoint.id, elapsed);
        }
        
        if response.status().is_success() {
            let json: Value = response.json().await?;
            
            if let Some(error) = json.get("error") {
                let error_msg = error["message"].as_str().unwrap_or("Unknown error");
                return Err(format!("Private submission error: {}", error_msg).into());
            }
            
            if let Some(result) = json.get("result") {
                if let Some(tx_hash) = result.as_str() {
                    let hash = H256::from_str(tx_hash).map_err(|e| format!("Invalid hash: {}", e))?;
                    
                    // Update metrics for successful submission
                    if let Ok(mut metrics) = self.metrics.lock() {
                        metrics.record_successful_submission(true);
                    }
                    
                    return Ok(SubmissionResult {
                        transaction_hash: Some(hash),
                        bundle_id: None,
                        status: SubmissionStatus::Pending,
                        block_number: None,
                        gas_used: None,
                        effective_gas_price: None,
                    });
                }
            }
            
            Err("Invalid private submission response format".into())
        } else {
            Err(format!("Private submission failed with status: {}", response.status()).into())
        }
    }
    
    /// Submit a bundle of transactions to be executed atomically
    pub async fn submit_bundle(&self, bundle_id: &str) -> Result<SubmissionResult, RelayError> {
        debug!("Submitting bundle {} to validator {}", bundle_id, self.endpoint.id);
        
        // In a real implementation, this would fetch the bundle from the bundle manager
        // and submit it through a secure channel to the validator
        
        // Simulate a successful submission
        Ok(SubmissionResult {
            transaction_hash: None,
            bundle_id: Some(bundle_id.to_string()),
            status: SubmissionStatus::Pending,
            block_number: None,
            gas_used: None,
            effective_gas_price: None,
        })
    }
    
    /// Format a transaction for RPC submission
    fn format_transaction_for_rpc(&self, tx: &Transaction) -> Result<String, RelayError> {
        // In a real implementation, this would serialize the transaction in RPC format
        // For now, we'll return a placeholder
        Ok("0x...".to_string())
    }
}
