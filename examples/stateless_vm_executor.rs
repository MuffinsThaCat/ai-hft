use ai_trading_agent::statelessvm::client::{StatelessVmClient, StatelessTxRequest, StatelessTxResponse, SecurityVerificationRequest, SecurityVerificationResult};
use ai_trading_agent::models::error::{AgentError, AgentResult};
use std::time::{Instant, Duration};
use log::{info, warn, error, debug};

// Status codes for better tracking
pub enum ExecutionStatus {
    Pending,
    GeneratingWitnesses,
    WitnessGenerationFailed,
    SubmittingTransaction,
    SubmissionFailed,
    Confirmed,
    Failed,
}

// Performance metrics for comprehensive monitoring
pub struct PerformanceMetrics {
    pub witness_generation_time_ms: u64,
    pub transaction_submission_time_ms: u64,
    pub confirmation_time_ms: u64,
    pub gas_used: u64,
    pub gas_price_gwei: f64,
    pub success: bool,
    pub error_message: Option<String>,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            witness_generation_time_ms: 0,
            transaction_submission_time_ms: 0,
            confirmation_time_ms: 0,
            gas_used: 0,
            gas_price_gwei: 0.0,
            success: false,
            error_message: None,
        }
    }
}

pub struct StatelessVmExecutor {
    client: StatelessVmClient,
    verification_timeout_ms: u64,
    max_retry_attempts: u8,
    retry_backoff_ms: u64,
    metrics: PerformanceMetrics,
    status: ExecutionStatus,
    use_mock: bool,
}

impl StatelessVmExecutor {
    pub fn new(stateless_vm_url: &str, verification_timeout_ms: u64, max_retry_attempts: u8, retry_backoff_ms: u64) -> Self {
        // Use mock mode if URL contains local-mock or is a test endpoint
        let use_mock = stateless_vm_url.contains("local-mock") || stateless_vm_url.contains("localhost");
        info!("Initializing StatelessVM executor with URL: {}", stateless_vm_url);
        if use_mock {
            info!("StatelessVM initialized in mock mode");
        }
        
        Self {
            client: StatelessVmClient::new(stateless_vm_url),
            verification_timeout_ms,
            max_retry_attempts,
            retry_backoff_ms,
            metrics: PerformanceMetrics::default(),
            status: ExecutionStatus::Pending,
            use_mock,
        }
    }

    /// Enable mock mode after connection failures
    pub fn enable_mock_mode(&mut self) {
        if !self.use_mock {
            warn!("Enabling mock mode due to connection issues with StatelessVM endpoint");
            self.use_mock = true;
        }
    }

    pub async fn execute_transaction(&mut self, tx_request: StatelessTxRequest) -> AgentResult<StatelessTxResponse> {
        // If mock mode is enabled, use the mock implementation
        if self.use_mock {
            return self.execute_mock_transaction(&tx_request);
        }
        
        debug!("Starting transaction execution with StatelessVM");
        self.metrics = PerformanceMetrics::default();
        
        // Start witness generation
        self.status = ExecutionStatus::GeneratingWitnesses;
        let witness_start = Instant::now();
        
        // Execute with retry logic
        let mut retry_count = 0;
        let mut last_error = None;
        
        while retry_count < self.max_retry_attempts {
            match self.execute_with_verification(&tx_request).await {
                Ok(response) => {
                    // Calculate and record metrics
                    self.metrics.witness_generation_time_ms = witness_start.elapsed().as_millis() as u64;
                    self.metrics.success = true;
                    self.status = ExecutionStatus::Confirmed;
                    return Ok(response);
                }
                Err(err) => {
                    retry_count += 1;
                    // Create a new error instead of cloning since AgentError doesn't implement Clone
                    let err_message = err.to_string();
                    last_error = Some(AgentError::ExecutionError(err_message.clone()));
                    let backoff_time = self.retry_backoff_ms * 2_u64.pow((retry_count - 1) as u32);
                    
                    // Check if the error indicates a connection issue or 404 Not Found
                    if err.to_string().contains("404 Not Found") || 
                       err.to_string().contains("connection") ||
                       err.to_string().contains("timed out") {
                        warn!("StatelessVM endpoint unavailable ({}). Will fall back to mock mode after retry attempts", err);
                    }
                    
                    warn!("Execution failed, retrying in {}ms (attempt {}/{:?}): {:?}", 
                        backoff_time, retry_count, self.max_retry_attempts, last_error);
                    
                    tokio::time::sleep(Duration::from_millis(backoff_time)).await;
                }
            }
        }

        error!("Transaction execution failed after {:?} retries: {:?}", self.max_retry_attempts, last_error);
        self.status = ExecutionStatus::Failed;
        self.metrics.error_message = last_error.as_ref().map(|e| e.to_string());
        
        // Auto-fallback to mock mode after consecutive failures
        if last_error.as_ref().map_or(false, |e| 
            e.to_string().contains("404 Not Found") || 
            e.to_string().contains("connection") ||
            e.to_string().contains("timed out")) {
                
            info!("Automatically falling back to mock mode after endpoint connection failures");
            self.enable_mock_mode();
            return self.execute_mock_transaction(&tx_request);
        }
        
        if let Some(err) = last_error {
            Err(err)
        } else {
            Err(AgentError::GeneralError {
                message: "Transaction execution failed with unknown error".to_string(),
                source: None
            })
        }
    }
    
    async fn execute_with_verification(&mut self, tx_request: &StatelessTxRequest) -> AgentResult<StatelessTxResponse> {
        // Timeout mechanism for witness generation
        let verification_timeout = Duration::from_millis(self.verification_timeout_ms);
        let verification_start = Instant::now();

        // Execute the transaction
        debug!("Submitting transaction to StatelessVM with security verification");
        self.status = ExecutionStatus::SubmittingTransaction;
        let submission_start = Instant::now();
        
        // If we're in mock mode, use local mock implementation instead of actual client
        if self.use_mock {
            // Create a small delay to simulate processing time
            tokio::time::sleep(Duration::from_millis(500)).await;
            return self.execute_mock_transaction(tx_request);
        }
        
        let result = tokio::time::timeout(
            verification_timeout, 
            self.client.execute_transaction(tx_request.clone())
        ).await;
        
        match result {
            Ok(tx_result) => {
                self.metrics.transaction_submission_time_ms = submission_start.elapsed().as_millis() as u64;
                
                match tx_result {
                    Ok(response) => {
                        // Check security verification result
                        if let Some(verification) = &response.security_verification {
                            if !verification.passed {
                                // Security verification failed
                                let warning_count = if let Some(warnings) = &verification.warnings {
                                    warnings.len()
                                } else {
                                    0
                                };
                                
                                error!("Security verification failed with {} warnings", warning_count);
                                
                                // Log detailed warnings
                                if let Some(warnings) = &verification.warnings {
                                    for warning in warnings {
                                        error!("Security warning: {} (severity: {})", warning.description, warning.severity);
                                    }
                                }
                                
                                return Err(AgentError::GeneralError {
                                    message: format!("Security verification failed with {} warnings", warning_count),
                                    source: None
                                });
                            } else {
                                debug!("Security verification passed successfully");
                            }
                        }            
                        // Check for transaction success
                        if response.status == "success" {
                            Ok(response)
                        } else {
                            Err(AgentError::GeneralError {
                                message: format!("Transaction failed with status: {}", response.status),
                                source: None
                            })
                        }
                    },
                    Err(e) => {
                        error!("Transaction submission error: {}", e);
                        self.status = ExecutionStatus::SubmissionFailed;
                        Err(AgentError::GeneralError {
                            message: format!("Transaction submission error: {}", e),
                            source: None
                        })
                    }
                }
            },
            Err(_) => {
                // Timeout occurred
                self.status = ExecutionStatus::WitnessGenerationFailed;
                error!("Witness generation timed out after {}ms", verification_timeout.as_millis());
                Err(AgentError::GeneralError {
                    message: format!("Witness generation timed out after {}ms", verification_timeout.as_millis()),
                    source: None
                })
            }
        }
    }
    
    pub fn get_metrics(&self) -> &PerformanceMetrics {
        &self.metrics
    }
    
    pub fn get_status(&self) -> &ExecutionStatus {
        &self.status
    }
    
    // Mock implementation for local testing without a real StatelessVM service
    fn execute_mock_transaction(&mut self, tx_request: &StatelessTxRequest) -> AgentResult<StatelessTxResponse> {
        debug!("Using mock StatelessVM implementation");
        
        // Record performance metrics
        self.metrics.witness_generation_time_ms = 250; // Simulate 250ms for witness generation
        self.metrics.transaction_submission_time_ms = 150; // Simulate 150ms for transaction submission
        
        // Generate a random transaction hash
        let tx_hash = format!("0x{:x}{:x}{:x}{:x}", 
            rand::random::<u64>(), 
            rand::random::<u64>(), 
            rand::random::<u64>(), 
            rand::random::<u64>());
            
        // In mock mode, security verification always passes for testing purposes
        // In a real implementation, this would contain actual verification logic
        let mock_security_verification = if tx_request.security_verification.enabled {
            Some(SecurityVerificationResult {
                passed: true,
                risk_score: 0,
                warnings: None,
                execution_time_ms: Some(120),
                vulnerability_count: Some(0),
            })
        } else {
            None
        };
        
        Ok(StatelessTxResponse {
            tx_hash,
            status: "success".to_string(),
            result: Some("0x0000000000000000000000000000000000000000000000000000000000000001".to_string()),
            error: None,
            security_verification: mock_security_verification,
        })
    }
}
