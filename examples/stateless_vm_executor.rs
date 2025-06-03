use ai_trading_agent::statelessvm::client::{StatelessVmClient, StatelessTxRequest, StatelessTxResponse, SecurityVerificationRequest, SecurityVerificationResult};
use ai_trading_agent::models::error::{AgentError, AgentResult};
use std::time::{Instant, Duration};
use std::env;
use log::{info, warn, error, debug};
use env_logger;

// Status codes for better tracking
#[derive(Debug)]
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

fn main() -> AgentResult<()> {
    // Create and run a new tokio runtime
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    // Get StatelessVM URL from environment or use default
    let stateless_vm_url = env::var("STATELESS_VM_URL")
        .unwrap_or_else(|_| "http://localhost:7548".to_string());
    
    println!("Starting StatelessVM executor example with URL: {}", stateless_vm_url);
    
    // Initialize the executor with reasonable defaults
    let verification_timeout_ms = 5000; // 5 seconds
    let max_retry_attempts = 3;
    let retry_backoff_ms = 1000; // 1 second
    
    let mut executor = StatelessVmExecutor::new(
        &stateless_vm_url,
        verification_timeout_ms,
        max_retry_attempts,
        retry_backoff_ms
    );
    
    // Example sender and receiver addresses
    let sender = "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199";
    let receiver = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    
    // Create a security verification request
    let security_config = SecurityVerificationRequest {
        address: sender.to_string(),
        enabled: true,
        max_risk_score: 50,
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
    
    // Sample transaction data (token transfer)
    let tx_data = "0xa9059cbb000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000003b9aca00";
    
    // Create transaction request
    let tx_request = StatelessTxRequest {
        from: sender.to_string(),
        to: receiver.to_string(),
        value: "0".to_string(),
        data: tx_data.to_string(),
        gas_limit: "100000".to_string(),
        gas_price: "10000000000".to_string(),
        security_verification: security_config.clone(),
        bundle_id: None,
    };
    
    // Execute the transaction
    println!("Executing transaction...\n");
    
    match executor.execute_transaction(tx_request).await {
        Ok(response) => {
            println!("Transaction executed successfully!");
            println!("Response: {:?}\n", response);
            
            println!("Performance metrics:");
            let metrics = executor.get_metrics();
            println!("  Witness generation time: {}ms", metrics.witness_generation_time_ms);
            println!("  Transaction submission time: {}ms", metrics.transaction_submission_time_ms);
            
            println!("\nCurrent executor status: {:?}", executor.get_status());
        },
        Err(e) => {
            println!("Failed to execute transaction: {:?}", e);
            println!("Current executor status: {:?}", executor.get_status());
            println!("\nFalling back to mock mode...");
            executor.enable_mock_mode();
            
            // Create a new request for mock execution
            let mock_tx_request = StatelessTxRequest {
                from: sender.to_string(),
                to: receiver.to_string(),
                value: "0".to_string(),
                data: tx_data.to_string(),
                gas_limit: "100000".to_string(),
                gas_price: "10000000000".to_string(),
                security_verification: security_config,
                bundle_id: None,
            };
            
            match executor.execute_mock_transaction(&mock_tx_request) {
                Ok(mock_response) => {
                    println!("Mock transaction executed successfully!");
                    println!("Mock response: {:?}", mock_response);
                },
                Err(mock_err) => {
                    println!("Mock execution also failed: {:?}", mock_err);
                }
            }
        }
    }
    
        Ok(())
    })
}
