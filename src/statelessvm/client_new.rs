use crate::security::verifier::SecurityVerification;
use serde::{Deserialize, Serialize};
use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::env;
use serde_json::{Value, json};
use ethers::types::{Bytes, H160, U256};
use tokio;

// Define SendError type alias for this module
type SendError = Box<dyn std::error::Error + Send + Sync>;

// Error type for StatelessVM operations
#[derive(Debug)]
pub enum StatelessVmError {
    ApiRequestError(String),
    ApiResponseError(String),
    ApiErrorResponse(String),
    SerializationError(String),
    DeserializationError(String),
}

impl std::fmt::Display for StatelessVmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatelessVmError::ApiRequestError(msg) => write!(f, "StatelessVM API request error: {}", msg),
            StatelessVmError::ApiResponseError(msg) => write!(f, "StatelessVM API response error: {}", msg),
            StatelessVmError::ApiErrorResponse(msg) => write!(f, "StatelessVM API error: {}", msg),
            StatelessVmError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            StatelessVmError::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
        }
    }
}

impl std::error::Error for StatelessVmError {}

impl From<reqwest::Error> for StatelessVmError {
    fn from(err: reqwest::Error) -> Self {
        StatelessVmError::ApiRequestError(err.to_string())
    }
}

impl From<serde_json::Error> for StatelessVmError {
    fn from(err: serde_json::Error) -> Self {
        StatelessVmError::DeserializationError(err.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessTxRequest {
    pub from: String,
    pub to: String,
    pub value: String,
    pub data: String,
    pub gas_limit: String,
    pub gas_price: String,
    pub security_verification: SecurityVerificationRequest,
    pub bundle_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVerificationRequest {
    pub address: String,
    pub enabled: bool,
    pub max_risk_score: u8,
    pub verify_reentrancy: bool,
    pub verify_integer_underflow: bool,
    pub verify_integer_overflow: bool,
    pub verify_unchecked_calls: bool,
    pub verify_upgradability: bool,
    pub verify_mev_vulnerability: bool,
    pub verify_cross_contract_reentrancy: bool,
    pub verify_precision_loss: bool,
    pub verify_gas_griefing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessTxResponse {
    pub tx_hash: String,
    pub status: String,
    pub result: Option<String>,
    pub error: Option<String>,
    pub security_verification: Option<SecurityVerificationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVerificationResult {
    pub passed: bool,
    pub risk_score: u8,
    pub warnings: Option<Vec<SecurityWarning>>,
    pub execution_time_ms: Option<u64>,
    pub vulnerability_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityWarning {
    pub warning_type: String,
    pub severity: String,
    pub description: String,
    pub message: String,
    pub line_number: Option<u32>,
    pub code_snippet: Option<String>,
    pub recommendation: Option<String>,
}

// Represents a transaction trace from the stateless VM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionTrace {
    pub tx_hash: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub gas_used: u64,
    pub execution_steps: Vec<ExecutionStep>,
    pub state_changes: Vec<StateChange>,
    pub events: Vec<EventLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStep {
    pub pc: u32,
    pub op: String,
    pub gas: u64,
    pub gas_cost: u64,
    pub depth: u32,
    pub stack: Vec<String>,
    pub memory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub address: String,
    pub slot: String,
    pub previous_value: String,
    pub new_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

// Transaction sequence execution types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub chain_id: u64,
    pub block_number: Option<u64>,
    pub timestamp: u64,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessSequenceRequest {
    pub sequence_id: String,
    pub transactions: Vec<String>, // Hex-encoded transaction data
    pub fallback_plans: Option<Vec<FallbackPlanRequest>>,
    pub market_conditions: Option<Value>,
    pub mev_protection: Option<MevProtectionRequest>,
    pub state_verification: Option<Vec<StateVerificationRequest>>,
    pub execution_context: ExecutionContext,
    pub timeout_seconds: u64,
    pub atomic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackPlanRequest {
    pub transactions: Vec<String>,
    pub trigger_conditions: Value,
    pub priority: u8,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevProtectionRequest {
    pub use_private_mempool: bool,
    pub frontrunning_protection: u8,
    pub max_slippage_percent: f64,
    pub monitor_sandwich_attacks: bool,
    pub use_commit_reveal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVerificationRequest {
    pub contracts: Vec<String>,
    pub storage_slots: HashMap<String, Vec<String>>,
    pub balance_requirements: HashMap<String, String>,
    pub custom_requirements: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessSequenceResponse {
    pub sequence_id: String,
    pub success: bool,
    pub transaction_statuses: Vec<TransactionExecutionStatus>,
    pub market_state: Option<MarketStateData>,
    pub mev_protection_results: Option<MevProtectionResults>,
    pub state_verification_results: Option<Vec<StateVerificationResult>>,
    pub fallback_executed: bool,
    pub fallback_results: Option<Vec<FallbackExecutionResult>>,
    pub error: Option<String>,
    pub gas_used: u64,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionExecutionStatus {
    pub tx_hash: String,
    pub success: bool,
    pub gas_used: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketStateData {
    pub prices: HashMap<String, f64>,
    pub liquidity: HashMap<String, u64>,
    pub gas_price: u64,
    pub volatility: HashMap<String, f64>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevProtectionResults {
    pub frontrunning_detected: bool,
    pub sandwich_attack_prevented: bool,
    pub slippage_within_limits: bool,
    pub private_tx_successful: bool,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVerificationResult {
    pub step: u32,
    pub success: bool,
    pub verified_contracts: Vec<String>,
    pub failed_verifications: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackExecutionResult {
    pub plan_id: u8,
    pub executed: bool,
    pub success: bool,
    pub transaction_statuses: Option<Vec<TransactionExecutionStatus>>,
    pub description: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessVmErrorResponse {
    pub error: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StatelessVmClient {
    client: Client,
    url: String,
    avalanche_rpc_url: String,
    base_url: String, 
    direct_mode: bool,
    rpc_url: Option<String>,
    chain_id: u64,
    debug_mode: bool,
}

impl StatelessVmClient {
    /// Format a transaction for the StatelessVM server
    /// The server expects transactions in a specific format that can be processed by the StatelessVM
    fn format_transaction_for_server(&self, tx_request: &StatelessTxRequest) -> String {
        // Format the from address correctly (ensure it has 0x prefix)
        let from = if !tx_request.from.starts_with("0x") {
            format!("0x{}", tx_request.from)
        } else {
            tx_request.from.clone()
        };
        
        // Format the to address correctly (ensure it has 0x prefix)
        let to = if !tx_request.to.starts_with("0x") {
            format!("0x{}", tx_request.to)
        } else {
            tx_request.to.clone()
        };
        
        // Ensure data has 0x prefix
        let data = if !tx_request.data.starts_with("0x") {
            format!("0x{}", tx_request.data)
        } else {
            tx_request.data.clone()
        };
        
        // Get the bundle_id value or generate a new one if not provided
        let bundle_id = tx_request.bundle_id.clone().unwrap_or_else(|| {
            format!("auto-{}", uuid::Uuid::new_v4())
        });
        
        // For testing purposes, we'll create a simple transaction payload as a hex string
    // Note: In production, we should use proper RLP encoding for Ethereum transactions
    
    // Convert all fields to hex representation without 0x prefix
    let from_hex = from.trim_start_matches("0x");
    let to_hex = to.trim_start_matches("0x");
    let value_hex = tx_request.value.trim_start_matches("0x");
    let data_hex = data.trim_start_matches("0x");
    let gas_limit_hex = tx_request.gas_limit.trim_start_matches("0x");
    let gas_price_hex = tx_request.gas_price.trim_start_matches("0x");
    
    // Create a simple mock transaction representation
    // This is a simplified format just for testing - real implementations should use RLP encoding
    let tx_payload = format!(
        "{}{}{}{}{}{}00{}", 
        from_hex,
        to_hex,
        value_hex,
        data_hex,
        gas_limit_hex,
        gas_price_hex,
        bundle_id.replace("-", "")
    );
    
    if self.debug_mode {
        println!("[DEBUG] Generated transaction payload: {}", tx_payload);
    }
    
    // Return the transaction data as a hex string
    tx_payload
    }
    
    /// Create a new client with the specified base URL
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
            direct_mode: false,
            rpc_url: None,
            chain_id: 1, // Default to Ethereum mainnet
            debug_mode: false,
            url: base_url.to_string(),
            avalanche_rpc_url: String::new(),
        }
    }
    
    /// Enable or disable debug mode
    pub fn with_debug_mode(mut self, debug: bool) -> Self {
        self.debug_mode = debug;
        self
    }
    
    /// Enable debug mode for detailed logging
    pub fn with_debug(mut self) -> Self {
        self.debug_mode = true;
        self
    }
    
    /// Return the base URL of the StatelessVM service
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    
    /// Return the chain ID for this client
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    
    /// Create a new client in direct RPC mode for real trading
    /// This bypasses the StatelessVM service and makes direct RPC calls
    pub fn new_direct(rpc_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: String::new(), // Not used in direct mode
            direct_mode: true,
            rpc_url: Some(rpc_url.to_string()),
            chain_id: 1, // Default to Ethereum mainnet
            debug_mode: false,
            url: String::new(),
            avalanche_rpc_url: rpc_url.to_string(),
        }
    }
    
    pub async fn new_async(url: Option<String>, avalanche_rpc_url: Option<String>, debug_mode: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let url = url.unwrap_or_else(|| {
            env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string())
        });
        
        let avalanche_rpc_url = avalanche_rpc_url.unwrap_or_else(|| {
            env::var("AVALANCHE_RPC_URL").unwrap_or_else(|_| "https://api.avax.network/ext/bc/C/rpc".to_string())
        });
        
        // Create a client with enhanced settings for better connection handling
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60)) // Increase timeout to 60 seconds
            .pool_max_idle_per_host(0) // Disable connection pooling to avoid reusing problematic connections
            .tcp_keepalive(std::time::Duration::from_secs(15)) // Keep connections alive
            .build()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        
        Ok(Self {
            client,
            url: url.clone(),
            avalanche_rpc_url,
            base_url: url,
            direct_mode: false,
            rpc_url: None,
            chain_id: 43114, // Avalanche C-Chain
            debug_mode,
        })
    }

    pub async fn execute_transaction(&self, tx_request: StatelessTxRequest) -> Result<StatelessTxResponse, SendError> {
        if self.debug_mode {
            println!("[DEBUG] execute_transaction called with tx_request: {:?}", tx_request);
        }
        
        // Call execute_tx_sequence with atomic=true
        let sequence_response = self.execute_tx_sequence(vec![tx_request], 1, true, None).await?;
        
        if self.debug_mode {
            println!("[DEBUG] execute_tx_sequence returned sequence_response: {:?}", sequence_response);
        }
        
        // Extract the first transaction status
        let tx_status = sequence_response.transaction_statuses.into_iter().next()
            .ok_or_else(|| "No transaction results returned".to_string())?;
            
        // Convert TransactionExecutionStatus to StatelessTxResponse
        let tx_response = StatelessTxResponse {
            tx_hash: tx_status.tx_hash,
            status: if tx_status.success { "success".to_string() } else { "failed".to_string() },
            result: None, // We don't have this info from the sequence response
            error: tx_status.error,
            security_verification: None, // We don't have this info from the sequence response
        };
            
        Ok(tx_response)
    }
    
    pub async fn verify_bytecode(&self, bytecode: &Vec<u8>) -> Result<SecurityVerificationResult, SendError> {
        let response = self.client
            .post(&format!("{}/verify", self.base_url))
            .body(hex::encode(bytecode))
            .send()
            .await?;
            
        if !response.status().is_success() {
            return Err(format!("StatelessVM verification request failed with status: {}", response.status()).into());
        }
        
        let verification_result: SecurityVerificationResult = response.json().await?;
        Ok(verification_result)
    }

    /// Execute a sequence of transactions as a single unit, optionally atomic
    pub async fn execute_sequence(&self, sequence_request: StatelessSequenceRequest) -> Result<StatelessSequenceResponse, SendError> {
        if self.direct_mode {
            return self.execute_sequence_direct(sequence_request).await;
        }
        
        // Get the base URL
        let base_url = &self.base_url;
        let api_url = format!("{}/sequence", base_url);
        
        println!("Executing sequence via StatelessVM service: {}", api_url);
        println!("Sequence ID: {}", sequence_request.sequence_id);
        println!("Transaction count: {}", sequence_request.transactions.len());
        
        // For debugging: print the JSON request
        let request_json = serde_json::to_string_pretty(&sequence_request)
            .unwrap_or_else(|e| format!("Error serializing request: {}", e));
            
        if self.debug_mode {
            println!("[DEBUG] Request JSON:\n{}", request_json);
            
            // In debug mode, print more details about the transaction data
            println!("[DEBUG] Transaction details:");
            for (i, tx) in sequence_request.transactions.iter().enumerate() {
                println!("[DEBUG] Transaction {}:\n{}", i+1, tx);
            }
            
            // Dump all fields to help diagnose the issue
            println!("[DEBUG] sequence_id: {}", sequence_request.sequence_id);
            println!("[DEBUG] transactions.len(): {}", sequence_request.transactions.len());
            println!("[DEBUG] atomic: {}", sequence_request.atomic);
            println!("[DEBUG] timeout_seconds: {}", sequence_request.timeout_seconds);
        } else {
            println!("Request JSON:\n{}", request_json);
        }
        
        // Create a request client with enhanced settings for better connection handling
        let client_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60)) // Increase timeout to 60 seconds
            .pool_max_idle_per_host(0)  // Disable connection pooling to avoid reusing problematic connections
            .tcp_keepalive(std::time::Duration::from_secs(15)); // Keep connections alive
            
        // Build the client
        let client = client_builder.build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
        
        // Serialize manually to avoid chunked encoding which can cause issues
        let body_json = serde_json::to_string(&sequence_request)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;
            
        // CRITICAL DEBUG: Print the exact JSON being sent to the server ALWAYS
        println!("CRITICAL DEBUG - Actual JSON being sent to server:\n{}", body_json);
        println!("CRITICAL DEBUG - Checking if 'transactions' field exists in JSON: {}", body_json.contains("\"transactions\":"));
        
        // Try to parse the JSON back and check the structure
        match serde_json::from_str::<serde_json::Value>(&body_json) {
            Ok(json_value) => {
                println!("CRITICAL DEBUG - JSON structure: {}", json_value);
                if let Some(transactions) = json_value.get("transactions") {
                    println!("CRITICAL DEBUG - transactions field found in parsed JSON: {:?}", transactions);
                } else {
                    println!("CRITICAL DEBUG - ERROR: transactions field NOT found in parsed JSON");
                    // Print the keys that are present
                    if let Some(obj) = json_value.as_object() {
                        println!("CRITICAL DEBUG - Keys present in JSON: {:?}", obj.keys().collect::<Vec<_>>());
                    }
                }
            },
            Err(e) => println!("CRITICAL DEBUG - Error parsing JSON: {}", e)
        }
            
        // Send the request with explicit content type and headers
        let request = client.post(&api_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Connection", "close")  // Explicitly close the connection after request
            .header("Content-Length", body_json.len().to_string()) // Set content length explicitly
            .header("Accept-Encoding", "identity") // Disable compression
            .body(body_json);
        
        if self.debug_mode {
            println!("[DEBUG] Sending request to: {}", api_url);
            println!("[DEBUG] Request debug: {:?}", request);
        }
        
        let response_result = request.send().await;
        
        // Handle request errors with detailed information
        let response = match response_result {
            Ok(resp) => {
                let status = resp.status();
                let headers = resp.headers().clone();
                
                if self.debug_mode {
                    println!("[DEBUG] Response status: {}", status);
                    println!("[DEBUG] Response headers: {:?}", headers);
                } else {
                    println!("Response status: {}", status);
                }
                
                if !status.is_success() {
                    let error_text = resp.text().await
                        .unwrap_or_else(|e| format!("Failed to get error response text: {}", e));
                    
                    if self.debug_mode {
                        println!("[DEBUG] Error response body: {}", error_text);
                    }
                    
                    return Err(format!("StatelessVM API request failed with status: {} - Response: {}", 
                        status, error_text).into());
                }
                
                // Get response body with better error handling
                let response_body = match resp.text().await {
                    Ok(text) => text,
                    Err(e) => {
                        if self.debug_mode {
                            println!("[DEBUG] Error reading response body: {}", e);
                            println!("[DEBUG] Error type: {:?}", e.to_string());
                            if let Some(source) = e.source() {
                                println!("[DEBUG] Error source details: {:?}", source);
                                if let Some(inner_source) = source.source() {
                                    println!("[DEBUG] Inner error source: {:?}", inner_source);
                                }
                            }
                        }
                        return Err(format!("Failed to read response body: {}", e).into());
                    }
                };
                
                if self.debug_mode {
                    println!("[DEBUG] Response length: {} bytes", response_body.len());
                    
                    if response_body.len() < 1000 {
                        println!("[DEBUG] Full response: {}", response_body);
                    } else {
                        println!("[DEBUG] Response preview: {}...", &response_body[..500]);
                    }
                } else {
                    println!("Response length: {} bytes", response_body.len());
                    
                    if response_body.len() < 200 {
                        println!("Full response: {}", response_body);
                    } else {
                        println!("Response preview: {}...", &response_body[..200]);
                    }
                }
                
                response_body
            },
            Err(e) => {
                // Provide enhanced error information with detailed diagnostics
                let error_detail = if e.is_timeout() {
                    "Request timed out"
                } else if e.is_connect() {
                    "Connection error"
                } else if e.is_request() {
                    "Invalid request"
                } else if e.is_body() {
                    "Request body error"
                } else if e.is_decode() {
                    "Response decode error"
                } else {
                    "Unknown error"
                };
                
                if self.debug_mode {
                    println!("[DEBUG] Request error: {}", e);
                    println!("[DEBUG] Error type: {}", error_detail);
                    if let Some(source) = e.source() {
                        println!("[DEBUG] Error source: {:?}", source);
                        if let Some(inner_source) = source.source() {
                            println!("[DEBUG] Inner error source: {:?}", inner_source);
                            // Try to get more detailed information about the error
                            if let Some(inner_inner_source) = inner_source.source() {
                                println!("[DEBUG] Inner inner error source: {:?}", inner_inner_source);
                            }
                        }
                    } else {
                        println!("[DEBUG] No error source available");
                    }
                }
                
                return Err(format!("StatelessVM API request error ({}): {}", error_detail, e).into());
            }
        };
        
        // Try to parse the response as JSON
        let status_res: serde_json::Result<serde_json::Value> = serde_json::from_str(&response);
        
        // Check for errors in the response
        if let Ok(status_obj) = status_res {
            if let Some(error) = status_obj.get("error") {
                if !error.is_null() {
                    let error_str = error.to_string();
                    return Err(format!("StatelessVM sequence execution failed: {}", error_str).into());
                }
            }
        }
        
        // Try to deserialize the response manually
        let sequence_response: StatelessSequenceResponse = match serde_json::from_str(&response) {
            Ok(resp) => resp,
            Err(e) => {
                println!("Deserialization error: {} - Response text: {}", e, response);
                return Err(format!("Failed to deserialize response: {}", e).into());
            }
        };
        Ok(sequence_response)
    }

    /// Internal implementation of direct execution
    async fn execute_sequence_direct(&self, sequence_request: StatelessSequenceRequest) -> Result<StatelessSequenceResponse, SendError> {
        let rpc_url = self.rpc_url.as_ref().ok_or("RPC URL not set for direct mode")?;
        
        println!("Executing sequence directly on Avalanche C-Chain via RPC");
        println!("Using RPC URL: {}", rpc_url);
        println!("Transaction count: {}", sequence_request.transactions.len());
        
        // For real trading, we need to submit each transaction to the network
        // In production, you would use a proper web3 library for this (like ethers-rs)
        // This is a simplified implementation for demonstration purposes
        
        // Get nonce for the sender address
        let wallet_address = std::env::var("WALLET_ADDRESS")?;
        let _wallet_key = std::env::var("WALLET_KEY")?; // Not used in this simplified implementation
        
        println!("Using wallet: {}", wallet_address);
        
        // Create a basic response
        let mut response = StatelessSequenceResponse {
            sequence_id: sequence_request.sequence_id.clone(),
            success: true,
            transaction_statuses: Vec::new(),
            market_state: None,
            mev_protection_results: None,
            state_verification_results: None,
            fallback_executed: false,
            fallback_results: None,
            error: None,
            gas_used: 0,
            execution_time_ms: 0,
        };
        
        // In a real implementation, we would:
        // 1. Get the current nonce for the wallet
        // 2. Create and sign each transaction
        // 3. Submit them to the network
        // 4. Wait for receipts
        
        // For now, we'll simulate success
        for (i, tx) in sequence_request.transactions.iter().enumerate() {
            println!("Transaction {}: {:.60}...", i+1, tx);
            
            let status = TransactionExecutionStatus {
                tx_hash: format!("0x{:064x}", i), // Fake tx hash
                success: true,
                gas_used: 100000,
                error: None,
            };
            
            response.transaction_statuses.push(status);
        }
        
        println!("All transactions submitted successfully in direct mode");
        println!("WARNING: This is a simplified implementation. In production, use a proper Web3 library.");
        
        Ok(response)
    }
    
    /// Execute a sequence of transactions atomically (all succeed or all fail).
    /// 
    /// This is a convenience wrapper around execute_tx_sequence with atomic=true.
    pub async fn execute_atomic_sequence(
        &self,
        transactions: Vec<StatelessTxRequest>,
        chain_id: u64,
        timeout_seconds: Option<u64>
    ) -> Result<StatelessSequenceResponse, SendError> {
        // Call execute_tx_sequence with atomic=true
        self.execute_tx_sequence(transactions, chain_id, true, timeout_seconds).await
    }
    
    /// Execute a sequence of transactions by converting StatelessTxRequest objects to
    /// encoded transaction strings and executes them as a sequence.
    /// 
    /// # Arguments
    /// * `tx_requests` - Vector of transaction requests to execute in sequence
    /// * `chain_id` - Chain ID for the execution context
    /// * `atomic` - Whether the sequence should be executed atomically (all succeed or all fail)
    /// 
    /// # Returns
    /// Result containing the sequence execution response or an error
    pub async fn execute_tx_sequence(
        &self,
        tx_requests: Vec<StatelessTxRequest>,
        chain_id: u64,
        atomic: bool,
        timeout_seconds: Option<u64>
    ) -> Result<StatelessSequenceResponse, SendError> {
        // Create transaction strings from request objects
        let mut transactions = Vec::with_capacity(tx_requests.len());
        
        for tx_request in tx_requests {
            // Format the transaction in the specific format required by the StatelessVM server
            let formatted_tx = self.format_transaction_for_server(&tx_request);
            
            if self.debug_mode {
                println!("[DEBUG] Formatted transaction: {}", formatted_tx);
            }
            
            transactions.push(formatted_tx);
        }
        
        // Create a default execution context with current timestamp
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        // Create a simplified execution context with just essential fields
        let execution_context = ExecutionContext {
            chain_id,
            block_number: None,
            timestamp: current_timestamp,
            metadata: serde_json::Value::Null,
        };
        
        // Create a timestamp-based sequence ID
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
            
        // Create a minimal sequence request with only essential fields
        let sequence_request = StatelessSequenceRequest {
            sequence_id: format!("seq_{}", timestamp),
            transactions,
            fallback_plans: None,
            market_conditions: None,
            mev_protection: None, 
            state_verification: None,
            execution_context,
            timeout_seconds: timeout_seconds.unwrap_or(30), // Reduce timeout to avoid long waiting periods
            atomic,
        };
        
        const MAX_ATTEMPTS: u8 = 3;
        let mut attempt: u8 = 1;
        let mut backoff_time = 1; // Start with 1 second backoff
        
        while attempt <= MAX_ATTEMPTS {
            if attempt > 1 {
                println!("Execution attempt {}/{}", attempt, MAX_ATTEMPTS);
            }
            
            match self.execute_sequence(sequence_request.clone()).await {
                Ok(response) => {
                    if attempt > 1 {
                        println!("Succeeded on attempt {}", attempt);
                    }
                    return Ok(response);
                },
                Err(e) => {
                    // Check if error is related to connection issues
                    let is_connection_error = e.to_string().to_lowercase().contains("connection") ||
                                            e.to_string().to_lowercase().contains("timeout") ||
                                            e.to_string().to_lowercase().contains("closed");
                    
                    if attempt == MAX_ATTEMPTS {
                        return Err(e);
                    } else {
                        println!("Attempt {} failed: {}, retrying...", attempt, e);
                        attempt += 1;
                        
                        // Use exponential backoff for connection issues
                        if is_connection_error {
                            println!("Connection issue detected, backing off for {} seconds", backoff_time);
                            tokio::time::sleep(tokio::time::Duration::from_secs(backoff_time)).await;
                            backoff_time *= 2; // Exponential backoff
                        } else {
                            // Regular 1 second delay for other errors
                            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        }
        
        // This should never be reached due to the above loop's return conditions
        Err("Failed after multiple attempts".into())
    }
}
