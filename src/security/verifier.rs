use std::fmt;
use std::sync::{Arc, RwLock, Mutex};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::str::FromStr;

use serde::{Serialize, Deserialize};
use ethers::types::{H160, H256, Transaction, Bytes, Address, U256, U64};
use log::{debug, warn, info};

use crate::utils::config::SecurityConfig;
use crate::statelessvm::client::StatelessVmClient;

// For any future imports that might be needed to fix proc-macro issues
use async_trait::async_trait; // Often needed for async trait implementations

/// Request for security verification
#[derive(Debug, Clone)]
pub struct SecurityVerificationRequest {
    /// Maximum risk score allowed
    pub max_risk_score: u8,
    /// Whether to verify reentrancy vulnerabilities
    pub verify_reentrancy: bool,
    /// Whether to verify integer underflow vulnerabilities
    pub verify_integer_underflow: bool,
    /// Whether to verify integer overflow vulnerabilities
    pub verify_integer_overflow: bool,
    /// Whether to verify unchecked calls
    pub verify_unchecked_calls: bool,
    /// Whether to verify upgradability issues
    pub verify_upgradability: bool,
    /// Whether to verify MEV vulnerabilities
    pub verify_mev_vulnerability: bool,
    /// Whether to verify cross-contract reentrancy
    pub verify_cross_contract_reentrancy: bool,
    /// Whether to verify precision loss
    pub verify_precision_loss: bool,
    /// Whether to verify gas griefing
    pub verify_gas_griefing: bool,
    /// Whether to verify access control issues
    pub verify_access_control: bool,
    /// Whether to cache verification results
    pub cache_verification_results: bool,
    /// Duration for caching verification results in seconds
    pub verification_cache_duration_s: u64,
}

/// Error type for security verification operations
#[derive(Debug)]
pub enum SendError {
    /// Error when an invalid address is provided
    InvalidAddress,
    /// Error when API request fails
    ApiError(String),
    /// Error when parsing or data conversion fails
    ParseError(String),
    /// Any other error type
    Other(Box<dyn std::error::Error + Send + Sync>)
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::InvalidAddress => write!(f, "Invalid address format"),
            SendError::ApiError(msg) => write!(f, "API error: {}", msg),
            SendError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            SendError::Other(err) => write!(f, "Error: {}", err),
        }
    }
}

impl std::error::Error for SendError {}

use std::cmp::min;
use uuid::Uuid;
/// Security verification modes for transaction submission
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SecurityVerificationMode {
    /// Always verify transaction security
    Always,
    /// Only verify high-value transactions
    HighValueOnly,
    /// Only verify contract deployments
    DeploymentOnly,
    /// Disable security verification
    Disabled,
}

/// Verification intensity modes for performance optimization
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationMode {
    /// Complete verification with all security checks
    Complete,
    /// Focus only on MEV and front-running vulnerabilities for HFT
    MEVFocused,
    /// Minimal latency mode with only critical vulnerability checks
    MinimalLatency,
    /// Use cached verification result for known contract template
    Cached(String),
}

/// Types of vulnerabilities that can be detected
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VulnerabilityType {
    /// Vulnerability to Maximal Extractable Value attacks
    MEV {
        /// Additional details about the MEV vulnerability
        details: String,
    },
    /// Reentrancy vulnerability
    Reentrancy {
        /// Function vulnerable to reentrancy
        function_signature: String,
    },
    /// Integer overflow vulnerability
    IntegerOverflow {
        /// Location of the overflow
        location: String,
    },
    /// Integer underflow vulnerability
    IntegerUnderflow {
        /// Location of the underflow
        location: String,
    },
    /// Access control vulnerability
    AccessControl {
        /// Details about the access control issue
        details: String,
    },
    /// Unprotected selfdestruct or delegatecall
    UnprotectedOperation {
        /// Type of operation (selfdestruct, delegatecall, etc.)
        operation: String,
    },
    /// Frontrunning vulnerability
    Frontrunning {
        /// Details about the frontrunning vulnerability
        details: String,
    },
    /// Upgradability issues in the contract
    Upgradability {
        /// Details about the upgradability issues
        details: String,
    },
    /// Price manipulation vulnerability
    PriceManipulation {
        /// Details about the price manipulation vulnerability
        details: String,
    },
    /// Oracle manipulation vulnerability
    OracleManipulation {
        /// Details about the oracle manipulation vulnerability
        details: String,
    },
    /// Uninitialized storage vulnerability
    UninitializedStorage {
        /// Details about the uninitialized storage vulnerability
        details: String,
    },
    /// Missing slippage protection
    MissingSlippage {
        /// Details about the missing slippage protection
        details: String,
    },
    /// Timestamp dependence vulnerability
    TimestampDependence {
        /// Details about the timestamp dependence
        details: String,
    },
    /// Block number dependence vulnerability
    BlockNumberDependence {
        /// Details about the block number dependence
        details: String,
    },
    /// Gas griefing vulnerability
    GasGriefing {
        /// Details about the gas griefing vulnerability
        details: String,
    },
    /// Unchecked external calls
    UncheckedCalls {
        /// Details about the unchecked calls
        details: String,
    },
    /// Cross-contract reentrancy vulnerability
    CrossContractReentrancy {
        /// Details about the cross-contract reentrancy
        details: String,
    },

    /// Other vulnerability type
    Other {
        /// Name of the vulnerability
        name: String,
        /// Details about the vulnerability
        details: String,
    },
}

/// Severity levels for vulnerabilities
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    /// Critical severity - must be fixed immediately
    Critical,
    /// High severity - should be fixed as soon as possible
    High,
    /// Medium severity - should be addressed
    Medium,
    /// Low severity - minor issue
    Low,
    /// Informational - not a security issue but worth noting
    Info,
}

/// Represents a vulnerability detected in a contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityReport {
    /// Type of vulnerability
    pub vulnerability_type: VulnerabilityType,
    /// Severity level of the vulnerability
    pub severity: Severity,
    /// Risk score from 0-100, where 100 is highest risk
    pub risk_score: u8,
    /// Confidence level in the vulnerability detection (0-100)
    pub confidence: u8,
    /// Bytecode offset where vulnerability was detected (if applicable)
    pub bytecode_offset: Option<usize>,
    /// Function selector where vulnerability was detected (if applicable)
    pub function_selector: Option<String>,
    /// Timestamp when vulnerability was detected
    pub timestamp: u64,
}

impl VulnerabilityReport {
    /// Create a new vulnerability report
    pub fn new(vulnerability_type: VulnerabilityType, severity: Severity, risk_score: u8) -> Self {
        Self {
            vulnerability_type,
            severity,
            risk_score,
            confidence: 100, // Default high confidence
            bytecode_offset: None,
            function_selector: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Set bytecode offset for this vulnerability
    pub fn with_bytecode_offset(mut self, offset: usize) -> Self {
        self.bytecode_offset = Some(offset);
        self
    }

    /// Set function selector for this vulnerability
    pub fn with_function_selector(mut self, selector: String) -> Self {
        self.function_selector = Some(selector);
        self
    }

    /// Set confidence level for this vulnerability
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = min(confidence, 100);
        self
    }
}

/// Results of a security verification check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVerification {
    /// ID of the verification
    pub id: String,
    /// Address of the contract being verified
    pub contract_address: Option<String>,
    /// Transaction being verified
    pub transaction_hash: Option<String>,
    /// Detected vulnerabilities
    pub vulnerabilities: Vec<VulnerabilityReport>,
    /// Overall security score (0-100, where 100 is most secure)
    pub security_score: u8,
    /// Whether the verification result came from cache
    pub from_cache: bool,
    /// Timestamp when verification was performed
    pub timestamp: u64,
    /// Time to complete verification in milliseconds
    pub verification_time_ms: u64,
}

impl SecurityVerification {
    /// Returns an iterator over the vulnerability reports
    pub fn iter(&self) -> std::slice::Iter<'_, VulnerabilityReport> {
        self.vulnerabilities.iter()
    }
    
    /// Check if the verification result is considered safe
    /// A security score below threshold or having critical vulnerabilities is unsafe
    pub fn is_safe(&self) -> bool {
        if self.security_score < 70 {
            return false;
        }
        
        !self.vulnerabilities.iter().any(|vuln| vuln.severity == Severity::Critical)
    }
}

impl std::ops::Not for SecurityVerification {
    type Output = bool;

    fn not(self) -> Self::Output {
        !self.is_safe()
    }
}

impl std::ops::Not for &SecurityVerification {
    type Output = bool;

    fn not(self) -> Self::Output {
        !self.is_safe()
    }
}

// Implement IntoIterator for &SecurityVerification to allow direct iteration
impl<'a> IntoIterator for &'a SecurityVerification {
    type Item = &'a VulnerabilityReport;
    type IntoIter = std::slice::Iter<'a, VulnerabilityReport>;

    fn into_iter(self) -> Self::IntoIter {
        self.vulnerabilities.iter()
    }
}

impl SecurityVerification {
    /// Create a new security verification result
    pub fn new(contract_address: Option<H160>, transaction_hash: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            contract_address: contract_address.map(|addr| addr.to_string()),
            transaction_hash,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            security_score: 100,
            vulnerabilities: Vec::new(),
            from_cache: false,
            verification_time_ms: 0,
        }
    }

    /// Add a vulnerability to the verification result
    pub fn add_vulnerability(&mut self, vulnerability: VulnerabilityReport) {
        // Update security score based on the most severe vulnerability
        self.security_score = self.security_score.saturating_sub(
            (vulnerability.risk_score as f32 * 0.25) as u8
        );
        
        self.vulnerabilities.push(vulnerability);
    }
    
    /// Check if this verification has any critical vulnerabilities
    pub fn has_critical_vulnerabilities(&self) -> bool {
        self.vulnerabilities.iter().any(|v| {
            matches!(
                v.vulnerability_type,
                VulnerabilityType::Reentrancy { .. } |
                VulnerabilityType::IntegerOverflow { .. } |
                VulnerabilityType::UnprotectedOperation { .. } |
                VulnerabilityType::CrossContractReentrancy { .. } |
                VulnerabilityType::AccessControl { .. }
            ) && (v.severity == Severity::Critical || v.severity == Severity::High)
        })
    }
    
    /// Check if this verification has any MEV vulnerabilities
    pub fn has_mev_vulnerability(&self) -> bool {
        self.vulnerabilities.iter().any(|v| {
            matches!(v.vulnerability_type, VulnerabilityType::MEV { .. })
        })
    }

    /// Set the cache hit status
    pub fn set_cache_hit(&mut self, is_cache_hit: bool) {
        self.from_cache = is_cache_hit;
    }

    // is_safe method is already implemented above

    /// Returns true if the contract has MEV vulnerabilities (placeholder for future implementation)
    pub fn has_mev_detection(&self) -> bool {
        self.vulnerabilities.iter().any(|v| match v.vulnerability_type {
            VulnerabilityType::MEV { .. } => true,
            _ => false,
        })
    }
    
    /// Create an empty verification result
    pub fn empty() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            contract_address: None,
            transaction_hash: None,
            vulnerabilities: Vec::new(),
            security_score: 100, // Max score for empty verification
            from_cache: false,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            verification_time_ms: 0,
        }
    }
    
    /// Check if there are no vulnerabilities
    pub fn is_empty(&self) -> bool {
        self.vulnerabilities.is_empty()
    }
    
    /// Get a summary of vulnerabilities found during verification
    pub fn get_vulnerability_summary(&self) -> String {
        if self.vulnerabilities.is_empty() {
            return "No vulnerabilities detected".to_string();
        }
        
        let mut summary = format!("Found {} vulnerabilities:\n", self.vulnerabilities.len());
        for (i, vuln) in self.vulnerabilities.iter().enumerate() {
            let vuln_type = match &vuln.vulnerability_type {
                VulnerabilityType::MEV { details } => format!("MEV: {}", details),
                VulnerabilityType::Reentrancy { function_signature } => format!("Reentrancy in {}", function_signature),
                VulnerabilityType::IntegerOverflow { location } => format!("Integer Overflow at {}", location),
                VulnerabilityType::IntegerUnderflow { location } => format!("Integer Underflow at {}", location),
                VulnerabilityType::AccessControl { details } => format!("Access Control: {}", details),
                VulnerabilityType::UnprotectedOperation { operation } => format!("Unprotected Operation: {}", operation),
                VulnerabilityType::Frontrunning { details } => format!("Frontrunning: {}", details),
                VulnerabilityType::Upgradability { details } => format!("Upgradability: {}", details),
                VulnerabilityType::PriceManipulation { details } => format!("Price Manipulation: {}", details),
                VulnerabilityType::OracleManipulation { details } => format!("Oracle Manipulation: {}", details),
                VulnerabilityType::UninitializedStorage { details } => format!("Uninitialized Storage: {}", details),
                VulnerabilityType::MissingSlippage { details } => format!("Missing Slippage: {}", details),
                VulnerabilityType::TimestampDependence { details } => format!("Timestamp Dependence: {}", details),
                VulnerabilityType::BlockNumberDependence { details } => format!("Block Number Dependence: {}", details),
                VulnerabilityType::GasGriefing { details } => format!("Gas Griefing: {}", details),
                VulnerabilityType::UncheckedCalls { details } => format!("Unchecked Calls: {}", details),
                VulnerabilityType::CrossContractReentrancy { details } => format!("Cross-Contract Reentrancy: {}", details),
                VulnerabilityType::Other { name, details } => format!("{}: {}", name, details),
            };
            summary.push_str(&format!("{}. {} (Severity: {:?}, Risk Score: {})\n", i+1, vuln_type, vuln.severity, vuln.risk_score));
        }
        
        summary
    }
}

/// Cache entry for security verification results
#[derive(Debug, Clone)]
struct SecurityVerificationCacheEntry {
    /// The security verification result
    verification: SecurityVerification,
    /// When this cache entry expires
    expires_at: u64,
}

/// Main security verifier for DemonTrader
/// 
/// Provides security verification for smart contracts and transactions
/// using the EVM Verify framework. Focuses on MEV vulnerability detection
/// and other critical security checks.
#[derive(Debug, Clone)]
pub struct SecurityVerifier {
    /// Configuration for security verification
    config: SecurityConfig,
    /// Client for StatelessVM API
    stateless_vm_client: Arc<StatelessVmClient>,
    /// Cache for verification results
    verification_cache: Arc<RwLock<HashMap<String, SecurityVerificationCacheEntry>>>,
    /// Lock for verification operations
    verification_lock: Arc<Mutex<()>>,
    /// Test mode flag - when true, use mocked responses instead of real verification
    test_mode: bool,
    /// Test vulnerabilities to simulate in test mode
    test_vulnerabilities: Vec<VulnerabilityType>,
}

impl SecurityVerifier {
    /// Create a new security verifier instance
    pub fn new(config: &SecurityConfig, stateless_vm_url: &str) -> Self {
        let client = StatelessVmClient::new(stateless_vm_url);
        Self {
            config: config.clone(),
            stateless_vm_client: Arc::new(client),
            verification_cache: Arc::new(RwLock::new(HashMap::new())),
            verification_lock: Arc::new(Mutex::new(())),
            test_mode: false,
            test_vulnerabilities: Vec::new(),
        }
    }
    
    /// Create a new security verifier with explicit client
    pub fn new_with_client(config: &SecurityConfig, client: Arc<StatelessVmClient>) -> Self {
        Self {
            config: config.clone(),
            stateless_vm_client: client,
            verification_cache: Arc::new(RwLock::new(HashMap::new())),
            verification_lock: Arc::new(Mutex::new(())),
            test_mode: false,
            test_vulnerabilities: Vec::new(),
        }
    }
    
    /// Create a new security verifier in test mode
    pub fn new_with_test_mode(config: &SecurityConfig) -> Self {
        let client = StatelessVmClient::new("http://localhost:8000"); // Dummy URL, won't be used
        Self {
            config: config.clone(),
            stateless_vm_client: Arc::new(client),
            verification_cache: Arc::new(RwLock::new(HashMap::new())),
            verification_lock: Arc::new(Mutex::new(())),
            test_mode: true,
            test_vulnerabilities: vec![
                VulnerabilityType::Reentrancy { function_signature: "transfer(address,uint256)".to_string() },
                VulnerabilityType::IntegerOverflow { location: "0x123".to_string() },
                VulnerabilityType::AccessControl { details: "Missing access control for admin function".to_string() }
            ],
        }
    }
    
    /// Configure which vulnerabilities to simulate in test mode
    pub fn set_test_vulnerabilities(&mut self, vulnerabilities: Vec<VulnerabilityType>) {
        self.test_vulnerabilities = vulnerabilities;
    }

    /// Helper to add a specific vulnerability type for testing
    pub fn add_test_vulnerability(&mut self, vulnerability_type: VulnerabilityType) {
        self.test_vulnerabilities.push(vulnerability_type);
    }
    
    /// Check if the verifier is in test mode
    pub fn is_test_mode(&self) -> bool {
        self.test_mode
    }

    /// Verify a contract by its address
    /// 
    /// Fetch contract bytecode from the network
    pub fn fetch_bytecode<'a>(&'a self, address: &'a str) -> impl std::future::Future<Output = Result<Bytes, SendError>> + Send + 'a {
        async move {
            if self.test_mode {
                // In test mode, return a simple mock bytecode
                return Ok(Bytes::from(vec![0x60, 0x80, 0x60, 0x40, 0x52])); // Simple PUSH1 PUSH1 MSTORE
            }
            
            // Use the stateless_vm_client to fetch the bytecode
            match self.stateless_vm_client.fetch_bytecode(address).await {
                Ok(bytes) => Ok(Bytes::from(bytes)), // Convert Vec<u8> to Bytes
                Err(e) => Err(SendError::ApiError(format!("Failed to fetch bytecode: {}", e)))
            }
        }
    }
    
    /// Performs a comprehensive security check on the contract bytecode,
    /// focusing on MEV vulnerabilities and other critical security issues.
    pub fn verify_contract<'a>(&'a self, address: &'a str) -> impl std::future::Future<Output = Result<SecurityVerification, SendError>> + Send + 'a {
        async move {
            let address_str = address.to_string();
            
            // Check cache first
            if let Some(cached) = self.get_from_cache(&address_str) {
                debug!("Cache hit for contract {}", address_str);
                return Ok(cached);
            }

            // Fetch bytecode from network
            debug!("Fetching bytecode for contract {}", address_str);
            let bytecode = self.fetch_bytecode(address).await?;
            if bytecode.is_empty() {
                return Err(SendError::ApiError("No bytecode found for contract".to_string()));
            }

            // Perform security verification
            let start_time = SystemTime::now();
            let address_h160 = H160::from_str(address).map_err(|_| SendError::InvalidAddress)?;
            let mut verification = SecurityVerification::new(Some(address_h160), None);

            // Call StatelessVM client for verification
            let verification_request = SecurityVerificationRequest {
                max_risk_score: self.config.max_risk_score,
                verify_reentrancy: self.config.verify_reentrancy,
                verify_integer_underflow: self.config.verify_integer_underflow,
                verify_integer_overflow: self.config.verify_integer_overflow,
                verify_unchecked_calls: self.config.verify_unchecked_calls,
                verify_upgradability: self.config.verify_upgradability,
                verify_mev_vulnerability: self.config.verify_mev_vulnerability,
                verify_cross_contract_reentrancy: self.config.verify_cross_contract_reentrancy,
                verify_precision_loss: self.config.verify_precision_loss,
                verify_gas_griefing: self.config.verify_gas_griefing,
                verify_access_control: self.config.verify_access_control,
                cache_verification_results: self.config.cache_verification_results,
                verification_cache_duration_s: self.config.verification_cache_duration_s,
            };

            // Convert Bytes to Vec<u8> for the verify_bytecode method
            let bytecode_vec: Vec<u8> = bytecode.to_vec();
            
            // Perform security verification using StatelessVM client
            let verification_result = self.stateless_vm_client.verify_bytecode(&bytecode_vec).await
                .map_err(|e| SendError::ApiError(format!("Failed to verify bytecode: {}", e)))?;
                
            // Process verification results
            // Update the verification object based on the verification_result
            if let Some(warnings) = verification_result.warnings {
                for warning in warnings {
                    // Convert the warning to a vulnerability
                    let vulnerability_type = self.convert_warning_to_vulnerability(&warning);
                    // Calculate severity and risk score before moving vulnerability_type
                    let severity = self.determine_severity(&vulnerability_type);
                    let risk_score = self.calculate_risk_score(&vulnerability_type);
                    // Create a VulnerabilityReport from VulnerabilityType
                    let vulnerability_report = VulnerabilityReport {
                        vulnerability_type,
                        severity,
                        risk_score,
                        confidence: 80, // Default confidence level
                        bytecode_offset: None,
                        function_selector: None,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    };
                    verification.vulnerabilities.push(vulnerability_report);
                }
            }
            
            // Update security score (previously risk_score)
            verification.security_score = verification_result.risk_score;
            
            // Set verification time if available
            if let Some(time) = verification_result.execution_time_ms {
                verification.verification_time_ms = time;
            }

            // Calculate verification time
            if let Ok(elapsed) = start_time.elapsed() {
                verification.verification_time_ms = elapsed.as_millis() as u64;
            }

            // Add to cache
            self.add_to_cache(address_str, verification.clone());

            Ok(verification)
        }
    }

    /// Verify a transaction using individual parameters
    /// This is an overloaded method to support the existing API in the rest of the codebase
    pub fn verify_transaction_params<'a>(
        &'a self,
        from_address: &'a str,
        to_address: &'a str,
        amount: &'a str,
        data: &'a str,
        gas_limit: &'a str,
        gas_price: &'a str,
    ) -> impl std::future::Future<Output = Result<SecurityVerification, SendError>> + Send + 'a {
        async move {
            // Convert parameters to appropriate types
            let from = match from_address.parse::<H160>() {
                Ok(addr) => addr,
                Err(e) => return Err(SendError::ParseError(format!("Invalid from address: {}", e))),
            };
            
            let to = match to_address.parse::<H160>() {
                Ok(addr) => addr,
                Err(e) => return Err(SendError::ParseError(format!("Invalid to address: {}", e))),
            };
            
            // Create a transaction object
            let tx = Transaction {
                from,
                to: Some(to),
                nonce: U256::from_dec_str("0").unwrap_or_default(),
                value: U256::from_dec_str(amount).unwrap_or_default(),
                gas: U256::from_dec_str(gas_limit).unwrap_or_default(),
                gas_price: Some(U256::from_dec_str(gas_price).unwrap_or_default()),
                input: Bytes::from(data.as_bytes().to_vec()),
                v: U64::zero(),
                r: U256::zero(),
                s: U256::zero(),
                hash: H256::random(), // Generate a random hash for testing
                block_hash: None,
                block_number: None,
                transaction_index: None,
                transaction_type: None,
                access_list: None,
                max_priority_fee_per_gas: None,
                max_fee_per_gas: None,
                chain_id: None,
                other: Default::default(),
            };
        
            // Call the main verify_transaction method
            self.verify_transaction(&tx).await
        }
    }

    /// Verify a transaction before submission
    /// 
    /// Analyzes the transaction for potential security issues, especially
    /// focusing on MEV vulnerabilities and sandwich attack vectors.
    pub fn verify_transaction<'a>(&'a self, tx: &'a Transaction) -> impl std::future::Future<Output = Result<SecurityVerification, SendError>> + Send + 'a {
        async move {
            // Use default Complete verification mode
            self.verify_transaction_with_mode(tx, VerificationMode::Complete).await
        }
    }

    /// Verify a transaction with specific verification mode for HFT optimization
    /// 
    /// Allows specifying different verification strategies to balance security and performance
    pub fn verify_transaction_with_mode<'a>(&'a self, tx: &'a Transaction, mode: VerificationMode) -> impl std::future::Future<Output = Result<SecurityVerification, SendError>> + Send + 'a {
        async move {
        // Test mode check
        if self.test_mode {
            let mut verification = SecurityVerification::new(tx.to, Some(format!("{:?}", tx.hash)));
            for vulnerability in &self.test_vulnerabilities {
                let severity = match vulnerability {
                    VulnerabilityType::Reentrancy { .. } => Severity::Critical,
                    VulnerabilityType::IntegerOverflow { .. } => Severity::High,
                    VulnerabilityType::AccessControl { .. } => Severity::Medium,
                    _ => Severity::Low,
                };
                let risk_score = match vulnerability {
                    VulnerabilityType::Reentrancy { .. } => 95,
                    VulnerabilityType::IntegerOverflow { .. } => 92,
                    VulnerabilityType::AccessControl { .. } => 85,
                    _ => 70,
                };
                let mut vuln = VulnerabilityReport::new(vulnerability.clone(), severity, risk_score);
                // The description is part of the vulnerability type, not a field of VulnerabilityReport
                // Store it in the function_selector field as a workaround
                vuln = vuln.with_function_selector("test".to_string());
                verification.add_vulnerability(vuln);
            }
            return Ok(verification);
        }
        
        // Handle cached mode first
        if let VerificationMode::Cached(template_id) = &mode {
            if let Some(cached_result) = self.get_from_cache(template_id) {
                debug!("Using cached template verification result for template {}", template_id);
                let mut result = cached_result.clone();
                result.set_cache_hit(true);
                return Ok(result);
            } else {
                warn!("No cached verification found for template {}, falling back to complete verification", template_id);
                // Fall through to complete verification
            }
        }
        
        // Check transaction hash cache as a secondary option
        let tx_hash = format!("{:?}", tx.hash);
        if let Some(cached_result) = self.get_from_cache(&tx_hash) {
            debug!("Using cached verification result for transaction {}", tx_hash);
            return Ok(cached_result);
        }
        
        // Create a new verification result
        let mut verification = SecurityVerification::new(tx.to, Some(tx_hash.clone()));
        
        // Apply different verification strategies based on mode
        match mode {
            VerificationMode::MinimalLatency => {
                // Perform only critical checks with minimal latency
                self.verify_critical_only(&mut verification, tx);
            },
            VerificationMode::MEVFocused => {
                // Focus on MEV protection for HFT
                self.verify_mev_focused(&mut verification, tx);
            },
            _ => {
                // Complete verification (default)
                self.verify_complete(&mut verification, tx);
            }
        };

        // Add to cache
        self.add_to_cache(tx_hash, verification.clone());
        
        // If this was a template verification in Complete mode, also cache by template ID if provided
        if let VerificationMode::Cached(template_id) = mode {
            debug!("Caching verification result for template {}", template_id);
            self.add_to_cache(template_id, verification.clone());
        }

        Ok(verification)
        }
    }

    /// Perform only critical security checks for minimal latency
    fn verify_critical_only(&self, verification: &mut SecurityVerification, tx: &Transaction) {
        // Lock to prevent concurrent modifications to shared state
        let _lock = self.verification_lock.lock().unwrap();
        
        debug!("Performing minimal latency verification for transaction {:?}", tx.hash);
        
        // Only check for critical vulnerabilities like reentrancy and integer overflow
        // that could lead to immediate fund loss
        
        // Check for reentrancy vulnerabilities
        if self.has_reentrancy_pattern(&tx.input.0) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::Reentrancy {
                    function_signature: "unknown".to_string(),
                },
                Severity::Critical,
                95,
            ));
        }
        
        // Check for integer overflow in transaction parameters
        if self.has_integer_overflow_risk(tx) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::IntegerOverflow {
                    location: "transaction parameters".to_string(),
                },
                Severity::Critical,
                92,
            ));
        }
    }
    
    /// Perform MEV-focused verification for HFT
    fn verify_mev_focused(&self, verification: &mut SecurityVerification, tx: &Transaction) {
        // Lock to prevent concurrent modifications to shared state
        let _lock = self.verification_lock.lock().unwrap();
        
        debug!("Performing MEV-focused verification for transaction {:?}", tx.hash);
        
        // First do critical checks
        self.verify_critical_only(verification, tx);
        
        // Add MEV-specific checks
        
        // Check for unprotected price operations
        if self.has_unprotected_price_operations(&tx.input.0) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::MEV {
                    details: "Unprotected price operations detected".to_string(),
                },
                Severity::High,
                85,
            ));
        }
        
        // Check for missing slippage protection
        if self.has_missing_slippage_protection(&tx.input.0) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::MEV {
                    details: "Missing slippage protection".to_string(),
                },
                Severity::High,
                82,
            ));
        }
    }
    
    /// Perform complete verification (all checks)
    fn verify_complete(&self, verification: &mut SecurityVerification, tx: &Transaction) {
        // Lock to prevent concurrent modifications to shared state
        let _lock = self.verification_lock.lock().unwrap();
        
        debug!("Performing complete verification for transaction {:?}", tx.hash);
        
        // First do MEV-focused checks which include critical checks
        self.verify_mev_focused(verification, tx);
        
        // Add all remaining checks
        
        // Check for gas griefing vulnerabilities
        if self.has_gas_griefing_pattern(&tx.input.0) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::GasGriefing {
                    details: "Potential gas griefing vulnerability".to_string(),
                },
                Severity::Medium,
                70,
            ));
        }
        
        // Check for access control issues
        if self.has_access_control_pattern(&tx.input.0) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::AccessControl {
                    details: "Potential access control vulnerability".to_string(),
                },
                Severity::Medium,
                75,
            ));
        }
        
        // Check for unchecked external calls
        if self.has_unchecked_calls_pattern(&tx.input.0) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::UncheckedCalls {
                    details: "Unchecked external call detected".to_string(),
                },
                Severity::Medium,
                72,
            ));
        }
        
        // Check for integer underflow
        if self.has_integer_underflow_pattern(&tx.input.0) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::IntegerUnderflow {
                    location: "transaction data".to_string(),
                },
                Severity::High,
                85,
            ));
        }
    }
    
    /// Add a verification result to the cache
    fn add_to_cache(&self, key: String, verification: SecurityVerification) {
        let mut cache = self.verification_cache.write().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let ttl = self.config.verification_cache_duration_s; // Cache duration in seconds
        
        let entry = SecurityVerificationCacheEntry {
            verification,
            expires_at: now + ttl,
        };
        
        cache.insert(key, entry);
        
        // Cleanup expired entries if cache is too large
        if cache.len() > 1000 { // Default max cache size
            let expired_keys: Vec<String> = cache.iter()
                .filter(|(_, entry)| entry.expires_at <= now)
                .map(|(key, _)| key.clone())
                .collect();
            
            for key in expired_keys {
                cache.remove(&key);
            }
        }
    }

    // Process verification results from the StatelessVM client
    /// Get verification result from cache if available
    fn get_from_cache(&self, key: &str) -> Option<SecurityVerification> {
        let cache = self.verification_cache.read().unwrap();
        
        if let Some(entry) = cache.get(key) {
            // Check if the cache entry is still valid
            let now = chrono::Utc::now().timestamp();
            if now < entry.expires_at as i64 {
                let mut result = entry.verification.clone();
                result.set_cache_hit(true);
                return Some(result);
            }
        }
        
        None
    }
    
    /// Check for MEV-specific patterns in bytecode
    fn check_for_mev_pattern(&self, bytecode: &[u8]) -> bool {
        // Check for unprotected price operations
        if self.has_unprotected_price_operations(bytecode) {
            return true;
        }
        
        // Check for missing slippage protection
        if self.has_missing_slippage_protection(bytecode) {
            return true;
        }
        
        false
    }
    
    /// Converts a SecurityWarning from the StatelessVmClient into a VulnerabilityType
    fn convert_warning_to_vulnerability(&self, warning: &crate::statelessvm::client::SecurityWarning) -> VulnerabilityType {
        // Map the warning type to a VulnerabilityType based on the warning_type string
        match warning.warning_type.as_str() {
            "reentrancy" => VulnerabilityType::Reentrancy {
                function_signature: warning.message.clone(),
            },
            "integer_overflow" => VulnerabilityType::IntegerOverflow {
                location: warning.message.clone(),
            },
            "integer_underflow" => VulnerabilityType::IntegerUnderflow {
                location: warning.message.clone(),
            },
            "unchecked_calls" => VulnerabilityType::UncheckedCalls {
                details: warning.description.clone(),
            },
            "cross_contract_reentrancy" => VulnerabilityType::CrossContractReentrancy {
                details: warning.description.clone(),
            },
            "mev" => VulnerabilityType::MEV {
                details: warning.description.clone(),
            },
            "access_control" => VulnerabilityType::AccessControl {
                details: warning.description.clone(),
            },
            "unprotected_operation" => VulnerabilityType::UnprotectedOperation {
                operation: warning.message.clone(),
            },
            "frontrunning" => VulnerabilityType::Frontrunning {
                details: warning.description.clone(),
            },
            "oracle_manipulation" => VulnerabilityType::OracleManipulation {
                details: warning.description.clone(),
            },
            "missing_slippage" => VulnerabilityType::MissingSlippage {
                details: warning.description.clone(),
            },
            "uninitialized_storage" => VulnerabilityType::UninitializedStorage {
                details: warning.description.clone(),
            },
            "timestamp_dependence" => VulnerabilityType::TimestampDependence {
                details: warning.description.clone(),
            },
            "blocknumber_dependence" => VulnerabilityType::BlockNumberDependence {
                details: warning.description.clone(),
            },
            "gas_griefing" => VulnerabilityType::GasGriefing {
                details: warning.description.clone(),
            },
            "upgradability" => VulnerabilityType::Upgradability {
                details: warning.description.clone(),
            },
            "price_manipulation" => VulnerabilityType::PriceManipulation {
                details: warning.description.clone(),
            },
            // Default case for unknown warning types
            _ => VulnerabilityType::Other {
                name: warning.warning_type.clone(),
                details: format!("{}. {}", warning.warning_type, warning.description)
            },
        }
    }
    
    /// Determine severity level based on vulnerability type
    fn determine_severity(&self, vulnerability_type: &VulnerabilityType) -> Severity {
        match vulnerability_type {
            VulnerabilityType::Reentrancy { .. } => Severity::Critical,
            VulnerabilityType::IntegerOverflow { .. } => Severity::High,
            VulnerabilityType::IntegerUnderflow { .. } => Severity::High,
            VulnerabilityType::MEV { .. } => Severity::High,
            VulnerabilityType::AccessControl { .. } => Severity::Critical,
            VulnerabilityType::UncheckedCalls { .. } => Severity::Medium,
            VulnerabilityType::GasGriefing { .. } => Severity::Medium,
            VulnerabilityType::CrossContractReentrancy { .. } => Severity::Critical,
            VulnerabilityType::BlockNumberDependence { .. } => Severity::Medium,
            VulnerabilityType::OracleManipulation { .. } => Severity::High,
            VulnerabilityType::PriceManipulation { .. } => Severity::High,
            VulnerabilityType::Frontrunning { .. } => Severity::Medium,
            VulnerabilityType::MissingSlippage { .. } => Severity::Medium,
            VulnerabilityType::UninitializedStorage { .. } => Severity::Medium,
            VulnerabilityType::TimestampDependence { .. } => Severity::Medium,
            VulnerabilityType::Upgradability { .. } => Severity::Medium,
            VulnerabilityType::UnprotectedOperation { .. } => Severity::High,
            VulnerabilityType::Other { .. } => Severity::Medium,
        }
    }
    
    /// Calculate risk score based on vulnerability type (0-100)
    fn calculate_risk_score(&self, vulnerability_type: &VulnerabilityType) -> u8 {
        match vulnerability_type {
            VulnerabilityType::Reentrancy { .. } => 95,
            VulnerabilityType::IntegerOverflow { .. } => 85,
            VulnerabilityType::IntegerUnderflow { .. } => 85,
            VulnerabilityType::MEV { .. } => 80,
            VulnerabilityType::AccessControl { .. } => 90,
            VulnerabilityType::UncheckedCalls { .. } => 70,
            VulnerabilityType::GasGriefing { .. } => 65,
            VulnerabilityType::CrossContractReentrancy { .. } => 90,
            VulnerabilityType::BlockNumberDependence { .. } => 60,
            VulnerabilityType::OracleManipulation { .. } => 85,
            VulnerabilityType::PriceManipulation { .. } => 80,
            VulnerabilityType::Frontrunning { .. } => 75,
            VulnerabilityType::MissingSlippage { .. } => 70,
            VulnerabilityType::UninitializedStorage { .. } => 75,
            VulnerabilityType::TimestampDependence { .. } => 60,
            VulnerabilityType::Upgradability { .. } => 70,
            VulnerabilityType::UnprotectedOperation { .. } => 85,
            VulnerabilityType::Other { .. } => 50,
        }
    }
    
    fn process_verification_result(
        &self,
        verification: &mut SecurityVerification,
        bytecode: Vec<u8>
    ) {
        // If we're in test mode, use mock analysis
        if self.test_mode {
            let vulnerabilities = self.mock_analyze_bytecode(&bytecode);
            for vuln in vulnerabilities {
                let (severity, risk_score) = match &vuln {
                    VulnerabilityType::Reentrancy { .. } => (Severity::Critical, 95),
                    VulnerabilityType::IntegerOverflow { .. } => (Severity::High, 80),
                    VulnerabilityType::IntegerUnderflow { .. } => (Severity::High, 80),
                    VulnerabilityType::UncheckedCalls { .. } => (Severity::Medium, 70),
                    VulnerabilityType::CrossContractReentrancy { .. } => (Severity::High, 85),
                    VulnerabilityType::MEV { .. } => (Severity::High, 85),
                    VulnerabilityType::AccessControl { .. } => (Severity::High, 85),
                    VulnerabilityType::UnprotectedOperation { .. } => (Severity::Critical, 95),
                    VulnerabilityType::Frontrunning { .. } => (Severity::Medium, 70),
                    VulnerabilityType::OracleManipulation { .. } => (Severity::High, 85),
                    VulnerabilityType::MissingSlippage { .. } => (Severity::Medium, 70),
                    VulnerabilityType::UninitializedStorage { .. } => (Severity::Medium, 65),
                    VulnerabilityType::TimestampDependence { .. } => (Severity::Low, 50),
                    VulnerabilityType::BlockNumberDependence { .. } => (Severity::Low, 50),
                    VulnerabilityType::GasGriefing { .. } => (Severity::Medium, 65),
                    VulnerabilityType::Upgradability { .. } => (Severity::Medium, 60),
                    VulnerabilityType::PriceManipulation { .. } => (Severity::High, 85),
                    VulnerabilityType::Other { .. } => (Severity::Medium, 65),
                };
                
                verification.add_vulnerability(VulnerabilityReport::new(vuln, severity, risk_score));
            }
            return;
        }
        
        // Real implementation would analyze bytecode here
        // This is a simplified version that looks for patterns in bytecode
        
        // Check for MEV vulnerabilities (simplified example)
        let has_mev_pattern = self.check_for_mev_pattern(&bytecode);
        if has_mev_pattern {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::MEV {
                    details: "Contract is vulnerable to MEV extraction".to_string(),
                },
                Severity::High,
                85,
            ));
        }
        
        // Check for uninitialized storage vulnerability
        if !bytecode.is_empty() && bytecode.len() > 10 {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::UninitializedStorage {
                    details: "Contract may have uninitialized storage variables".to_string(),
                },
                Severity::Medium,
                65,
            ));
        }
        
        // Check for reentrancy vulnerabilities
        if self.has_reentrancy_pattern(&bytecode) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::Reentrancy {
                    function_signature: "unknown".to_string(),
                },
                Severity::Critical,
                95,
            ));
        }
        
        // Check for integer overflow
        if self.has_integer_overflow_pattern(&bytecode) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::IntegerOverflow {
                    location: "unknown".to_string(),
                },
                Severity::High,
                80,
            ));
        }
        
        // Check for integer underflow
        if self.has_integer_underflow_pattern(&bytecode) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::IntegerUnderflow {
                    location: "unknown".to_string(),
                },
                Severity::High,
                80,
            ));
        }
        
        // Check for unchecked calls
        if self.has_unchecked_calls_pattern(&bytecode) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::UncheckedCalls {
                    details: "External calls without proper error handling".to_string(),
                },
                Severity::Medium,
                70,
            ));
        }
        
        // Check for access control issues
        if self.has_access_control_pattern(&bytecode) {
            verification.add_vulnerability(VulnerabilityReport::new(
                VulnerabilityType::AccessControl {
                    details: "Missing or improper access controls".to_string(),
                },
                Severity::High,
                85,
            ));
        }
    }
    
    /// Detects reentrancy patterns in bytecode
    /// Looks for CALL opcodes followed by state modifications (SSTORE)
    fn has_reentrancy_pattern(&self, bytecode: &[u8]) -> bool {
        for i in 0..bytecode.len().saturating_sub(5) {
            // Check for CALL opcode (0xF1) followed by SSTORE (0x55) within a few opcodes
            if bytecode[i] == 0xF1 {
                for j in i+1..std::cmp::min(i+10, bytecode.len()) {
                    if bytecode[j] == 0x55 {
                        return true;
                    }
                }
            }
            
            // Also check for DELEGATECALL (0xF4) followed by SSTORE
            if bytecode[i] == 0xF4 {
                for j in i+1..std::cmp::min(i+10, bytecode.len()) {
                    if bytecode[j] == 0x55 {
                        return true;
                    }
                }
            }
            
            // Check for STATICCALL (0xFA) followed by SSTORE
            if bytecode[i] == 0xFA {
                for j in i+1..std::cmp::min(i+10, bytecode.len()) {
                    if bytecode[j] == 0x55 {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Detects integer overflow patterns in bytecode
    /// Checks for ADD, MUL operations without proper bounds checking
    fn has_integer_overflow_pattern(&self, bytecode: &[u8]) -> bool {
        for i in 0..bytecode.len().saturating_sub(10) {
            // Check for ADD (0x01) or MUL (0x02) operations without overflow checks
            if bytecode[i] == 0x01 || bytecode[i] == 0x02 {
                // Check if there's no overflow check (no comparison before the operation)
                let mut has_check = false;
                for j in i.saturating_sub(5)..i {
                    if j < bytecode.len() && (bytecode[j] == 0x10 || bytecode[j] == 0x11) { // LT or GT
                        has_check = true;
                        break;
                    }
                }
                if !has_check {
                    return true;
                }
            }
        }
        false
    }
    
    /// Detects integer underflow patterns in bytecode
    /// Checks for SUB operations without proper checks
    fn has_integer_underflow_pattern(&self, bytecode: &[u8]) -> bool {
        for i in 0..bytecode.len().saturating_sub(5) {
            // Check for SUB (0x03) without proper checks
            if bytecode[i] == 0x03 {
                // Check if there's no underflow check (no comparison before the operation)
                let mut has_check = false;
                for j in i.saturating_sub(5)..i {
                    if j < bytecode.len() && bytecode[j] == 0x10 { // LT comparison
                        has_check = true;
                        break;
                    }
                }
                if !has_check {
                    return true;
                }
            }
        }
        false
    }
    
    /// Detects gas griefing patterns in bytecode
    /// Checks for unbounded loops and expensive operations
    fn has_gas_griefing_pattern(&self, bytecode: &[u8]) -> bool {
        let mut loop_count = 0;
        
        for i in 0..bytecode.len().saturating_sub(3) {
            // Look for JUMP (0x56) and JUMPI (0x57) patterns that might indicate loops
            if bytecode[i] == 0x56 || bytecode[i] == 0x57 {
                loop_count += 1;
                
                // Check for SLOAD (0x54) or SSTORE (0x55) within potential loop
                for j in i+1..std::cmp::min(i+20, bytecode.len()) {
                    if bytecode[j] == 0x54 || bytecode[j] == 0x55 {
                        // Storage operations in a loop are expensive
                        return true;
                    }
                }
            }
            
            // Check for CALL (0xF1) without gas check
            if bytecode[i] == 0xF1 {
                let mut has_gas_check = false;
                for j in i.saturating_sub(5)..i {
                    if j < bytecode.len() && bytecode[j] == 0x5A { // GAS opcode
                        has_gas_check = true;
                        break;
                    }
                }
                if !has_gas_check {
                    return true;
                }
            }
        }
        
        // Multiple loops might indicate gas griefing potential
        loop_count > 2
    }
    
    /// Detects access control pattern issues
    /// Checks for operations without proper authorization
    fn has_access_control_pattern(&self, bytecode: &[u8]) -> bool {
        let mut has_auth_check = false;
        
        // Look for standard access control patterns
        for i in 0..bytecode.len().saturating_sub(10) {
            // Check for potential authorization via CALLER (0x33) opcode
            if bytecode[i] == 0x33 { // CALLER
                for j in i+1..std::cmp::min(i+10, bytecode.len()) {
                    if bytecode[j] == 0x14 { // EQ opcode (comparing to a stored address)
                        has_auth_check = true;
                        break;
                    }
                }
            }
            
            // Check for potential admin role check pattern
            if i+3 < bytecode.len() && bytecode[i] == 0x54 && bytecode[i+1] == 0x33 && bytecode[i+2] == 0x14 {
                // SLOAD + CALLER + EQ pattern (loading role and comparing to caller)
                has_auth_check = true;
            }
            
            // Check for SELFDESTRUCT (0xFF) or DELEGATECALL (0xF4) without authorization
            if (bytecode[i] == 0xFF || bytecode[i] == 0xF4) && !has_auth_check {
                return true;
            }
        }
        
        !has_auth_check && bytecode.len() > 30 // If no auth checks found in a non-trivial contract
    }
    
    /// Detects unchecked external calls patterns
    /// Checks for CALL operations without return value checking
    fn has_unchecked_calls_pattern(&self, bytecode: &[u8]) -> bool {
        for i in 0..bytecode.len().saturating_sub(5) {
            // Check for CALL (0xF1) without checking return value
            if bytecode[i] == 0xF1 {
                let mut checks_return = false;
                for j in i+1..std::cmp::min(i+5, bytecode.len()) {
                    if bytecode[j] == 0x15 { // ISZERO check for return value
                        checks_return = true;
                        break;
                    }
                }
                if !checks_return {
                    return true;
                }
            }
        }
        false
    }
    
    /// Detects unprotected price operations in bytecode
    /// Checks for common DEX swap signatures without slippage protection
    fn has_unprotected_price_operations(&self, bytecode: &[u8]) -> bool {
        // Common DEX swap function signatures
        let swap_signatures = [
            // Uniswap V2 swapExactTokensForTokens
            [0x38, 0xed, 0x17, 0x39],
            // Uniswap V2 swapTokensForExactTokens
            [0x8e, 0xd5, 0x28, 0x73],
            // PancakeSwap exact input
            [0x41, 0x4b, 0xf3, 0x89],
            // SushiSwap swapExactTokensForTokens
            [0x79, 0x39, 0xe0, 0x24]
        ];
        
        // Check if the bytecode contains swap function signatures
        for i in 0..bytecode.len().saturating_sub(4) {
            for signature in &swap_signatures {
                if bytecode[i..].starts_with(signature) {
                    // Look for slippage protection (min/max amount parameters)
                    let mut has_protection = false;
                    
                    // Skip 4 bytes of function signature and look for parameters
                    if i+4+64 < bytecode.len() {
                        // Check for deadline parameter (common in DEX swaps with slippage protection)
                        for j in i+4..i+4+64 {
                            if j+4 < bytecode.len() && bytecode[j..j+4] == [0x42, 0x00, 0x00, 0x00] { // TIMESTAMP comparison
                                has_protection = true;
                                break;
                            }
                        }
                    }
                    
                    if !has_protection {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Detects missing slippage protection in transactions
    /// Looks for swap operations without min/max amount bounds
    fn has_missing_slippage_protection(&self, data: &[u8]) -> bool {
        // Common DEX methods that require slippage protection
        let swap_methods = [
            // Uniswap V2 - swapExactTokensForTokens - 0x38ed1739
            [0x38, 0xed, 0x17, 0x39],
            // Uniswap V2 - swapTokensForExactTokens - 0x8803dbee
            [0x88, 0x03, 0xdb, 0xee],
            // Uniswap V3 - exactInputSingle - 0x414bf389
            [0x41, 0x4b, 0xf3, 0x89]
        ];
        
        // Check if transaction data contains a swap method
        if data.len() >= 4 {
            let method_id = &data[0..4];
            
            for &swap_method in &swap_methods {
                if method_id == swap_method {
                    // For most swap methods, the last parameter should be a non-zero deadline
                    // and there should be a minimum amount out parameter (typically found at offset 4+32)
                    
                    // Check if there's enough data for parameters
                    if data.len() >= 4+32*2 {
                        // Check for zero or very high slippage (min amount out is very low or amountOutMin = 1)
                        let min_amount_position = 4+32; // Typical position of amountOutMin parameter
                        
                        // Check if min amount is 0 or 1 (indicating no slippage protection)
                        let mut is_zero_or_one = true;
                        for i in 0..31 {
                            if data[min_amount_position + i] != 0 {
                                is_zero_or_one = false;
                                break;
                            }
                        }
                        
                        // Last byte could be 0 or 1 for no protection
                        if is_zero_or_one && (data[min_amount_position + 31] == 0 || data[min_amount_position + 31] == 1) {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    /// Detects integer overflow risk in transaction parameters
    /// Checks for suspiciously large values that could cause overflow
    fn has_integer_overflow_risk(&self, tx: &Transaction) -> bool {
        let max_safe_value = U256::from(2).pow(U256::from(128));
        
        // Check transaction value
        if tx.value > max_safe_value {
            return true;
        }
        
        // Check gas price if available
        if let Some(gas_price) = tx.gas_price {
            if gas_price > max_safe_value {
                return true;
            }
        }
        
        // Check for large numbers in transaction data
        if tx.input.0.len() >= 36 { // At least function selector + one parameter
            // Check each 32-byte parameter for large values
            for i in (4..tx.input.0.len()).step_by(32) {
                if i + 32 <= tx.input.0.len() {
                    let mut value = U256::zero();
                    for j in 0..32 {
                        if i + j < tx.input.0.len() {
                            value = value.overflowing_mul(U256::from(256)).0;
                            value = value.overflowing_add(U256::from(tx.input.0[i + j])).0;
                        }
                    }
                    
                    if value > max_safe_value {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Helper method to check for timestamp checks in bytecode
    fn has_timestamp_check(&self, bytecode: &[u8]) -> bool {
        for i in 0..bytecode.len().saturating_sub(2) {
            // Look for TIMESTAMP (0x42) opcode followed by comparison
            if bytecode[i] == 0x42 && i+1 < bytecode.len() {
                if bytecode[i+1] == 0x10 || bytecode[i+1] == 0x11 || bytecode[i+1] == 0x14 { // LT, GT, EQ
                    return true;
                }
            }
        }
        false
    }
    
    /// Helper method to check for minimum amount checks in bytecode
    fn has_minimum_amount_check(&self, bytecode: &[u8]) -> bool {
        // This is a simplified check for minimum amount comparisons
        // A real implementation would need to analyze the stack and data flow
        for i in 0..bytecode.len().saturating_sub(5) {
            // Look for pattern of loading a parameter and doing comparison
            if bytecode[i] == 0x35 && i+2 < bytecode.len() { // CALLDATALOAD
                if bytecode[i+1] == 0x10 || bytecode[i+1] == 0x11 { // LT or GT
                    return true;
                }
            }
        }
        false
    }
    
    /// Mock analyze bytecode for test mode
    fn mock_analyze_bytecode(&self, _bytecode: &[u8]) -> Vec<VulnerabilityType> {
        let mut vulnerabilities = Vec::new();
        
        // In test mode, return the configured test vulnerabilities
        for vuln in &self.test_vulnerabilities {
            match vuln {
                VulnerabilityType::Reentrancy { .. } => vulnerabilities.push(VulnerabilityType::Reentrancy { 
                    function_signature: "test_function".to_string() 
                }),
                VulnerabilityType::IntegerOverflow { .. } => vulnerabilities.push(VulnerabilityType::IntegerOverflow { 
                    location: "test_location".to_string() 
                }),
                VulnerabilityType::IntegerUnderflow { .. } => vulnerabilities.push(VulnerabilityType::IntegerUnderflow { 
                    location: "test_location".to_string() 
                }),
                VulnerabilityType::UncheckedCalls { .. } => vulnerabilities.push(VulnerabilityType::UncheckedCalls {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::CrossContractReentrancy { .. } => vulnerabilities.push(VulnerabilityType::CrossContractReentrancy {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::MEV { .. } => vulnerabilities.push(VulnerabilityType::MEV {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::AccessControl { .. } => vulnerabilities.push(VulnerabilityType::AccessControl {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::UnprotectedOperation { .. } => vulnerabilities.push(VulnerabilityType::UnprotectedOperation {
                    operation: "test_operation".to_string() 
                }),
                VulnerabilityType::Frontrunning { .. } => vulnerabilities.push(VulnerabilityType::Frontrunning {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::Upgradability { .. } => vulnerabilities.push(VulnerabilityType::Upgradability {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::PriceManipulation { .. } => vulnerabilities.push(VulnerabilityType::PriceManipulation {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::OracleManipulation { .. } => vulnerabilities.push(VulnerabilityType::OracleManipulation {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::MissingSlippage { .. } => vulnerabilities.push(VulnerabilityType::MissingSlippage {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::TimestampDependence { .. } => vulnerabilities.push(VulnerabilityType::TimestampDependence {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::BlockNumberDependence { .. } => vulnerabilities.push(VulnerabilityType::BlockNumberDependence {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::GasGriefing { .. } => vulnerabilities.push(VulnerabilityType::GasGriefing {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::UninitializedStorage { .. } => vulnerabilities.push(VulnerabilityType::UninitializedStorage {
                    details: "test_details".to_string()
                }),
                VulnerabilityType::Other { .. } => {
                    vulnerabilities.push(VulnerabilityType::Other { 
                        name: "Custom".to_string(),
                        details: "Custom vulnerability for testing".to_string() 
                    });
                }
            }
        }

        
        vulnerabilities
    }
    
    /// Test mode version of verify_contract
    pub async fn verify_contract_test_mode(&self, contract_address: &str) -> Result<Vec<VulnerabilityReport>, SendError> {
        let mut vulnerabilities = Vec::new();
        
        // Generate mock vulnerabilities based on test_vulnerabilities
        for vuln_type in &self.test_vulnerabilities {
            let (severity, description) = match vuln_type {
                VulnerabilityType::Reentrancy { function_signature } => 
                    (Severity::High, format!("Reentrancy in function {}", function_signature)),
                VulnerabilityType::IntegerOverflow { location } => 
                    (Severity::High, format!("Integer overflow at {}", location)),
                VulnerabilityType::IntegerUnderflow { location } => 
                    (Severity::High, format!("Integer underflow at {}", location)),
                VulnerabilityType::UninitializedStorage { details } => 
                    (Severity::Medium, format!("Uninitialized storage: {}", details)),
                VulnerabilityType::UncheckedCalls { details } => 
                    (Severity::Medium, format!("Unchecked external calls: {}", details)),
                VulnerabilityType::CrossContractReentrancy { details } => 
                    (Severity::High, format!("Cross-contract reentrancy: {}", details)),
                VulnerabilityType::MEV { details } => 
                    (Severity::High, format!("MEV vulnerability: {}", details)),
                VulnerabilityType::AccessControl { details } => 
                    (Severity::High, format!("Access control issue: {}", details)),
                VulnerabilityType::UnprotectedOperation { operation } => 
                    (Severity::Critical, format!("Unprotected {}", operation)),
                VulnerabilityType::Frontrunning { details } => 
                    (Severity::Medium, format!("Frontrunning vulnerability: {}", details)),
                VulnerabilityType::OracleManipulation { details } => 
                    (Severity::High, format!("Oracle manipulation: {}", details)),
                VulnerabilityType::MissingSlippage { details } => 
                    (Severity::Medium, format!("Missing slippage protection: {}", details)),
                VulnerabilityType::TimestampDependence { details } => 
                    (Severity::Low, format!("Timestamp dependence: {}", details)),
                VulnerabilityType::BlockNumberDependence { details } => 
                    (Severity::Low, format!("Block number dependence: {}", details)),
                VulnerabilityType::GasGriefing { details } => 
                    (Severity::Medium, format!("Gas griefing: {}", details)),
                VulnerabilityType::Upgradability { details } => 
                    (Severity::Medium, format!("Upgradability issues: {}", details)),
                VulnerabilityType::PriceManipulation { details } => 
                    (Severity::High, format!("Price manipulation: {}", details)),
                VulnerabilityType::Other { name, details } => 
                    (Severity::Medium, format!("{}: {}", name, details)),
            };
            
            let risk_score = match severity {
                Severity::High => 80,
                Severity::Medium => 60,
                Severity::Low => 30,
                Severity::Critical => 100,
                Severity::Info => 10,
            };
            
            let mut vuln = VulnerabilityReport::new(vuln_type.clone(), severity, risk_score);
            vuln = vuln.with_function_selector(description);
            vulnerabilities.push(vuln);
        }
        
        Ok(vulnerabilities)
    }

/// Test mode version of verify_transaction
pub fn verify_transaction_test_mode<'a>(
    &'a self,
    _from: &'a str,
    _to: &'a str,
    _value: &'a str,
    _data: &'a str,
    _gas_limit: &'a str,
    _gas_price: &'a str,
) -> impl std::future::Future<Output = Result<bool, SendError>> + Send + 'a {
    async move {
        // In test mode, simple ETH transfers are always safe
        let is_data_empty = _data == "0x" || _data.is_empty();
        
        if is_data_empty {
            // Simple ETH transfer is safe
            return Ok(true);
        }
        
        // For contract interactions, determine safety based on configured test vulnerabilities
        let has_mev_vulnerability = self.test_vulnerabilities.iter().any(|v| {
            match v {
                VulnerabilityType::MEV { .. } => true,
                _ => false
            }
        });
        
        // Check for critical vulnerabilities using proper pattern matching for struct variants
        let has_critical_vulnerabilities = self.test_vulnerabilities.iter().any(|v| {
            match v {
                VulnerabilityType::Reentrancy { .. } => true,
                VulnerabilityType::IntegerOverflow { .. } => true,
                VulnerabilityType::UnprotectedOperation { .. } => true,
                VulnerabilityType::AccessControl { details: _ } => true, // Explicit field binding
                VulnerabilityType::IntegerUnderflow { .. } => true,
                VulnerabilityType::UncheckedCalls { .. } => true,
                VulnerabilityType::CrossContractReentrancy { .. } => true,
                VulnerabilityType::UninitializedStorage { .. } => false, // Not critical
                VulnerabilityType::OracleManipulation { .. } => true,
                VulnerabilityType::MissingSlippage { .. } => true,
                VulnerabilityType::TimestampDependence { .. } => false,
                VulnerabilityType::BlockNumberDependence { .. } => false,
                VulnerabilityType::GasGriefing { .. } => true,
                VulnerabilityType::Upgradability { .. } => false,
                VulnerabilityType::PriceManipulation { .. } => true,
                VulnerabilityType::Frontrunning { .. } => true,
                VulnerabilityType::MEV { .. } => true,
                VulnerabilityType::Other { .. } => false
            }
        });
        
        Ok(!has_critical_vulnerabilities && !has_mev_vulnerability)
    }
}
}
