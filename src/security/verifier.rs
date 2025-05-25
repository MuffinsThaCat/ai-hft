use crate::utils::config::SecurityConfig;
use crate::statelessvm::client::{StatelessVmClient, SecurityVerificationRequest, SecurityVerificationResult};
// Define SendError type alias for this module
type SendError = Box<dyn std::error::Error + Send + Sync>;
use std::sync::Arc;
use uuid::Uuid;
use tokio::sync::Mutex;

// Represents a vulnerability detected in a contract
#[derive(Debug, Clone)]
pub struct VulnerabilityReport {
    pub contract_address: String,
    pub vulnerability_type: VulnerabilityType,
    pub severity: Severity,
    pub description: String,
    pub risk_score: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VulnerabilityType {
    Reentrancy,
    IntegerOverflow,
    IntegerUnderflow,
    AccessControl,
    FlashLoanVulnerability,
    MEVVulnerability,
    PrecisionLoss,
    GasGriefing,
    UninitializedStorage,
    CrossContractReentrancy,
    SignatureReplay,
    OracleManipulation,
    BlockNumberDependence,
    FrontRunning,
    PriceManipulation,
    BitMaskVulnerability,
    GovernanceVulnerability,
    UncheckedExternalCalls,
    TxOriginUsage,
    BlockGasLimitIssues,
    UpgradabilityIssue,
}

#[derive(Debug, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// SecurityVerification modes and settings for integration with stateless VM
#[derive(Debug, Clone)]
pub struct SecurityVerification {
    pub enabled: bool,
    pub max_risk_score: u8,
    // Individual verification flags are now used instead of verification_types
}

// VerificationType enum removed - now using individual boolean flags for each verification type

// Security verifier that integrates with your EVM-Verify components
#[derive(Debug, Clone)]
pub struct SecurityVerifier {
    config: SecurityConfig,
    stateless_client: Arc<Mutex<StatelessVmClient>>,
}

impl SecurityVerifier {
    pub fn new(config: &SecurityConfig, stateless_vm_url: &str) -> Self {
        Self {
            config: config.clone(),
            stateless_client: Arc::new(Mutex::new(StatelessVmClient::new(stateless_vm_url))),
        }
    }
    
    // Verify a contract before interacting with it
    pub async fn verify_contract(&self, contract_address: &str) -> Result<Vec<VulnerabilityReport>, SendError> {
        println!("Verifying contract safety: {}", contract_address);
        if !self.config.verify_contracts {
            println!("Contract verification disabled in config");
            return Ok(Vec::new());
        }
        
        // Check if we already verified this contract
        if let Some(is_safe) = self.get_cached_verification(contract_address).await {
            if is_safe {
                println!("Contract {} already verified and is safe", contract_address);
                return Ok(Vec::new());
            } else {
                println!("Contract {} already verified and has vulnerabilities", contract_address);
                // In a real implementation, you would return the cached vulnerabilities
                return Ok(vec![VulnerabilityReport {
                    contract_address: contract_address.to_string(),
                    vulnerability_type: VulnerabilityType::Reentrancy,
                    severity: Severity::High,
                    description: "Cached vulnerability report".to_string(),
                    risk_score: 8,
                }]);
            }
        }
        
        // Fetch the contract bytecode
        let bytecode = self.fetch_contract_bytecode(contract_address).await?;
        
        // In test mode, we use local mock verification
        if self.config.verification_mode == "test" {
            println!("Using local test mode verification for {}", contract_address);
            
            // Test bytecode analysis would go here - for simplicity, we'll return a random result
            let has_vulnerabilities = self.mock_has_mev_vulnerability(&bytecode);
            
            // Cache the result
            self.cache_verification_result(contract_address, !has_vulnerabilities).await;
            
            if has_vulnerabilities {
                return Ok(vec![VulnerabilityReport {
                    contract_address: contract_address.to_string(),
                    vulnerability_type: VulnerabilityType::MEVVulnerability,
                    severity: Severity::Medium,
                    description: "Test mode detected potential MEV vulnerability".to_string(),
                    risk_score: 6,
                }]);
            } else {
                return Ok(Vec::new());
            }
        }
        
        // In real mode, we use the stateless VM service
        println!("Using stateless VM service for verification of {}", contract_address);
        
        // We now directly verify the contract bytecode instead of using a verification request
        
        // Fetch the contract bytecode
        let bytecode = self.fetch_contract_bytecode(contract_address).await?;
        
        // Call the stateless VM service to verify the bytecode
        let client = self.stateless_client.lock().await;
        let result = (*client).verify_bytecode(&bytecode).await?;
        
        // Process the results
        let vulnerabilities = self.convert_verification_result(result, contract_address);
        
        // Cache the result
        self.cache_verification_result(contract_address, vulnerabilities.is_empty()).await;
        
        Ok(vulnerabilities)
    }
    
    // Verify a transaction before submitting it
    pub async fn verify_transaction(
        &self,
        from: &str,
        to: &str,
        value: &str,
        data: &str,
        gas_limit: &str,
        gas_price: &str,
    ) -> Result<bool, SendError> {
        // Check if verification is enabled
        if self.config.verification_mode == "disabled" {
            return Ok(true); // Skip verification if disabled
        }
        
        // If verification is set to contract-only mode and we have a cached result, use it
        if self.config.verification_mode == "contract-only" && self.config.cache_verification_results {
            if let Some(cached_result) = self.get_cached_verification(to).await {
                return Ok(cached_result);
            }
        }
        
        // Create a transaction request for the stateless VM
        let tx_request = self.create_stateless_tx_request(
            from,
            to,
            value,
            data,
            gas_limit,
            gas_price,
        );
        
        // Execute the transaction in the stateless VM
        let client = self.stateless_client.lock().await;
        let response = (*client).execute_transaction(tx_request).await?;
        
        // Check if the transaction is safe based on security verification
        let is_safe = if let Some(verification) = response.security_verification {
            let passed = verification.passed && verification.risk_score <= self.config.max_risk_score;
            
            // Log details about the verification result
            if !passed {
                println!("Transaction verification failed: risk_score={}, max_allowed={}", 
                         verification.risk_score, self.config.max_risk_score);
                if let Some(warnings) = verification.warnings {
                    for warning in warnings {
                        println!("Security warning: {} (severity: {})", warning.message, warning.severity);
                    }
                }
            }
            
            passed
        } else {
            // If no security verification was performed, use the transaction status
            response.status == "success"
        };
        
        // Cache the result if caching is enabled
        if self.config.cache_verification_results {
            self.cache_verification_result(to, is_safe).await;
        }
        
        Ok(is_safe)
    }
    
    // Get cached verification result if available
    pub async fn get_cached_verification(&self, _contract_address: &str) -> Option<bool> {
        // In a real implementation, this would check a cache or database
        None
    }
    
    // Cache verification result
    pub async fn cache_verification_result(&self, contract_address: &str, is_safe: bool) {
        // In a real implementation, this would update a cache or database
        println!("Caching verification result for {}: {}", contract_address, is_safe);
    }
    
    // Helper method to fetch contract bytecode from the blockchain
    pub async fn fetch_contract_bytecode(&self, contract_address: &str) -> Result<Vec<u8>, SendError> {
        // Use the StatelessVmClient to fetch the bytecode
        let client = self.stateless_client.lock().await;
        let bytecode = (*client).fetch_bytecode(contract_address).await?;
        
        if bytecode.is_empty() {
            return Err(format!("No bytecode found for contract: {}", contract_address).into());
        }
        
        Ok(bytecode)
    }
    
    // Create a transaction request for the stateless VM
    fn create_stateless_tx_request(
        &self,
        from: &str,
        to: &str,
        value: &str,
        data: &str,
        gas_limit: &str,
        gas_price: &str,
    ) -> crate::statelessvm::client::StatelessTxRequest {
        // Create security verification config based on current settings
        let security_verification = SecurityVerificationRequest {
            address: to.to_string(), // Use the target contract address
            enabled: self.config.verification_mode != "disabled",
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
        };
        
        crate::statelessvm::client::StatelessTxRequest {
            from: from.to_string(),
            to: to.to_string(),
            value: value.to_string(),
            data: data.to_string(),
            gas_limit: gas_limit.to_string(),
            gas_price: gas_price.to_string(),
            security_verification,
            bundle_id: Some(format!("verify-{}", uuid::Uuid::new_v4())),
        }
    }
    
    // Convert the stateless VM verification result to our internal format
    fn convert_verification_result(
        &self,
        result: SecurityVerificationResult,
        contract_address: &str,
    ) -> Vec<VulnerabilityReport> {
        let mut vulnerabilities = Vec::new();
        
        // Only process warnings if they exist
        if let Some(warnings) = &result.warnings {
            for warning in warnings {
                // Map warning type to vulnerability type
                let vulnerability_type = match warning.warning_type.as_str() {
                    "Reentrancy" => VulnerabilityType::Reentrancy,
                    "IntegerUnderflow" => VulnerabilityType::IntegerUnderflow,
                    "UncheckedCalls" => VulnerabilityType::AccessControl,
                    "MEVVulnerability" => VulnerabilityType::MEVVulnerability,
                    "CrossContractReentrancy" => VulnerabilityType::CrossContractReentrancy,
                    "GasGriefing" => VulnerabilityType::GasGriefing,
                    "UninitializedStorage" => VulnerabilityType::UninitializedStorage,
                    _ => VulnerabilityType::AccessControl, // Default case
                };
                
                // Map severity string to our enum
                let severity = match warning.severity.as_str() {
                    "Low" => Severity::Low,
                    "Medium" => Severity::Medium,
                    "High" => Severity::High,
                    "Critical" => Severity::Critical,
                    _ => Severity::Medium, // Default case
                };
                
                // Estimate risk score based on severity
                let risk_score = match severity {
                    Severity::Low => 3,
                    Severity::Medium => 5,
                    Severity::High => 8,
                    Severity::Critical => 10,
                };
                
                vulnerabilities.push(VulnerabilityReport {
                    contract_address: contract_address.to_string(),
                    vulnerability_type,
                    severity,
                    description: warning.description.clone(),
                    risk_score,
                });
            }
        }
        
        vulnerabilities
    }
    
    // Mock function for test mode - in reality, this would be a real bytecode analyzer
    fn mock_has_mev_vulnerability(&self, _bytecode: &Vec<u8>) -> bool {
        // In a real implementation, this would use your MEV vulnerability detection from EVM-Verify
        // As mentioned in your memory about the MEV Vulnerability Circuit
        false
    }
}
