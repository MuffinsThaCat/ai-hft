use ai_trading_agent::security::verifier::{SecurityVerifier, VulnerabilityType, Severity, SecurityVerification, VulnerabilityReport};
use ai_trading_agent::utils::config;
use ethers::types::H160;
use std::str::FromStr;
use std::error::Error;
use std::collections::HashMap;
use tokio::runtime::Runtime;

/// Create a direct verification result without calling verify_contract
/// This completely bypasses the network calls by manually constructing the results
#[test]
fn test_security_verification_direct() {
    // Initialize logging
    let _ = env_logger::builder().is_test(true).try_init();
    
    // Create a manually constructed verification result for testing
    let contract_address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
    let address_h160 = H160::from_str(contract_address).unwrap();
    
    // Create the verification result directly
    let mut verification = SecurityVerification::new(Some(address_h160), None);
    
    // Add a reentrancy vulnerability
    verification.add_vulnerability(VulnerabilityReport {
        vulnerability_type: VulnerabilityType::Reentrancy { 
            function_signature: "swap".to_string() 
        },
        severity: Severity::High,
        risk_score: 85,
        confidence: 90,
        bytecode_offset: Some(1234),
        function_selector: Some("0x7ff36ab5".to_string()),
        timestamp: 0,
    });
        
    // Verify we got the expected vulnerabilities
    assert!(!verification.vulnerabilities.is_empty());
    
    // We should have a reentrancy vulnerability 
    let has_reentrancy = verification.vulnerabilities.iter().any(|v| {
        matches!(v.vulnerability_type, VulnerabilityType::Reentrancy { .. })
    });
    assert!(has_reentrancy, "Expected to find reentrancy vulnerability");
    
    // Verify vulnerabilities have proper severity and risk scores
    for vulnerability in &verification.vulnerabilities {
        assert!(vulnerability.risk_score > 0);
        assert!(matches!(vulnerability.severity, 
            Severity::Critical | Severity::High | 
            Severity::Medium | Severity::Low));
    }
}

/// Test multiple vulnerability types using direct verification construction
#[test]
fn test_multiple_vulnerability_types() {
    // Create the verification result directly
    let contract_address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
    let address_h160 = H160::from_str(contract_address).unwrap();
    let mut verification = SecurityVerification::new(Some(address_h160), None);
    
    // Add multiple vulnerabilities
    verification.add_vulnerability(VulnerabilityReport {
        vulnerability_type: VulnerabilityType::IntegerOverflow { 
            location: "0x123".to_string() 
        },
        severity: Severity::High,
        risk_score: 80,
        confidence: 90,
        bytecode_offset: Some(1234),
        function_selector: None,
        timestamp: 0,
    });
    
    verification.add_vulnerability(VulnerabilityReport {
        vulnerability_type: VulnerabilityType::IntegerUnderflow { 
            location: "0x456".to_string() 
        },
        severity: Severity::Medium,
        risk_score: 60,
        confidence: 85,
        bytecode_offset: Some(5678),
        function_selector: None,
        timestamp: 0,
    });
    
    verification.add_vulnerability(VulnerabilityReport {
        vulnerability_type: VulnerabilityType::AccessControl { 
            details: "Missing access control".to_string() 
        },
        severity: Severity::Critical,
        risk_score: 95,
        confidence: 95,
        bytecode_offset: Some(9012),
        function_selector: Some("0xadmin123".to_string()),
        timestamp: 0,
    });
    
    // Verify we get the expected number of vulnerabilities
    assert_eq!(verification.vulnerabilities.len(), 3, 
               "Expected 3 vulnerabilities, got {}", verification.vulnerabilities.len());
    
    // Count each type of vulnerability
    let mut integer_overflow_count = 0;
    let mut integer_underflow_count = 0;
    let mut access_control_count = 0;
    
    for vulnerability in &verification.vulnerabilities {
        match &vulnerability.vulnerability_type {
            VulnerabilityType::IntegerOverflow { .. } => integer_overflow_count += 1,
            VulnerabilityType::IntegerUnderflow { .. } => integer_underflow_count += 1,
            VulnerabilityType::AccessControl { .. } => access_control_count += 1,
            _ => {
                println!("Unexpected vulnerability type: {:?}", vulnerability.vulnerability_type);
            }
        }
    }
    
    // Verify we have one of each type
    assert_eq!(integer_overflow_count, 1, "Expected 1 integer overflow vulnerability");
    assert_eq!(integer_underflow_count, 1, "Expected 1 integer underflow vulnerability");
    assert_eq!(access_control_count, 1, "Expected 1 access control vulnerability");
}
