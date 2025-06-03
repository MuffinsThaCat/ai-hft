use ai_trading_agent::security::verifier::{SecurityVerifier, VerificationMode, VulnerabilityType, Severity, SecurityVerification};
use ai_trading_agent::utils::config::SecurityConfig;
use ai_trading_agent::StatelessVmClient;
use ethers::types::Transaction;
use std::sync::Arc;
use std::error::Error;

/// Test the tiered verification modes in the security verifier
/// This test ensures that each verification mode applies the correct checks
#[tokio::test]
async fn test_tiered_verification_modes() -> Result<(), Box<dyn Error>> {
    // Create a security verifier in test mode
    let mut security_config = SecurityConfig::default();
    // Enable test mode in verifier directly (no test_mode field in SecurityConfig)
    
    let mut security_verifier = SecurityVerifier::new_with_test_mode(&security_config);
    
    // Configure specific vulnerabilities for testing different modes
    security_verifier.set_test_vulnerabilities(vec![
        VulnerabilityType::Reentrancy { function_signature: "Critical vulnerability".to_string() },
        VulnerabilityType::IntegerOverflow { location: "Medium severity".to_string() },
        VulnerabilityType::UncheckedCalls { details: "Low severity".to_string() },
        VulnerabilityType::MEV { details: "MEV-specific vulnerability".to_string() },
    ]);
    
    // Create a dummy transaction for testing
    let tx = Transaction {
        nonce: Default::default(),
        gas_price: Some(Default::default()),
        gas: Default::default(),
        to: None,
        value: Default::default(),
        input: Default::default(),
        v: Default::default(),
        r: Default::default(),
        s: Default::default(),
        hash: Default::default(),
        chain_id: None,
        access_list: None,
        max_priority_fee_per_gas: None,
        max_fee_per_gas: None,
        transaction_type: None,
        block_hash: None,
        block_number: None,
        transaction_index: None,
        from: Default::default(),
        other: Default::default(),
    };
    
    // Test MinimalLatency mode - should only check for critical vulnerabilities
    println!("Testing MinimalLatency mode...");
    let minimal_result = security_verifier.verify_transaction_with_mode(&tx, VerificationMode::MinimalLatency).await?;
    
    // Should detect Reentrancy (critical) but not others
    assert!(minimal_result.vulnerabilities.iter().any(|v| matches!(v.vulnerability_type, VulnerabilityType::Reentrancy { .. })));
    assert!(!minimal_result.vulnerabilities.iter().any(|v| matches!(v.vulnerability_type, VulnerabilityType::IntegerOverflow { .. })));
    assert!(!minimal_result.vulnerabilities.iter().any(|v| matches!(v.vulnerability_type, VulnerabilityType::UncheckedCalls { .. })));
    println!("MinimalLatency mode detected {} vulnerabilities", minimal_result.vulnerabilities.len());
    
    // Test MEVFocused mode - should check for MEV vulnerabilities and critical ones
    println!("Testing MEVFocused mode...");
    let mev_result = security_verifier.verify_transaction_with_mode(&tx, VerificationMode::MEVFocused).await?;
    
    // Should detect Reentrancy (critical) and MEV but not others
    assert!(mev_result.vulnerabilities.iter().any(|v| matches!(v.vulnerability_type, VulnerabilityType::Reentrancy { .. })));
    assert!(mev_result.vulnerabilities.iter().any(|v| matches!(v.vulnerability_type, VulnerabilityType::MEV { .. })));
    assert!(!mev_result.vulnerabilities.iter().any(|v| matches!(v.vulnerability_type, VulnerabilityType::UncheckedCalls { .. })));
    println!("MEVFocused mode detected {} vulnerabilities", mev_result.vulnerabilities.len());
    
    // Test Complete mode - should check for all vulnerabilities
    println!("Testing Complete mode...");
    let complete_result = security_verifier.verify_transaction_with_mode(&tx, VerificationMode::Complete).await?;
    
    // Should detect all vulnerabilities
    assert!(complete_result.vulnerabilities.iter().any(|v| matches!(v.vulnerability_type, VulnerabilityType::Reentrancy { .. })));
    assert!(complete_result.vulnerabilities.iter().any(|v| matches!(v.vulnerability_type, VulnerabilityType::IntegerOverflow { .. })));
    assert!(complete_result.vulnerabilities.iter().any(|v| matches!(v.vulnerability_type, VulnerabilityType::UncheckedCalls { .. })));
    assert!(complete_result.vulnerabilities.iter().any(|v| matches!(v.vulnerability_type, VulnerabilityType::MEV { .. })));
    println!("Complete mode detected {} vulnerabilities", complete_result.vulnerabilities.len());
    
    // Test Cached mode - should initially be the same as Complete but faster on second call
    println!("Testing Cached mode...");
    let start = std::time::Instant::now();
    let first_cached = security_verifier.verify_transaction_with_mode(&tx, VerificationMode::Cached(tx.hash.to_string())).await?;
    let first_duration = start.elapsed();
    
    let start = std::time::Instant::now();
    let second_cached = security_verifier.verify_transaction_with_mode(&tx, VerificationMode::Cached(tx.hash.to_string())).await?;
    let second_duration = start.elapsed();
    
    // Should have the same vulnerabilities as Complete mode
    assert_eq!(first_cached.vulnerabilities.len(), complete_result.vulnerabilities.len());
    assert_eq!(second_cached.vulnerabilities.len(), complete_result.vulnerabilities.len());
    
    // Second call should be faster due to caching
    println!("First Cached call took: {:?}", first_duration);
    println!("Second Cached call took: {:?}", second_duration);
    assert!(second_duration < first_duration, "Cached mode should be faster on second call");
    
    // Verify that second cached result indicates it was a cache hit
    assert!(second_cached.from_cache, "Second cached result should indicate a cache hit");
    
    Ok(())
}
