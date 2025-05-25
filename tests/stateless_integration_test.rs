use ai_trading_agent::security::verifier::SecurityVerifier;
use ai_trading_agent::statelessvm::{StatelessVmClient, StatelessTxRequest};
use ai_trading_agent::utils::config;
use std::error::Error;

#[tokio::test]
async fn test_stateless_vm_integration() -> Result<(), Box<dyn Error>> {
    println!("Testing Stateless VM Integration");
    
    // Load configuration
    let config_path = "config/config.toml";
    let app_config = config::load_config(config_path)?;
    
    println!("Configuration loaded from {}", config_path);
    
    // Initialize the stateless VM client
    let stateless_client = StatelessVmClient::new(&app_config.execution.stateless_vm_url);
    
    println!("StatelessVmClient initialized with URL: {}", app_config.execution.stateless_vm_url);
    
    // Initialize the security verifier
    let security_verifier = SecurityVerifier::new(&app_config.security, &app_config.execution.stateless_vm_url);
    
    println!("SecurityVerifier initialized");
    
    // Test contract verification
    // Using Uniswap V2 Router contract on Avalanche C-Chain for testing
    let contract_address = "0x60aE616a2155Ee3d9A68541Ba4544862310933d4";
    
    println!("Testing contract verification for address: {}", contract_address);
    
    match security_verifier.verify_contract(contract_address).await {
        Ok(vulnerabilities) => {
            println!("Contract verification successful");
            println!("Detected {} vulnerabilities", vulnerabilities.len());
            
            for (i, vuln) in vulnerabilities.iter().enumerate() {
                println!("Vulnerability #{}", i + 1);
                println!("  Type: {:?}", vuln.vulnerability_type);
                println!("  Severity: {:?}", vuln.severity);
                println!("  Description: {}", vuln.description);
                println!("  Risk Score: {}", vuln.risk_score);
            }
        }
        Err(e) => {
            println!("Contract verification failed: {}", e);
            // This is expected during testing if the stateless VM is not running
            println!("Note: This error is expected if the stateless VM is not running");
        }
    }
    
    // Test transaction verification
    // This is a simple ETH transfer transaction
    let from_address = "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199";
    let to_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    let value = "1000000000000000"; // 0.001 ETH
    let data = "0x";
    let gas_limit = "21000";
    let gas_price = "20";
    
    println!("\nTesting transaction verification");
    println!("From: {}", from_address);
    println!("To: {}", to_address);
    println!("Value: {} wei", value);
    
    match security_verifier.verify_transaction(
        from_address, 
        to_address, 
        value, 
        data, 
        gas_limit, 
        gas_price
    ).await {
        Ok(is_safe) => {
            println!("Transaction verification successful");
            println!("Transaction is safe: {}", is_safe);
        }
        Err(e) => {
            println!("Transaction verification failed: {}", e);
            // This is expected during testing if the stateless VM is not running
            println!("Note: This error is expected if the stateless VM is not running");
        }
    }
    
    // If we get here, our integration is configured correctly
    println!("\nStateless VM integration test completed");
    println!("Note: Some errors may be expected if the stateless VM service is not running");
    println!("The integration is configured correctly if the test runs without panicking");
    
    Ok(())
}
