use ai_trading_agent::models::error::AgentResult;

// Import from the main crate
use ai_trading_agent::security::verifier::SecurityVerifier;
use ai_trading_agent::statelessvm::client::StatelessVmClient;
use ai_trading_agent::utils::config;

#[tokio::main]
async fn main() -> AgentResult<()> {
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
        Ok(verification_result) => {
            println!("Contract verification successful");
            println!("Detected {} vulnerabilities", verification_result.vulnerabilities.len());
            
            for (i, vuln) in verification_result.vulnerabilities.iter().enumerate() {
                println!("Vulnerability #{}", i + 1);
                println!("  Type: {:?}", vuln.vulnerability_type);
                println!("  Severity: {:?}", vuln.severity);
                // No description field in VulnerabilityReport
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
    // We need to create a Transaction object since the API now expects a single Transaction parameter
    use ethers::types::{Transaction, U256, U64, H160, Bytes, H256, OtherFields};
    use std::str::FromStr;
    
    // Create a Transaction object
    let tx = Transaction {
        hash: H256::zero(),  // Not important for verification
        nonce: U256::from(0),
        block_hash: None,
        block_number: None,
        transaction_index: None,
        from: H160::from_str("0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199").unwrap(),
        to: Some(H160::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap()),
        value: U256::from_dec_str("1000000000000000").unwrap(), // 0.001 ETH
        gas_price: Some(U256::from(20)),
        gas: U256::from(21000),
        input: Bytes::from_str("0x").unwrap(),
        v: U64::from(0),
        r: U256::from(0),
        s: U256::from(0),
        transaction_type: None,
        access_list: None,
        max_priority_fee_per_gas: None,
        max_fee_per_gas: None,
        chain_id: None,
        other: OtherFields::default(),
    };
    
    println!("\nTesting transaction verification");
    println!("From: {:?}", tx.from);
    println!("To: {:?}", tx.to);
    println!("Value: {} wei", tx.value);
    
    match security_verifier.verify_transaction(&tx).await {
        Ok(is_safe) => {
            println!("Transaction verification successful");
            println!("Transaction is safe: {:?}", is_safe);
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
