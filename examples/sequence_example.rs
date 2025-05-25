use ai_trading_agent::statelessvm::{StatelessVmClient, StatelessTxRequest, SecurityVerificationRequest};
use std::error::Error;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize the StatelessVM client
    let stateless_vm_url = env::var("STATELESS_VM_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let client = StatelessVmClient::new(&stateless_vm_url);
    
    println!("Connecting to StatelessVM at: {}", stateless_vm_url);
    
    // Security verification configuration (same for all transactions)
    let security_config = SecurityVerificationRequest {
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
    
    // Example sender and receiver addresses
    let sender = "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199";
    let receiver = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    
    // Sample transaction data (in this case, a token transfer)
    let tx_data = "0xa9059cbb000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000003b9aca00"; // Transfer 1 token
    
    // Create transaction 1 (hex-encoded for sequence)
    let tx1 = StatelessTxRequest {
        from: sender.to_string(),
        to: receiver.to_string(),
        value: "0".to_string(),
        data: tx_data.to_string(),
        gas_limit: "100000".to_string(),
        gas_price: "10000000000".to_string(),
        security_verification: security_config.clone(),
    };
    
    // Create transaction 2 (similar but with different amount)
    let tx2 = StatelessTxRequest {
        from: sender.to_string(),
        to: receiver.to_string(),
        value: "0".to_string(),
        data: "0xa9059cbb000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000001dcd6500".to_string(), // Transfer 0.5 token
        gas_limit: "100000".to_string(),
        gas_price: "10000000000".to_string(),
        security_verification: security_config.clone(),
    };
    
    // Convert transactions to hex strings (in a real application, you'd use proper encoding)
    // This is just a simplified example - in production, use proper RLP encoding
    let tx1_hex = serde_json::to_string(&tx1).unwrap();
    let tx2_hex = serde_json::to_string(&tx2).unwrap();
    
    // Chain ID for Ethereum mainnet
    let chain_id = 1;
    
    // Execute the transactions as an atomic sequence
    println!("Executing atomic transaction sequence...");
    match client.execute_atomic_sequence(vec![tx1_hex, tx2_hex], chain_id).await {
        Ok(result) => {
            println!("Sequence execution result: {}", if result.success { "SUCCESS" } else { "FAILED" });
            println!("Sequence ID: {}", result.sequence_id);
            
            println!("\nTransaction statuses:");
            for (i, status) in result.transaction_statuses.iter().enumerate() {
                println!("  Transaction {}: {}", i + 1, if status.success { "SUCCESS" } else { "FAILED" });
                println!("    TX Hash: {}", status.tx_hash);
                println!("    Gas Used: {}", status.gas_used);
                if let Some(ref error) = status.error {
                    println!("    Error: {}", error);
                }
            }
            
            if let Some(market_state) = result.market_state {
                println!("\nMarket State:");
                println!("  Gas Price: {}", market_state.gas_price);
                println!("  Block Number: {}", market_state.block_number);
                println!("  Network Congestion: {}/10", market_state.network_congestion);
            }
            
            if result.fallback_executed {
                println!("\nFallback plan was executed!");
                if let Some(ref fallback_results) = result.fallback_results {
                    for result in fallback_results {
                        println!("  Fallback Plan ID: {}", result.plan_id);
                        println!("  Description: {}", result.description);
                        println!("  Success: {}", result.success);
                    }
                }
            }
        },
        Err(e) => {
            println!("Failed to execute transaction sequence: {}", e);
        }
    }
    
    Ok(())
}
