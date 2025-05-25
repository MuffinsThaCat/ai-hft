use crate::statelessvm::client::{StatelessVmClient, StatelessSequenceRequest, ExecutionContext};
use crate::models::error::{AgentError, AgentResult};
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json;

pub async fn run_multi_step_transaction_example() -> AgentResult<()> {
    println!("Running multi-step transaction example...");
    
    // Create a client to the local StatelessVM server
    let client = StatelessVmClient::new("http://127.0.0.1:7545");
    
    // IMPORTANT: The server's parsing logic is:
    // 1. Extract characters 0-41 for 'from' address, then trim "0x" prefix
    // 2. Extract characters 42-83 for 'to' address, then trim "0x" prefix
    // 3. Extract characters 84+ for transaction data, then trim "0x" prefix
    // So we need to include the "0x" prefix in our formatted string
    
    // Addresses with 0x prefix
    let from_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
    let to_address = "0x388C818CA8B9251b393131C08a736A67ccB19297";
    
    // Transaction data with 0x prefix
    let tx_data1 = "0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b844bc454e4438f44e0000000000000000000000000000000000000000000000000000000000000001";
    let tx_data2 = "0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b844bc454e4438f44e0000000000000000000000000000000000000000000000000000000000000002";
    
    // Create transaction strings by concatenating in the exact format the server expects
    // The server will trim the "0x" prefix after extracting each component
    let tx1 = format!("{}{}{}", from_address, to_address, tx_data1);
    let tx2 = format!("{}{}{}", from_address, to_address, tx_data2);
    
    // Create a sequence ID using timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    
    // Create execution context
    let execution_context = ExecutionContext {
        chain_id: 1,  // Chain ID
        block_number: None,
        timestamp: timestamp as u64,  // Current timestamp as required u64
        metadata: serde_json::Value::Null,  // Empty metadata
    };
    
    // We'll create the sequence request after debugging output
    
    // Print out the exact request we're sending for debugging
    println!("Formatted transaction 1: {} (length: {})", tx1, tx1.len());
    println!("Formatted transaction 2: {} (length: {})", tx2, tx2.len());
    
    // Create the sequence request with cloned transactions to avoid moving them
    let sequence_request = StatelessSequenceRequest {
        sequence_id: format!("seq_{}", timestamp),
        transactions: vec![tx1.clone(), tx2.clone()],
        fallback_plans: None,
        market_conditions: None,
        mev_protection: None,
        state_verification: None,
        execution_context,
        timeout_seconds: 60,
        atomic: true,  // Atomic execution
        bundle_id: Some(format!("bundle_{}", timestamp)),
    };
    
    // Print out the JSON we're about to send
    let json_request = serde_json::to_string_pretty(&sequence_request).unwrap();
    println!("Sending JSON request to server:\n{}", json_request);
    
    // Execute the transaction sequence
    println!("Executing a sequence of 2 transactions...");
    let response = client.execute_sequence(sequence_request).await?;
    
    // Print the response
    println!("Sequence execution complete:");
    println!("  Sequence ID: {}", response.sequence_id);
    println!("  Success: {}", response.success);
    println!("  Transaction statuses:");
    
    for (i, status) in response.transaction_statuses.iter().enumerate() {
        println!("    Transaction #{}: ID={}, Success={}, Gas={}", 
            i+1, 
            status.tx_hash, 
            status.success, 
            status.gas_used
        );
        
        if let Some(ref error) = status.error {
            println!("      Error: {}", error);
        }
    }
    
    if let Some(error) = response.error {
        println!("  Sequence Error: {}", error);
    }
    
    Ok(())
}
