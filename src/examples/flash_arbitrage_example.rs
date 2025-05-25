use crate::statelessvm::client::{StatelessVmClient, ExecutionContext, StatelessSequenceRequest};
use crate::models::error::{AgentError, AgentResult};
use ethers::types::U256;
use std::time::{SystemTime, UNIX_EPOCH};

/// This example demonstrates a flash loan arbitrage executed as an atomic multi-step transaction.
/// The example simulates:
/// 1. Flash loan borrowing from a lending protocol
/// 2. Buying a token at a lower price on DEX A
/// 3. Selling the token at a higher price on DEX B
/// 4. Repaying the flash loan with interest
///
/// All steps must execute successfully as a single atomic transaction or the entire sequence reverts.
pub async fn run_flash_arbitrage_example() -> AgentResult<()> {
    println!("Running flash arbitrage example...");
    
    // Check if we're in production mode
    let production_mode = std::env::var("PRODUCTION_MODE").unwrap_or_default() == "true";
    
    // Initialize the StatelessVM client - use direct mode for real trading
    let avalanche_rpc_url = "https://api.avax.network/ext/bc/C/rpc";
    let client = if production_mode {
        println!("PRODUCTION MODE: Using direct RPC mode for real trading on Avalanche C-Chain");
        StatelessVmClient::new_direct(avalanche_rpc_url)
    } else {
        println!("SIMULATION MODE: Using StatelessVM service for transaction simulation");
        StatelessVmClient::new("http://localhost:7547")
    };
    
    // Flash loan parameters for Avalanche C-Chain
    let flash_loan_provider = "0x794a61358D6845594F94dc1DB02A252b5b4814aD"; // Aave V3 Pool on Avalanche
    let usdc_token = "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E"; // USDC token on Avalanche
    let wavax_token = "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7"; // WAVAX token on Avalanche
    let weth_token = "0x49D5c2BdFfac6CE2BFdB6640F4F80f226bc10bAB"; // WETH.e token on Avalanche
    let dex_a = "0x60aE616a2155Ee3d9A68541Ba4544862310933d4"; // TraderJoe router on Avalanche
    let dex_b = "0xE54Ca86531e17Ef3616d22Ca28b0D458b6C89106"; // Pangolin router on Avalanche
    let trader_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"; // Our trader address
    
    // Flash loan amount (1000 USDC)
    let loan_amount = U256::from(1000000000); // 1000 USDC with 6 decimals
    let loan_fee = U256::from(900000); // 0.09% fee (900 USDC)
    let repay_amount = loan_amount + loan_fee;
    
    // Token amount for the trade (simplified for example)
    let eth_buy_amount = U256::from_dec_str("500000000000000000").unwrap(); // 0.5 ETH
    
    // Create the flash loan borrow transaction
    let borrow_tx = format!(
        "0x{}{}{}{}",
        "ab9c4b5d", // Example function selector for flashLoan
        pad_u256(loan_amount),
        pad_address(usdc_token),
        pad_address(trader_address) // Sender address is usually in the call data for the receiver
    );
    
    // Create the buy transaction on DEX A
    let buy_tx = format!(
        "0x{}{}{}{}{}",
        "38ed1739", // Example function selector for swapExactTokensForTokens
        pad_u256(loan_amount),
        pad_u256(eth_buy_amount),
        pad_address(usdc_token),
        pad_address(weth_token)
    );
    
    // Create the sell transaction on DEX B
    let sell_tx = format!(
        "0x{}{}{}{}{}",
        "38ed1739", // Example function selector for swapExactTokensForTokens
        pad_u256(eth_buy_amount),
        pad_u256(repay_amount), // We need at least this much to repay
        pad_address(weth_token),
        pad_address(usdc_token)
    );
    
    // Create the flash loan repay transaction
    let repay_tx = format!(
        "0x{}{}{}",
        "7eea2251", // Example function selector for repayFlashLoan
        pad_u256(repay_amount),
        pad_address(usdc_token)
    );
    
    // Print formatted transactions for debugging
    println!("Formatted transaction 1 (Borrow): {} (length: {})", borrow_tx, borrow_tx.len());
    println!("Formatted transaction 2 (Buy): {} (length: {})", buy_tx, buy_tx.len());
    println!("Formatted transaction 3 (Sell): {} (length: {})", sell_tx, sell_tx.len());
    println!("Formatted transaction 4 (Repay): {} (length: {})", repay_tx, repay_tx.len());
    
    // Create a sequence ID using current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    
    let sequence_id = format!("flash_arb_{}", timestamp);
    
    // Create execution context for Avalanche C-Chain
    let context = ExecutionContext {
        chain_id: 43114, // Avalanche C-Chain ID
        block_number: None,
        timestamp,
        metadata: serde_json::Value::Null,
    };
    
    // Create the sequence request
    let sequence_request = StatelessSequenceRequest {
        sequence_id: sequence_id.clone(),
        transactions: vec![borrow_tx, buy_tx, sell_tx, repay_tx],
        fallback_plans: None,
        market_conditions: None,
        mev_protection: None,
        state_verification: None,
        execution_context: context,
        timeout_seconds: 60,
        atomic: true, // This is critical for flash loans - must be atomic!
        bundle_id: Some(format!("bundle_{}", timestamp)),
    };
    
    println!("Executing a sequence of 4 transactions...");
    println!("\nNote: This example simulates a flash arbitrage transaction on Avalanche C-Chain. In production,");
    println!("you would need to connect to a real Avalanche node and ensure the following:");
    println!("1. You have access to a flash loan provider");
    println!("2. There is an actual arbitrage opportunity between DEXes");
    println!("3. The transaction is submitted with proper MEV protection");
    println!("4. EVM-Verify security checks are run on all involved contracts\n");
    
    // Execute the sequence
    match client.execute_sequence(sequence_request).await {
        Ok(response) => {
            println!("Sequence execution complete:");
            println!("  Sequence ID: {}", response.sequence_id);
            println!("  Success: {}", response.success);
            println!("  Transaction statuses:");
            
            for (i, status) in response.transaction_statuses.iter().enumerate() {
                println!("    Transaction #{}: ID={}, Success={}, Gas={}", 
                    i + 1, 
                    status.tx_hash, 
                    status.success, 
                    status.gas_used);
                
                if let Some(error) = &status.error {
                    println!("    Error: {}", error);
                }
            }
            
            println!("  Total gas used: {}", response.gas_used);
            println!("  Execution time: {} ms", response.execution_time_ms);
            
            if let Some(market_state) = &response.market_state {
                println!("  Market state at execution:");
                println!("    Gas price: {} wei", market_state.gas_price);
                println!("    Timestamp: {}", market_state.timestamp);
                
                if !market_state.prices.is_empty() {
                    println!("    Prices:");
                    for (token, price) in &market_state.prices {
                        println!("      {}: ${}", token, price);
                    }
                }
            }
            
            // The profit would be any USDC remaining after repaying the flash loan
            println!("\nFlash arbitrage execution complete. In a real scenario, profit would be any USDC remaining after repayment.");
            println!("Typical flash arbitrage profit ranges from 0.1% to 1% of the borrowed amount.");
            println!("In this example, a profitable trade would net approximately $1-$10 on a $1000 flash loan.");
            println!("\nBenefits of flash arbitrage using StatelessVM:");
            println!("1. Atomic execution - all steps succeed or all revert");
            println!("2. No upfront capital required beyond gas fees");
            println!("3. Risk-free if implemented correctly (only gas costs at risk)");
            println!("4. Can be combined with MEV protection to prevent frontrunning");
            
            Ok(())
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(AgentError::from(e))
        }
    }
}

// Helper function to pad U256 to the proper format
fn pad_u256(value: U256) -> String {
    // Format to 64-character hex string without 0x prefix
    format!("{:064x}", value)
}

// Helper function to pad address to the proper format
fn pad_address(address: &str) -> String {
    // Remove 0x prefix if present and pad to 64 characters (32 bytes)
    // Ethereum addresses are 20 bytes, so we need to pad with 12 bytes of zeros
    let addr = address.trim_start_matches("0x");
    format!("{:0>64}", addr)
}
