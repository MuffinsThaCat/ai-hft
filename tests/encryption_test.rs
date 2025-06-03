#[cfg(feature = "relay")]
use ai_trading_agent::relay::encryption::EncryptionService;
#[cfg(feature = "relay")]
use ai_trading_agent::relay::types::EncryptedTransaction;
#[cfg(feature = "relay")]
use ethers::types::{Transaction, H160, U256, U64, Bytes};
#[cfg(feature = "relay")]
use std::str::FromStr;

#[cfg(feature = "relay")]
#[tokio::test]
async fn test_transaction_encryption_decryption() {
    // Create a new encryption service with a test key
    let encryption_service = EncryptionService::new().expect("Failed to create encryption service");

    // Create a sample transaction
    let from_address = H160::from_str("0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199").unwrap();
    let to_address = H160::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();
    let test_tx = Transaction {
        hash: Default::default(),
        nonce: U256::from(42),
        block_hash: None,
        block_number: None,
        transaction_index: None,
        from: from_address,
        to: Some(to_address),
        value: U256::from(1000000000000000u64), // 0.001 ETH
        gas_price: Some(U256::from(20000000000u64)), // 20 gwei
        gas: U256::from(21000u64), // Standard ETH transfer gas
        input: Bytes::from(hex::decode("0x").unwrap_or_default()),
        v: U64::from(27),
        r: U256::from(1),
        s: U256::from(2),
        transaction_type: None,
        access_list: None,
        max_priority_fee_per_gas: None,
        max_fee_per_gas: None,
        chain_id: Some(U256::from(1)), // Ethereum Mainnet
        other: Default::default()
    };

    // Encrypt the transaction
    let encrypted_tx = encryption_service.encrypt_transaction(&test_tx)
        .expect("Failed to encrypt transaction");

    println!("Successfully encrypted transaction");
    println!("Encrypted data length: {} bytes", encrypted_tx.encrypted_data.len());
    
    // Verify encrypted transaction has expected fields
    assert!(!encrypted_tx.encrypted_data.is_empty(), "Encrypted data should not be empty");
    assert_eq!(encrypted_tx.sender, from_address.to_string(), "Sender address mismatch");
    
    // Decrypt the transaction
    let decrypted_tx = encryption_service.decrypt_transaction(&encrypted_tx)
        .expect("Failed to decrypt transaction");
    
    println!("Successfully decrypted transaction");
    
    // Verify decrypted transaction matches original
    assert_eq!(decrypted_tx.nonce, test_tx.nonce, "Nonce mismatch");
    assert_eq!(decrypted_tx.from, test_tx.from, "From address mismatch");
    assert_eq!(decrypted_tx.to, test_tx.to, "To address mismatch");
    assert_eq!(decrypted_tx.value, test_tx.value, "Value mismatch");
    assert_eq!(decrypted_tx.gas, test_tx.gas, "Gas mismatch");
    assert_eq!(decrypted_tx.gas_price, test_tx.gas_price, "Gas price mismatch");
    assert_eq!(decrypted_tx.input, test_tx.input, "Input data mismatch");
    assert_eq!(decrypted_tx.chain_id, test_tx.chain_id, "Chain ID mismatch");
    
    println!("Transaction encryption/decryption test passed successfully");
}

#[cfg(feature = "relay")]
#[tokio::test]
async fn test_transaction_encryption_malformed_data() {
    // Create a new encryption service with a test key
    let encryption_service = EncryptionService::new().expect("Failed to create encryption service");
    
    // Create a malformed encrypted transaction (too short)
    let malformed_encrypted_tx = EncryptedTransaction {
        encrypted_data: vec![1, 2, 3], // Too short to be valid
        sender: "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199".to_string(),
        nonce: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        metadata: Default::default(),
    };
    
    // Attempt to decrypt - should fail
    let result = encryption_service.decrypt_transaction(&malformed_encrypted_tx);
    assert!(result.is_err(), "Decryption should fail with malformed data");
    println!("Correctly rejected malformed encrypted data: {:?}", result.err());
    
    // Create a transaction with valid length but invalid content
    let invalid_content_tx = EncryptedTransaction {
        encrypted_data: vec![0; 100], // Valid length but invalid content
        sender: "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199".to_string(),
        nonce: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        metadata: Default::default(),
    };
    
    // Attempt to decrypt - should fail
    let result = encryption_service.decrypt_transaction(&invalid_content_tx);
    assert!(result.is_err(), "Decryption should fail with invalid content");
    println!("Correctly rejected invalid encrypted content: {:?}", result.err());
}
