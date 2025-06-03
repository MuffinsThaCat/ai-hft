use crate::relay::types::*;
use ethers::types::{Transaction, H256, U256, U64};
use ring::aead::{Aad, LessSafeKey, UnboundKey, AES_256_GCM, Nonce, SealingKey, OpeningKey};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::{Arc, Mutex};
use log::{debug, error};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Service for encrypting and decrypting transaction data
pub struct EncryptionService {
    /// Encryption key
    key: LessSafeKey,
    /// Random number generator
    rng: SystemRandom,
    /// Nonce counter for ensuring uniqueness
    nonce_counter: Arc<Mutex<u64>>,
}

/// Transaction data for encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransactionData {
    pub to: Option<String>,
    pub from: Option<String>,
    pub nonce: Option<String>,
    pub value: String,
    pub gas: String,
    pub gas_price: String,
    pub data: String,
    pub chain_id: Option<u64>,
}

impl EncryptionService {
    /// Create a new encryption service with the given key
    pub fn new(key_hex: &str) -> Result<Self, RelayError> {
        // Convert hex key to bytes
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| format!("Invalid encryption key format: {}", e))?;
            
        if key_bytes.len() != 32 {
            return Err(format!("Encryption key must be 32 bytes (64 hex characters), got {} bytes", key_bytes.len()).into());
        }
        
        // Create encryption key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|_| "Failed to create encryption key")?;
        let key = LessSafeKey::new(unbound_key);
        
        Ok(Self {
            key,
            rng: SystemRandom::new(),
            nonce_counter: Arc::new(Mutex::new(0)),
        })
    }
    
    /// Encrypt a transaction
    pub fn encrypt_transaction(&self, tx: &Transaction) -> Result<EncryptedTransaction, RelayError> {
        // Create transaction data for encryption
        let tx_data = TransactionData {
            to: tx.to.map(|addr| format!("{:?}", addr)),
            from: Some(format!("{:?}", tx.from)),
            nonce: Some(format!("{:?}", tx.nonce)),
            value: format!("{:?}", tx.value),
            gas: format!("{:?}", tx.gas),
            gas_price: format!("{:?}", tx.gas_price),
            data: hex::encode(&tx.input),
            chain_id: tx.chain_id.map(|id| id.as_u64()),
        };
        
        // Serialize to JSON
        let mut serialized = serde_json::to_vec(&tx_data)
            .map_err(|e| format!("Failed to serialize transaction: {}", e))?;
            
        // Generate a unique nonce
        let nonce = self.generate_nonce()?;
        
        // Encrypt the data
        // Create an empty AAD (Additional Authenticated Data)
        let aad = ring::aead::Aad::empty();
        
        // Encrypt the data
        self.key.seal_in_place_append_tag(nonce, aad, &mut serialized)
            .map_err(|_| "Encryption failed")?;
        
        // Now serialized contains the encrypted data with tag appended
            
        // Create public metadata
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        let metadata = TransactionMetadata {
            gas_limit: tx.gas.as_u64(),
            gas_price: tx.gas_price.unwrap_or_default(),
            priority_fee: None, // EIP-1559 not used in this example
            value: tx.value,
            size_bytes: tx.input.len(),
            expires_at: now + 300, // 5 minute expiration
        };
        
        Ok(EncryptedTransaction {
            encrypted_data: serialized,
            public_metadata: metadata,
            sender: Some(tx.from),
            nonce: Some(tx.nonce),
        })
    }
    
    /// Decrypt transaction data
    pub fn decrypt_transaction(&self, encrypted: &EncryptedTransaction) -> Result<Transaction, RelayError> {
        // We need to extract the nonce from the first 12 bytes of the encrypted data
        if encrypted.encrypted_data.len() < 12 {
            return Err("Invalid encrypted data: too short".into());
        }
        
        // Extract the nonce (first 12 bytes) from the ciphertext
        let nonce = Nonce::try_assume_unique_for_key(&encrypted.encrypted_data[0..12])
            .map_err(|_| "Failed to extract nonce from encrypted data")?;
            
        // Clone the encrypted data for decryption (excluding the nonce)
        let mut encrypted_data = encrypted.encrypted_data[12..].to_vec();
        
        // Decrypt the data
        // Create an empty AAD (Additional Authenticated Data)
        let aad = ring::aead::Aad::empty();
        
        // Decrypt the data
        let decrypted = self.key.open_in_place(nonce, aad, &mut encrypted_data)
            .map_err(|_| "Decryption failed: invalid ciphertext or tag")?;
            
        // Deserialize the JSON data
        let tx_data: TransactionData = serde_json::from_slice(decrypted)
            .map_err(|e| format!("Failed to deserialize transaction data: {}", e))?;
            
        // Convert TransactionData back to Transaction
        let to_addr = if let Some(to_str) = &tx_data.to {
            // Parse the address string, removing the "0x" prefix if present
            let to_str = to_str.trim_start_matches("0x");
            Some(to_str.parse()
                .map_err(|e| format!("Failed to parse 'to' address: {}", e))?)
        } else {
            None
        };
        
        let from_addr = if let Some(from_str) = &tx_data.from {
            // Parse the address string, removing the "0x" prefix if present
            let from_str = from_str.trim_start_matches("0x");
            Some(from_str.parse()
                .map_err(|e| format!("Failed to parse 'from' address: {}", e))?)
        } else {
            None
        };
        
        let nonce = if let Some(nonce_str) = &tx_data.nonce {
            // Parse the nonce value
            Some(nonce_str.parse::<U256>()
                .map_err(|e| format!("Failed to parse nonce: {}", e))?)
        } else {
            None
        };
        
        // Parse value, gas and gas_price from strings
        let value = tx_data.value.parse::<U256>()
            .map_err(|e| format!("Failed to parse value: {}", e))?;
            
        let gas = tx_data.gas.parse::<U256>()
            .map_err(|e| format!("Failed to parse gas: {}", e))?;
            
        let gas_price = tx_data.gas_price.parse::<U256>()
            .map_err(|e| format!("Failed to parse gas_price: {}", e))?;
            
        // Decode transaction data from hex
        let input = hex::decode(&tx_data.data)
            .map_err(|e| format!("Failed to decode transaction data: {}", e))?;
            
        // Create and return the Transaction object
        Ok(Transaction {
            hash: H256::zero(), // Hash will be computed when the transaction is submitted
            nonce: nonce.unwrap_or_default(),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: from_addr.unwrap_or_default(),
            to: to_addr,
            value,
            gas_price: Some(gas_price),
            gas,
            input: input.into(),
            v: U64::zero(), // Initialize with zero, will be set during signing
            r: U256::zero(), // Initialize with zero, will be set during signing
            s: U256::zero(), // Initialize with zero, will be set during signing
            transaction_type: None,
            access_list: None,
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            chain_id: tx_data.chain_id.map(|id| U256::from(id)),
            other: Default::default(), // Add missing 'other' field
        })
    }
    
    /// Generate a unique nonce for encryption
    fn generate_nonce(&self) -> Result<Nonce, RelayError> {
        let mut nonce_bytes = [0u8; 12]; // AES-GCM uses 12-byte nonces
        
        // Get current counter value and increment
        let counter = {
            let mut counter = self.nonce_counter.lock().unwrap();
            let current = *counter;
            *counter = current.wrapping_add(1);
            current
        };
        
        // First 8 bytes are counter, last 4 are random
        nonce_bytes[0..8].copy_from_slice(&counter.to_le_bytes());
        self.rng.fill(&mut nonce_bytes[8..12])
            .map_err(|_| "Failed to generate random bytes for nonce")?;
            
        Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| "Failed to create nonce".into())
    }
}
