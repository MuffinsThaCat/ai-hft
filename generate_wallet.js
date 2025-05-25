const ethers = require('ethers');
const fs = require('fs');
const path = require('path');

// Function to generate a new wallet and save keystore
async function generateWallet() {
  // Check if password is provided in environment
  const password = process.env.KEYSTORE_PASSWORD;
  if (!password) {
    console.error('Error: KEYSTORE_PASSWORD environment variable must be set');
    process.exit(1);
  }

  // Create a new random wallet
  const wallet = ethers.Wallet.createRandom();
  console.log(`Generated new wallet with address: ${wallet.address}`);
  
  // Encrypt the wallet as a keystore file
  const keystore = await wallet.encrypt(password);
  
  // Create directory if it doesn't exist
  const keystoreDir = path.join(__dirname, 'keystore');
  if (!fs.existsSync(keystoreDir)) {
    fs.mkdirSync(keystoreDir);
  }
  
  // Write keystore to file
  const keystorePath = path.join(keystoreDir, `${wallet.address}.json`);
  fs.writeFileSync(keystorePath, keystore);
  
  console.log(`Wallet private key (DO NOT SHARE): ${wallet.privateKey}`);
  console.log(`Keystore saved to: ${keystorePath}`);
  console.log('');
  console.log('IMPORTANT: Back up your private key securely!');
  console.log('To use this wallet with the trading agent, set these environment variables:');
  console.log(`KEYSTORE_PATH=${keystorePath}`);
  console.log('KEYSTORE_PASSWORD=your-secure-password');
}

// Run the function
generateWallet().catch(error => {
  console.error('Error generating wallet:', error);
  process.exit(1);
});
