const ethers = require('ethers');
const fs = require('fs');
const path = require('path');

// Create a random wallet
const wallet = ethers.Wallet.createRandom();
console.log('Generated test wallet address:', wallet.address);
console.log('Private key:', wallet.privateKey);

// Encrypt the wallet with a simple password
const password = 'testpassword';
async function encrypt() {
    const json = await wallet.encrypt(password);
    const keystorePath = path.join(__dirname, 'keystore', 'test-wallet.json');
    fs.writeFileSync(keystorePath, json);
    console.log('Keystore saved to:', keystorePath);
    console.log('Password:', password);
}

encrypt();
