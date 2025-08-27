const { ethers } = require('ethers');
const axios = require('axios');

// 🔐 Crypto Payment Verification System
class CryptoPaymentVerifier {
  constructor() {
    this.WALLET_ADDRESS = '0x15315077b2C2bA625bc0bc156415F704208FBd45';
    this.SUPPORTED_TOKENS = {
      USDC: {
        ETH: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
        POLYGON: '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174',
        BSC: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d'
      },
      USDT: {
        ETH: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
        POLYGON: '0xc2132D05D31c914a87C6611C10748AEb04B58e8F',
        BSC: '0x55d398326f99059fF775485246999027B3197955'
      }
    };
    
    this.RPC_ENDPOINTS = {
      ETH: 'https://mainnet.infura.io/v3/YOUR_INFURA_KEY',
      POLYGON: 'https://polygon-rpc.com',
      BSC: 'https://bsc-dataseed.binance.org'
    };
    
    this.TIER_PRICES = {
      PERSONAL: 29,
      STARTUP: 1500,
      BUSINESS: 8500,
      ENTERPRISE: 45000,
      GLOBAL_SCALE: 180000,
      INSTITUTIONAL: 500000
    };
    
    this.activeSubscriptions = new Map();
  }

  // Verify payment on blockchain
  async verifyPayment(clientId, txHash, network, token, tier) {
    try {
      const provider = new ethers.providers.JsonRpcProvider(this.RPC_ENDPOINTS[network]);
      const tx = await provider.getTransaction(txHash);
      
      if (!tx || tx.to.toLowerCase() !== this.WALLET_ADDRESS.toLowerCase()) {
        return { success: false, error: 'Invalid transaction' };
      }
      
      // Decode token transfer
      const tokenAddress = this.SUPPORTED_TOKENS[token][network];
      if (!tokenAddress) {
        return { success: false, error: 'Unsupported token/network combination' };
      }
      
      // Verify amount matches tier price
      const expectedAmount = this.TIER_PRICES[tier];
      const decimals = token === 'USDC' ? 6 : 18;
      const expectedWei = ethers.utils.parseUnits(expectedAmount.toString(), decimals);
      
      // Create token contract instance
      const tokenContract = new ethers.Contract(tokenAddress, [
        'function decimals() view returns (uint8)',
        'function balanceOf(address) view returns (uint256)',
        'event Transfer(address indexed from, address indexed to, uint256 value)'
      ], provider);
      
      // Get transfer events from transaction
      const receipt = await provider.getTransactionReceipt(txHash);
      const transferEvents = receipt.logs.filter(log => 
        log.address.toLowerCase() === tokenAddress.toLowerCase()
      );
      
      if (transferEvents.length === 0) {
        return { success: false, error: 'No token transfer found' };
      }
      
      // Parse transfer event
      const transferEvent = tokenContract.interface.parseLog(transferEvents[0]);
      const amount = transferEvent.args.value;
      
      if (!amount.eq(expectedWei)) {
        return { success: false, error: `Invalid amount. Expected ${expectedAmount} ${token}` };
      }
      
      // Payment verified! Activate subscription
      const subscription = {
        clientId,
        tier,
        txHash,
        network,
        token,
        amount: expectedAmount,
        startDate: new Date(),
        endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        status: 'ACTIVE'
      };
      
      this.activeSubscriptions.set(clientId, subscription);
      await this.storeSubscription(subscription);
      
      return { 
        success: true, 
        subscription,
        message: `✅ Payment verified! ${tier} tier activated for 30 days.`
      };
      
    } catch (error) {
      console.error('Payment verification error:', error);
      return { success: false, error: error.message };
    }
  }
  
  // Check subscription status
  async checkSubscription(clientId) {
    const subscription = this.activeSubscriptions.get(clientId);
    
    if (!subscription) {
      // Try loading from database
      const stored = await this.loadSubscription(clientId);
      if (stored) {
        this.activeSubscriptions.set(clientId, stored);
        return stored;
      }
      return null;
    }
    
    // Check if expired
    if (new Date() > subscription.endDate) {
      subscription.status = 'EXPIRED';
      this.activeSubscriptions.set(clientId, subscription);
    }
    
    return subscription;
  }
  
  // Get tier limits
  getTierLimits(tier) {
    const limits = {
      PERSONAL: { users: 1, queries: 5000, apis: 10 },
      STARTUP: { users: 100, queries: 50000, apis: 100 },
      BUSINESS: { users: 1000, queries: 200000, apis: 500 },
      ENTERPRISE: { users: 10000, queries: 1000000, apis: -1 },
      GLOBAL_SCALE: { users: 50000, queries: -1, apis: -1 },
      INSTITUTIONAL: { users: -1, queries: -1, apis: -1 }
    };
    
    return limits[tier] || { users: 0, queries: 0, apis: 0 };
  }
  
  // Monitor blockchain for new payments
  async startPaymentMonitoring() {
    console.log('🔍 Starting blockchain payment monitoring...');
    
    for (const [network, rpcUrl] of Object.entries(this.RPC_ENDPOINTS)) {
      const provider = new ethers.providers.JsonRpcProvider(rpcUrl);
      
      // Monitor our wallet for incoming transfers
      provider.on('block', async (blockNumber) => {
        const block = await provider.getBlockWithTransactions(blockNumber);
        
        for (const tx of block.transactions) {
          if (tx.to && tx.to.toLowerCase() === this.WALLET_ADDRESS.toLowerCase()) {
            console.log(`💰 Incoming transaction detected on ${network}: ${tx.hash}`);
            // Auto-process payment
            await this.processIncomingPayment(tx, network);
          }
        }
      });
    }
  }
  
  // Process incoming payment automatically
  async processIncomingPayment(tx, network) {
    // Extract client ID from transaction data or memo
    // In production, this would come from payment gateway integration
    const clientId = await this.extractClientIdFromTx(tx);
    
    if (clientId) {
      // Try each tier to find matching amount
      for (const [tier, price] of Object.entries(this.TIER_PRICES)) {
        const result = await this.verifyPayment(clientId, tx.hash, network, 'USDC', tier);
        if (result.success) {
          console.log(`✅ Auto-activated ${tier} subscription for client ${clientId}`);
          break;
        }
      }
    }
  }
  
  // Database operations
  async storeSubscription(subscription) {
    // Store in SQLite for persistence
    const db = require('./smartcache').db;
    return new Promise((resolve, reject) => {
      db.run(`
        CREATE TABLE IF NOT EXISTS subscriptions (
          client_id TEXT PRIMARY KEY,
          tier TEXT,
          tx_hash TEXT,
          network TEXT,
          token TEXT,
          amount REAL,
          start_date INTEGER,
          end_date INTEGER,
          status TEXT
        )
      `, () => {
        db.run(`
          INSERT OR REPLACE INTO subscriptions 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          subscription.clientId,
          subscription.tier,
          subscription.txHash,
          subscription.network,
          subscription.token,
          subscription.amount,
          subscription.startDate.getTime(),
          subscription.endDate.getTime(),
          subscription.status
        ], err => err ? reject(err) : resolve());
      });
    });
  }
  
  async loadSubscription(clientId) {
    const db = require('./smartcache').db;
    return new Promise((resolve, reject) => {
      db.get(`
        SELECT * FROM subscriptions WHERE client_id = ?
      `, [clientId], (err, row) => {
        if (err) reject(err);
        else if (row) {
          resolve({
            clientId: row.client_id,
            tier: row.tier,
            txHash: row.tx_hash,
            network: row.network,
            token: row.token,
            amount: row.amount,
            startDate: new Date(row.start_date),
            endDate: new Date(row.end_date),
            status: row.status
          });
        } else resolve(null);
      });
    });
  }
  
  extractClientIdFromTx(tx) {
    // In production, extract from transaction data field
    // For now, mock implementation
    return tx.from ? tx.from.substring(0, 8) : null;
  }
}

module.exports = new CryptoPaymentVerifier();