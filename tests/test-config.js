/**
 * 🧪 ENTERPRISE TEST CONFIGURATION
 * Comprehensive testing setup for enterprise security components
 */

const path = require('path');
const fs = require('fs');

// Test environment setup
process.env.NODE_ENV = 'test';
process.env.MASTER_PASSPHRASE = 'test-enterprise-passphrase-2024';
process.env.TEST_DB_PATH = './tests/test.db';

// Mock external services for testing
const mockConfig = {
  // Mock Infura endpoints for blockchain testing
  INFURA_ENDPOINTS: {
    ETH: 'http://localhost:8545', // Use local test node
    POLYGON: 'http://localhost:8546',
    BSC: 'http://localhost:8547'
  },
  
  // Mock contract addresses
  CONTRACT_ADDRESSES: {
    ETH: {
      USDC: '0xA0b86a33E6F82c4c8F2E1Bf69e6C49a6F3e0Fb58',
      USDT: '0xdAC17F958D2ee523a2206206994597C13D831ec7'
    },
    POLYGON: {
      USDC: '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174',
      USDT: '0xc2132D05D31c914a87C6611C10748AEb04B58e8F'
    },
    BSC: {
      USDC: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',
      USDT: '0x55d398326f99059fF775485246999027B3197955'
    }
  },
  
  // Test wallet addresses
  TEST_WALLET: '0x15315077b2C2bA625bc0bc156415F704208FBd45',
  
  // Rate limiting for tests (more lenient)
  RATE_LIMITS: {
    WINDOW_MS: 60000, // 1 minute
    MAX_REQUESTS: 1000, // Higher limit for tests
    DDOS_THRESHOLD: 500
  }
};

// Setup test database
async function setupTestDatabase() {
  const testDbPath = path.resolve(__dirname, 'test.db');
  
  // Clean up existing test database
  try {
    await fs.promises.unlink(testDbPath);
  } catch (error) {
    // File doesn't exist, that's fine
  }
  
  // Create tests directory if it doesn't exist
  try {
    await fs.promises.mkdir(path.dirname(testDbPath), { recursive: true });
  } catch (error) {
    // Directory exists, that's fine
  }
}

// Setup test logs directory
async function setupTestLogs() {
  const testLogsPath = path.resolve(__dirname, 'logs');
  
  try {
    await fs.promises.mkdir(testLogsPath, { recursive: true });
  } catch (error) {
    // Directory exists, that's fine
  }
}

// Mock external API responses for testing
const mockResponses = {
  // Mock successful transaction
  validTransaction: {
    hash: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    to: mockConfig.TEST_WALLET,
    from: '0x742d35Cc6575C80b8c3D3F5B4De1E99d2b8Fda4D',
    value: '0',
    data: '0xa9059cbb000000000000000000000000' + 
          mockConfig.TEST_WALLET.substring(2).toLowerCase() +
          '00000000000000000000000000000000000000000000000000000000000f4240', // 1 USDC
    blockNumber: 18500000,
    confirmations: 12
  },
  
  // Mock transaction receipt
  validReceipt: {
    status: 1,
    logs: [
      {
        address: mockConfig.CONTRACT_ADDRESSES.ETH.USDC,
        topics: [
          '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef', // Transfer event signature
          '0x000000000000000000000000742d35Cc6575C80b8c3D3F5B4De1E99d2b8Fda4D', // from
          '0x00000000000000000000000015315077b2c2ba625bc0bc156415f704208fbd45'  // to (our wallet)
        ],
        data: '0x00000000000000000000000000000000000000000000000000000000000f4240' // 1 USDC
      }
    ]
  }
};

// Test data generators
class TestDataGenerator {
  static generateClientId() {
    return `test_client_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }
  
  static generateTxHash() {
    return '0x' + require('crypto').randomBytes(32).toString('hex');
  }
  
  static generateWalletAddress() {
    return '0x' + require('crypto').randomBytes(20).toString('hex');
  }
  
  static generateApiKey() {
    return 'sk-test-' + require('crypto').randomBytes(32).toString('hex');
  }
  
  static generateSubscriptionData(overrides = {}) {
    return {
      client_id: this.generateClientId(),
      tier: 'BUSINESS',
      api_key: this.generateApiKey(),
      wallet_address: this.generateWalletAddress(),
      usage_limits: {
        daily: 10000,
        monthly: 300000
      },
      ...overrides
    };
  }
  
  static generatePaymentData(overrides = {}) {
    return {
      client_id: this.generateClientId(),
      tx_hash: this.generateTxHash(),
      network: 'ETH',
      token: 'USDC',
      tier: 'BUSINESS',
      amount: '199000000', // 199 USDC in microunits
      ...overrides
    };
  }
}

// Test utilities
class TestUtils {
  static async sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  static async waitForCondition(conditionFn, timeout = 5000, interval = 100) {
    const start = Date.now();
    
    while (Date.now() - start < timeout) {
      if (await conditionFn()) {
        return true;
      }
      await this.sleep(interval);
    }
    
    throw new Error(`Condition not met within ${timeout}ms`);
  }
  
  static generateLargePayload(sizeInBytes) {
    return require('crypto').randomBytes(sizeInBytes).toString('hex');
  }
  
  static async measureExecutionTime(asyncFn) {
    const start = process.hrtime.bigint();
    const result = await asyncFn();
    const end = process.hrtime.bigint();
    const duration = Number(end - start) / 1000000; // Convert to milliseconds
    
    return { result, duration };
  }
}

// Security test helpers
class SecurityTestHelpers {
  static async attemptSQLInjection(database, testPayloads) {
    const results = [];
    
    for (const payload of testPayloads) {
      try {
        // Attempt various SQL injection vectors
        await database.executeQuery(
          'SELECT * FROM secure_subscriptions WHERE client_id = ?',
          [payload]
        );
        results.push({ payload, vulnerable: false });
      } catch (error) {
        // Error is expected for malicious payloads
        results.push({ payload, vulnerable: false, error: error.message });
      }
    }
    
    return results;
  }
  
  static generateXSSPayloads() {
    return [
      '<script>alert("xss")</script>',
      '"><script>alert("xss")</script>',
      "';alert('xss');//",
      'javascript:alert("xss")',
      '<img src=x onerror=alert("xss")>',
      '<svg onload=alert("xss")>',
      '${alert("xss")}',
      '{{constructor.constructor("alert(\"xss\")")()}}'
    ];
  }
  
  static generateSQLInjectionPayloads() {
    return [
      "'; DROP TABLE secure_subscriptions; --",
      "' OR '1'='1",
      "'; INSERT INTO secure_subscriptions VALUES ('hacked'); --",
      "' UNION SELECT * FROM secure_api_keys --",
      "'; UPDATE secure_subscriptions SET tier='INSTITUTIONAL' WHERE client_id='attacker'; --",
      "' OR 1=1 --",
      "'; DELETE FROM secure_subscriptions; --",
      "' OR EXISTS(SELECT * FROM secure_subscriptions) --"
    ];
  }
  
  static async testTimingAttack(encryptionFn, correctInput, wrongInputs, iterations = 100) {
    const measurements = {
      correct: [],
      wrong: []
    };
    
    // Warm up
    for (let i = 0; i < 10; i++) {
      await encryptionFn(correctInput);
      await encryptionFn(wrongInputs[0]);
    }
    
    // Measure correct input
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      try {
        await encryptionFn(correctInput);
      } catch (e) { /* Expected */ }
      const end = process.hrtime.bigint();
      measurements.correct.push(Number(end - start));
    }
    
    // Measure wrong inputs
    for (const wrongInput of wrongInputs) {
      for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        try {
          await encryptionFn(wrongInput);
        } catch (e) { /* Expected */ }
        const end = process.hrtime.bigint();
        measurements.wrong.push(Number(end - start));
      }
    }
    
    // Calculate statistics
    const avgCorrect = measurements.correct.reduce((a, b) => a + b) / measurements.correct.length;
    const avgWrong = measurements.wrong.reduce((a, b) => a + b) / measurements.wrong.length;
    
    return {
      avgCorrect,
      avgWrong,
      timingRatio: Math.max(avgCorrect, avgWrong) / Math.min(avgCorrect, avgWrong),
      vulnerable: Math.abs(avgCorrect - avgWrong) > (Math.min(avgCorrect, avgWrong) * 0.1) // 10% threshold
    };
  }
}

// Performance test utilities
class PerformanceTestUtils {
  static async loadTest(fn, concurrency, duration) {
    const results = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      errors: [],
      averageResponseTime: 0,
      minResponseTime: Infinity,
      maxResponseTime: 0,
      responseTimes: []
    };
    
    const startTime = Date.now();
    const endTime = startTime + duration;
    
    const workers = [];
    
    for (let i = 0; i < concurrency; i++) {
      workers.push(this._worker(fn, endTime, results));
    }
    
    await Promise.all(workers);
    
    // Calculate statistics
    if (results.responseTimes.length > 0) {
      results.averageResponseTime = results.responseTimes.reduce((a, b) => a + b) / results.responseTimes.length;
      results.minResponseTime = Math.min(...results.responseTimes);
      results.maxResponseTime = Math.max(...results.responseTimes);
      
      // Calculate percentiles
      const sorted = results.responseTimes.sort((a, b) => a - b);
      results.p50 = sorted[Math.floor(sorted.length * 0.5)];
      results.p95 = sorted[Math.floor(sorted.length * 0.95)];
      results.p99 = sorted[Math.floor(sorted.length * 0.99)];
    }
    
    return results;
  }
  
  static async _worker(fn, endTime, results) {
    while (Date.now() < endTime) {
      const start = process.hrtime.bigint();
      
      try {
        await fn();
        results.successfulRequests++;
        
        const duration = Number(process.hrtime.bigint() - start) / 1000000;
        results.responseTimes.push(duration);
      } catch (error) {
        results.failedRequests++;
        results.errors.push(error.message);
      }
      
      results.totalRequests++;
    }
  }
}

// Initialize test environment
async function initializeTestEnvironment() {
  await setupTestDatabase();
  await setupTestLogs();
  
  // Set global test configuration
  global.TEST_CONFIG = mockConfig;
  global.TEST_RESPONSES = mockResponses;
  global.TestDataGenerator = TestDataGenerator;
  global.TestUtils = TestUtils;
  global.SecurityTestHelpers = SecurityTestHelpers;
  global.PerformanceTestUtils = PerformanceTestUtils;
  
  console.log('🧪 Enterprise test environment initialized');
}

module.exports = {
  mockConfig,
  mockResponses,
  TestDataGenerator,
  TestUtils,
  SecurityTestHelpers,
  PerformanceTestUtils,
  initializeTestEnvironment
};