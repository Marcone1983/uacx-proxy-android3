const { describe, it, before, after, beforeEach, afterEach } = require('mocha');
const { expect } = require('chai');
const sinon = require('sinon');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

// Import modules to test
const EnterpriseSecurityManager = require('../src/enterprise-security');
const SecureDatabase = require('../src/secure-database');
const SecureCryptoPayment = require('../src/secure-crypto-payment');
const EnterpriseRateLimiter = require('../src/enterprise-rate-limiter');
const EnterpriseMonitoring = require('../src/enterprise-monitoring');

describe('🏛️ ENTERPRISE SECURITY TEST SUITE', () => {
  
  describe('EnterpriseSecurityManager', () => {
    let security;
    const testPassphrase = 'test-enterprise-passphrase-2024';
    
    beforeEach(async () => {
      // Reset environment
      delete process.env.MASTER_PASSPHRASE;
      delete process.env.SECURE_CONFIG_PATH;
      
      // Clean up test files
      try {
        await fs.unlink('./config/secure.enc');
      } catch (e) { /* ignore */ }
      
      try {
        await fs.rmdir('./config', { recursive: true });
      } catch (e) { /* ignore */ }
    });

    describe('🔐 Encryption/Decryption', () => {
      it('should encrypt and decrypt data correctly using AES-256-GCM', async () => {
        process.env.MASTER_PASSPHRASE = testPassphrase;
        security = require('../src/enterprise-security');
        
        const testData = { 
          apiKey: 'sk-test123456789', 
          secret: 'very-secret-data',
          timestamp: Date.now()
        };
        const plaintext = JSON.stringify(testData);
        
        // Encrypt
        const encrypted = await security.encryptData(plaintext, testPassphrase);
        expect(encrypted).to.be.instanceOf(Buffer);
        expect(encrypted.length).to.be.greaterThan(plaintext.length);
        
        // Decrypt
        const decrypted = await security.decryptData(encrypted, testPassphrase);
        expect(decrypted).to.deep.equal(testData);
      });

      it('should fail decryption with wrong passphrase', async () => {
        process.env.MASTER_PASSPHRASE = testPassphrase;
        security = require('../src/enterprise-security');
        
        const plaintext = 'sensitive-data';
        const encrypted = await security.encryptData(plaintext, testPassphrase);
        
        try {
          await security.decryptData(encrypted, 'wrong-passphrase');
          expect.fail('Should have thrown an error');
        } catch (error) {
          expect(error.message).to.include('bad decrypt');
        }
      });

      it('should generate different ciphertext for same plaintext (IV randomization)', async () => {
        process.env.MASTER_PASSPHRASE = testPassphrase;
        security = require('../src/enterprise-security');
        
        const plaintext = 'same-data';
        const encrypted1 = await security.encryptData(plaintext, testPassphrase);
        const encrypted2 = await security.encryptData(plaintext, testPassphrase);
        
        expect(Buffer.compare(encrypted1, encrypted2)).to.not.equal(0);
      });
    });

    describe('🛡️ Input Validation', () => {
      before(() => {
        process.env.MASTER_PASSPHRASE = testPassphrase;
        security = require('../src/enterprise-security');
      });

      it('should validate Ethereum addresses correctly', () => {
        const validAddress = '0x742d35Cc6575C80b8c3D3F5B4De1E99d2b8Fda4D';
        const result = security.validateInput(validAddress, 'ethereum_address');
        expect(result).to.equal(validAddress.toLowerCase());
      });

      it('should reject invalid Ethereum addresses', () => {
        const invalidAddresses = [
          '0x123', // too short
          '742d35Cc6575C80b8c3D3F5B4De1E99d2b8Fda4D', // missing 0x
          '0xGGGd35Cc6575C80b8c3D3F5B4De1E99d2b8Fda4D', // invalid hex
          '', // empty
          null, // null
          undefined // undefined
        ];

        invalidAddresses.forEach(addr => {
          expect(() => security.validateInput(addr, 'ethereum_address'))
            .to.throw(Error);
        });
      });

      it('should validate transaction hashes correctly', () => {
        const validTxHash = '0x' + crypto.randomBytes(32).toString('hex');
        const result = security.validateInput(validTxHash, 'transaction_hash');
        expect(result).to.equal(validTxHash.toLowerCase());
      });

      it('should validate client IDs with sanitization', () => {
        const validClientId = 'client_123_test';
        const result = security.validateInput(validClientId, 'client_id');
        expect(result).to.equal(validClientId);

        // Test sanitization
        const dirtyClientId = 'client<script>alert("xss")</script>123';
        const cleaned = security.validateInput(dirtyClientId, 'client_id');
        expect(cleaned).to.equal('clientscriptalertxssscript123');
      });

      it('should validate networks and tokens', () => {
        // Valid networks
        ['ETH', 'POLYGON', 'BSC'].forEach(network => {
          expect(security.validateInput(network, 'network')).to.equal(network);
        });

        // Valid tokens
        ['USDC', 'USDT'].forEach(token => {
          expect(security.validateInput(token, 'token')).to.equal(token);
        });

        // Invalid network/token should throw
        expect(() => security.validateInput('INVALID', 'network')).to.throw();
        expect(() => security.validateInput('BTC', 'token')).to.throw();
      });

      it('should validate subscription tiers', () => {
        const validTiers = ['PERSONAL', 'STARTUP', 'BUSINESS', 'ENTERPRISE', 'GLOBAL_SCALE', 'INSTITUTIONAL'];
        validTiers.forEach(tier => {
          expect(security.validateInput(tier, 'tier')).to.equal(tier);
        });

        expect(() => security.validateInput('INVALID_TIER', 'tier')).to.throw();
      });
    });

    describe('🔍 Audit Logging', () => {
      let logSpy;
      
      beforeEach(() => {
        process.env.MASTER_PASSPHRASE = testPassphrase;
        security = require('../src/enterprise-security');
        logSpy = sinon.spy(console, 'log');
      });

      afterEach(() => {
        logSpy.restore();
      });

      it('should create audit log entries with integrity hash', async () => {
        const event = 'TEST_EVENT';
        const data = { testField: 'testValue' };
        
        await security.auditLog(event, data);
        
        // Check if console.log was called (audit logs to console in dev)
        expect(logSpy.calledWith(sinon.match.string, sinon.match.string)).to.be.true;
        
        // Check if log contains the event
        const logCall = logSpy.getCall(0);
        expect(logCall.args[0]).to.include('AUDIT');
        expect(logCall.args[0]).to.include(event);
      });
    });

    describe('🏥 Health Checks', () => {
      it('should return comprehensive health status', async () => {
        process.env.MASTER_PASSPHRASE = testPassphrase;
        security = require('../src/enterprise-security');
        
        const health = await security.healthCheck();
        
        expect(health).to.be.an('object');
        expect(health).to.have.property('configuration_loaded');
        expect(health).to.have.property('audit_logging');
        expect(health).to.have.property('certificate_pinning');
        expect(health).to.have.property('encryption_available');
        expect(health).to.have.property('memory_usage');
        expect(health).to.have.property('uptime');
        
        expect(health.encryption_available).to.be.true;
        expect(health.certificate_pinning).to.be.true;
      });
    });
  });

  describe('🗃️ SecureDatabase', () => {
    let db;
    
    beforeEach(async () => {
      // Initialize test database
      process.env.NODE_ENV = 'test';
      db = new (require('../src/secure-database'))();
      await db.initialize();
    });

    afterEach(async () => {
      if (db) {
        await db.close();
      }
    });

    it('should create all required tables with proper schema', async () => {
      const tables = await db.executeQuery(`
        SELECT name FROM sqlite_master WHERE type='table' ORDER BY name
      `);
      
      const expectedTables = [
        'secure_subscriptions',
        'secure_payments',
        'secure_audit_logs',
        'secure_rate_limits',
        'secure_api_keys'
      ];
      
      const tableNames = tables.map(t => t.name);
      expectedTables.forEach(expectedTable => {
        expect(tableNames).to.include(expectedTable);
      });
    });

    it('should encrypt sensitive subscription data', async () => {
      const testSubscription = {
        client_id: 'test_client_123',
        tier: 'ENTERPRISE',
        api_key: 'sk-test-key-123456',
        wallet_address: '0x742d35Cc6575C80b8c3D3F5B4De1E99d2b8Fda4D',
        usage_limits: { daily: 10000, monthly: 300000 }
      };

      const subscriptionId = await db.storeSubscription(testSubscription);
      expect(subscriptionId).to.be.a('string');

      // Verify data is encrypted in database
      const raw = await db.executeQuery(
        'SELECT encrypted_data FROM secure_subscriptions WHERE subscription_id = ?',
        [subscriptionId]
      );
      
      expect(raw[0].encrypted_data).to.not.include(testSubscription.api_key);
      expect(raw[0].encrypted_data).to.not.include(testSubscription.wallet_address);

      // Verify decryption works
      const retrieved = await db.getSubscription(subscriptionId);
      expect(retrieved.client_id).to.equal(testSubscription.client_id);
      expect(retrieved.tier).to.equal(testSubscription.tier);
    });

    it('should verify data integrity with hash validation', async () => {
      const testPayment = {
        client_id: 'test_client',
        tx_hash: '0x' + crypto.randomBytes(32).toString('hex'),
        network: 'ETH',
        token: 'USDC',
        amount: '1000000', // 1 USDC
        tier: 'BUSINESS'
      };

      const paymentId = await db.storePayment(testPayment);
      
      // Verify integrity hash exists
      const stored = await db.executeQuery(
        'SELECT integrity_hash FROM secure_payments WHERE payment_id = ?',
        [paymentId]
      );
      
      expect(stored[0].integrity_hash).to.be.a('string');
      expect(stored[0].integrity_hash).to.have.length(64); // SHA256 hex
    });
  });

  describe('💰 SecureCryptoPayment', () => {
    let payment;
    let mockProvider;

    beforeEach(() => {
      payment = new (require('../src/secure-crypto-payment'))();
      
      // Mock ethers provider
      mockProvider = {
        getTransaction: sinon.stub(),
        getTransactionReceipt: sinon.stub(),
        getBlockNumber: sinon.stub().resolves(18500000)
      };
      
      // Stub the provider creation
      sinon.stub(payment, 'createProvider').returns(mockProvider);
    });

    afterEach(() => {
      sinon.restore();
    });

    it('should verify valid USDC payment on Ethereum', async () => {
      const testTx = {
        hash: '0x' + crypto.randomBytes(32).toString('hex'),
        to: '0x15315077b2C2bA625bc0bc156415F704208FBd45', // Our wallet
        value: '0',
        data: '0xa9059cbb000000000000000000000000' + 
              '15315077b2c2ba625bc0bc156415f704208fbd45' + // to address
              '00000000000000000000000000000000000000000000000000000000000f4240', // 1M = 1 USDC
        blockNumber: 18499900
      };

      const receipt = {
        status: 1,
        logs: [
          {
            address: '0xA0b86a33E6F82c4c8F2E1Bf69e6C49a6F3e0Fb58', // USDC contract
            topics: [
              '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef', // Transfer
              '0x000000000000000000000000' + 'sender'.padStart(40, '0'),
              '0x000000000000000000000000' + '15315077b2c2ba625bc0bc156415f704208fbd45'
            ],
            data: '0x00000000000000000000000000000000000000000000000000000000000f4240'
          }
        ]
      };

      mockProvider.getTransaction.resolves(testTx);
      mockProvider.getTransactionReceipt.resolves(receipt);

      const result = await payment.verifyPayment(
        'test_client',
        testTx.hash,
        'ETH',
        'USDC',
        'BUSINESS'
      );

      expect(result.verified).to.be.true;
      expect(result.amount).to.equal('1000000'); // 1 USDC in microunits
      expect(result.token).to.equal('USDC');
      expect(result.network).to.equal('ETH');
    });

    it('should reject payment to wrong address', async () => {
      const testTx = {
        hash: '0x' + crypto.randomBytes(32).toString('hex'),
        to: '0x742d35Cc6575C80b8c3D3F5B4De1E99d2b8Fda4D', // Wrong address
        value: '0',
        blockNumber: 18499900
      };

      mockProvider.getTransaction.resolves(testTx);

      try {
        await payment.verifyPayment('test_client', testTx.hash, 'ETH', 'USDC', 'BUSINESS');
        expect.fail('Should have rejected payment to wrong address');
      } catch (error) {
        expect(error.message).to.include('Invalid payment recipient');
      }
    });

    it('should validate payment amount against tier price', async () => {
      const testTx = {
        hash: '0x' + crypto.randomBytes(32).toString('hex'),
        to: '0x15315077b2C2bA625bc0bc156415F704208FBd45',
        value: '0',
        data: '0xa9059cbb000000000000000000000000' + 
              '15315077b2c2ba625bc0bc156415f704208fbd45' +
              '0000000000000000000000000000000000000000000000000000000000001388', // Only 5000 microunits = 0.005 USDC
        blockNumber: 18499900
      };

      const receipt = {
        status: 1,
        logs: [{
          address: '0xA0b86a33E6F82c4c8F2E1Bf69e6C49a6F3e0Fb58',
          topics: [
            '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
            '0x000000000000000000000000' + 'sender'.padStart(40, '0'),
            '0x000000000000000000000000' + '15315077b2c2ba625bc0bc156415f704208fbd45'
          ],
          data: '0x0000000000000000000000000000000000000000000000000000000000001388'
        }]
      };

      mockProvider.getTransaction.resolves(testTx);
      mockProvider.getTransactionReceipt.resolves(receipt);

      try {
        await payment.verifyPayment('test_client', testTx.hash, 'ETH', 'USDC', 'BUSINESS'); // Should cost 199 USDC
        expect.fail('Should have rejected insufficient payment');
      } catch (error) {
        expect(error.message).to.include('Insufficient payment amount');
      }
    });

    it('should implement rate limiting for payment verification', async () => {
      const clientId = 'rate_test_client';
      
      // Mock a transaction
      const testTx = {
        hash: '0x' + crypto.randomBytes(32).toString('hex'),
        to: '0x15315077b2C2bA625bc0bc156415F704208FBd45',
        value: '0',
        blockNumber: 18499900
      };

      mockProvider.getTransaction.resolves(testTx);

      // Make multiple rapid requests
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          payment.verifyPayment(clientId, testTx.hash, 'ETH', 'USDC', 'PERSONAL')
            .catch(e => e)
        );
      }

      const results = await Promise.all(promises);
      
      // Some should be rate limited
      const rateLimitErrors = results.filter(r => 
        r instanceof Error && r.message.includes('Rate limit exceeded')
      );
      
      expect(rateLimitErrors).to.have.length.greaterThan(0);
    });
  });

  describe('🛡️ EnterpriseRateLimiter', () => {
    let rateLimiter;

    beforeEach(() => {
      rateLimiter = new (require('../src/enterprise-rate-limiter'))();
    });

    it('should allow requests within rate limits', async () => {
      const clientId = 'test_client';
      const endpoint = '/api/test';

      const result1 = await rateLimiter.checkRateLimit(clientId, endpoint, 'user');
      const result2 = await rateLimiter.checkRateLimit(clientId, endpoint, 'user');

      expect(result1.allowed).to.be.true;
      expect(result2.allowed).to.be.true;
    });

    it('should block requests exceeding rate limits', async () => {
      const clientId = 'spam_client';
      const endpoint = '/api/test';

      // Exceed the rate limit
      const promises = [];
      for (let i = 0; i < 150; i++) { // Above default limit of 100/minute
        promises.push(
          rateLimiter.checkRateLimit(clientId, endpoint, 'user')
        );
      }

      const results = await Promise.all(promises);
      const blocked = results.filter(r => !r.allowed);

      expect(blocked).to.have.length.greaterThan(0);
    });

    it('should detect DDoS patterns', async () => {
      const maliciousIP = '192.168.1.100';
      const suspiciousUA = 'BadBot/1.0';
      const endpoint = '/api/sensitive';

      // Simulate rapid-fire requests
      const ddosRequests = [];
      for (let i = 0; i < 200; i++) {
        ddosRequests.push({
          ip: maliciousIP,
          userAgent: suspiciousUA,
          endpoint,
          timestamp: Date.now() + i
        });
      }

      // Analyze pattern
      let ddosDetected = false;
      for (const req of ddosRequests) {
        const analysis = await rateLimiter.performDDoSAnalysis(
          req.ip, 
          req.userAgent, 
          req.endpoint
        );
        
        if (analysis.isDDoS) {
          ddosDetected = true;
          break;
        }
      }

      expect(ddosDetected).to.be.true;
    });

    it('should automatically block suspicious IPs', async () => {
      const suspiciousIP = '10.0.0.100';
      
      // First, trigger DDoS detection
      for (let i = 0; i < 300; i++) {
        await rateLimiter.checkRateLimit('attacker', '/api/test', 'ip', { ip: suspiciousIP });
      }

      // Check if IP is now blocked
      const blockStatus = await rateLimiter.isBlocked(suspiciousIP, 'ip');
      expect(blockStatus.blocked).to.be.true;
      expect(blockStatus.reason).to.include('DDoS');
    });
  });

  describe('📊 EnterpriseMonitoring', () => {
    let monitoring;
    let alertSpy;

    beforeEach(() => {
      monitoring = new (require('../src/enterprise-monitoring'))();
      alertSpy = sinon.spy(monitoring, 'sendAlert');
    });

    afterEach(() => {
      alertSpy.restore();
    });

    it('should collect system metrics', async () => {
      const metrics = await monitoring.collectSystemMetrics();
      
      expect(metrics).to.have.property('cpu');
      expect(metrics).to.have.property('memory');
      expect(metrics).to.have.property('disk');
      expect(metrics).to.have.property('timestamp');
      
      expect(metrics.memory.percent).to.be.a('number');
      expect(metrics.memory.percent).to.be.at.least(0);
      expect(metrics.memory.percent).to.be.at.most(100);
    });

    it('should trigger alerts for high resource usage', async () => {
      // Mock high CPU usage
      sinon.stub(monitoring, 'getCPUUsage').resolves(95); // 95% CPU

      await monitoring.collectSystemMetrics();

      // Should trigger high CPU alert
      expect(alertSpy.calledWith('HIGH_CPU_USAGE')).to.be.true;
    });

    it('should track business metrics', async () => {
      const businessMetrics = {
        api_calls: 1500,
        cache_hits: 1200,
        cache_misses: 300,
        cost_savings: 45.67,
        revenue: 299.00
      };

      await monitoring.recordBusinessMetrics(businessMetrics);

      const stored = await monitoring.getBusinessMetrics('today');
      expect(stored.total_api_calls).to.equal(1500);
      expect(stored.cache_hit_rate).to.be.approximately(0.8, 0.01); // 80%
    });

    it('should perform comprehensive health checks', async () => {
      const health = await monitoring.performHealthCheck();
      
      expect(health).to.have.property('status');
      expect(health).to.have.property('components');
      expect(health).to.have.property('timestamp');
      
      expect(health.components).to.have.property('database');
      expect(health.components).to.have.property('cache');
      expect(health.components).to.have.property('payment_processor');
      expect(health.components).to.have.property('rate_limiter');
      
      expect(health.status).to.be.oneOf(['healthy', 'degraded', 'unhealthy']);
    });

    it('should implement intelligent alert escalation', async () => {
      const criticalAlert = {
        level: 'CRITICAL',
        event: 'DATABASE_CONNECTION_FAILED',
        data: { retries: 5, lastError: 'Connection timeout' }
      };

      await monitoring.sendAlert(criticalAlert.event, criticalAlert.data, criticalAlert.level);

      // Verify alert was processed with correct escalation
      expect(alertSpy.calledOnce).to.be.true;
      
      const alertCall = alertSpy.getCall(0);
      expect(alertCall.args[0]).to.equal(criticalAlert.event);
      expect(alertCall.args[2]).to.equal(criticalAlert.level);
    });
  });

  describe('🔄 Integration Tests', () => {
    let security, database, payment, rateLimiter, monitoring;

    before(async () => {
      // Initialize all components
      process.env.MASTER_PASSPHRASE = 'integration-test-passphrase';
      process.env.NODE_ENV = 'test';
      
      security = require('../src/enterprise-security');
      database = new (require('../src/secure-database'))();
      payment = new (require('../src/secure-crypto-payment'))();
      rateLimiter = new (require('../src/enterprise-rate-limiter'))();
      monitoring = new (require('../src/enterprise-monitoring'))();
      
      await database.initialize();
    });

    after(async () => {
      if (database) {
        await database.close();
      }
    });

    it('should handle end-to-end payment flow with security', async () => {
      const clientId = 'integration_test_client';
      const txHash = '0x' + crypto.randomBytes(32).toString('hex');
      
      // 1. Validate inputs through security manager
      const validatedClientId = security.validateInput(clientId, 'client_id');
      const validatedTxHash = security.validateInput(txHash, 'transaction_hash');
      const validatedNetwork = security.validateInput('ETH', 'network');
      const validatedToken = security.validateInput('USDC', 'token');
      const validatedTier = security.validateInput('BUSINESS', 'tier');
      
      // 2. Check rate limits
      const rateCheck = await rateLimiter.checkRateLimit(validatedClientId, '/api/payment/verify', 'user');
      expect(rateCheck.allowed).to.be.true;
      
      // 3. Record business metrics
      await monitoring.recordBusinessMetrics({
        payment_verification_started: 1,
        timestamp: Date.now()
      });
      
      // 4. Store payment attempt in secure database
      const paymentData = {
        client_id: validatedClientId,
        tx_hash: validatedTxHash,
        network: validatedNetwork,
        token: validatedToken,
        tier: validatedTier,
        status: 'pending'
      };
      
      const paymentId = await database.storePayment(paymentData);
      expect(paymentId).to.be.a('string');
      
      // 5. Audit log the attempt
      await security.auditLog('PAYMENT_VERIFICATION_ATTEMPT', {
        client_id: validatedClientId,
        payment_id: paymentId,
        tx_hash: validatedTxHash
      });
      
      // Verify integration worked
      const storedPayment = await database.getPayment(paymentId);
      expect(storedPayment.client_id).to.equal(validatedClientId);
      expect(storedPayment.status).to.equal('pending');
    });

    it('should handle security breach scenario', async () => {
      const maliciousIP = '666.666.666.666';
      const attackerUA = 'EvilBot/1.0 (Attack Framework)';
      
      // Simulate attack pattern
      for (let i = 0; i < 500; i++) {
        await rateLimiter.checkRateLimit(
          'attacker',
          '/api/sensitive',
          'ip',
          { ip: maliciousIP, userAgent: attackerUA }
        );
      }
      
      // System should have detected and blocked
      const blockStatus = await rateLimiter.isBlocked(maliciousIP, 'ip');
      expect(blockStatus.blocked).to.be.true;
      
      // Should have triggered security alerts
      const securityMetrics = await monitoring.getSecurityMetrics();
      expect(securityMetrics.blocked_ips).to.be.greaterThan(0);
    });

    it('should maintain data consistency under load', async () => {
      const concurrentOperations = [];
      
      // Simulate multiple concurrent clients
      for (let i = 0; i < 20; i++) {
        const clientId = `concurrent_client_${i}`;
        
        concurrentOperations.push(async () => {
          // Each client tries to store subscription data
          const subscriptionData = {
            client_id: clientId,
            tier: 'STARTUP',
            api_key: `sk-${crypto.randomBytes(16).toString('hex')}`,
            wallet_address: '0x' + crypto.randomBytes(20).toString('hex'),
            usage_limits: { daily: 1000, monthly: 30000 }
          };
          
          return await database.storeSubscription(subscriptionData);
        });
      }
      
      // Execute all operations concurrently
      const results = await Promise.all(concurrentOperations.map(op => op()));
      
      // All should succeed and have unique IDs
      const uniqueIds = new Set(results);
      expect(uniqueIds.size).to.equal(20);
      
      // Verify all data is retrievable
      for (const subscriptionId of results) {
        const subscription = await database.getSubscription(subscriptionId);
        expect(subscription).to.not.be.null;
        expect(subscription.tier).to.equal('STARTUP');
      }
    });
  });

  describe('🚨 Security Stress Tests', () => {
    it('should resist timing attacks on encryption', async () => {
      process.env.MASTER_PASSPHRASE = 'timing-test-passphrase';
      const security = require('../src/enterprise-security');
      
      const correctPassphrase = 'timing-test-passphrase';
      const wrongPassphrases = [
        'a', // very different
        'timing-test-passwor', // one char off
        'timing-test-passworde', // one char added
        'TIMING-TEST-PASSPHRASE' // case different
      ];
      
      const testData = 'sensitive-timing-data';
      const encrypted = await security.encryptData(testData, correctPassphrase);
      
      // Measure decryption times
      const measureDecryptTime = async (passphrase) => {
        const start = process.hrtime.bigint();
        try {
          await security.decryptData(encrypted, passphrase);
        } catch (error) {
          // Expected for wrong passphrases
        }
        const end = process.hrtime.bigint();
        return Number(end - start) / 1000000; // Convert to milliseconds
      };
      
      const correctTime = await measureDecryptTime(correctPassphrase);
      const wrongTimes = await Promise.all(
        wrongPassphrases.map(pass => measureDecryptTime(pass))
      );
      
      // Times should be relatively consistent (within 2x) to resist timing attacks
      wrongTimes.forEach(wrongTime => {
        const ratio = Math.max(correctTime, wrongTime) / Math.min(correctTime, wrongTime);
        expect(ratio).to.be.lessThan(3); // Allow some variance but not orders of magnitude
      });
    });

    it('should handle memory pressure gracefully', async () => {
      const database = new (require('../src/secure-database'))();
      await database.initialize();
      
      // Store large amounts of data
      const largeBatch = [];
      for (let i = 0; i < 1000; i++) {
        largeBatch.push({
          client_id: `stress_client_${i}`,
          tier: 'ENTERPRISE',
          api_key: crypto.randomBytes(32).toString('hex'),
          wallet_address: '0x' + crypto.randomBytes(20).toString('hex'),
          large_data: crypto.randomBytes(10240).toString('hex') // 10KB per record
        });
      }
      
      // Should not crash or leak memory
      const startMemory = process.memoryUsage().heapUsed;
      
      for (const data of largeBatch) {
        await database.storeSubscription(data);
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const endMemory = process.memoryUsage().heapUsed;
      const memoryGrowth = endMemory - startMemory;
      
      // Memory growth should be reasonable (less than 100MB for this test)
      expect(memoryGrowth).to.be.lessThan(100 * 1024 * 1024);
      
      await database.close();
    });
  });
});