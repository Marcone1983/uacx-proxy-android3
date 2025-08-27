const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

/**
 * 🔐 SECURE CONFIGURATION MANAGER
 * Enterprise-grade configuration management with encryption and validation
 * 
 * Features:
 * - Environment-based configuration loading
 * - Encrypted configuration files for production
 * - Runtime secret validation
 * - Configuration schema validation
 * - Audit logging for configuration access
 * - Hot reload capabilities
 */
class SecureConfigManager {
  constructor() {
    this.config = null;
    this.schema = null;
    this.auditLogger = null;
    this.watchers = new Map();
    
    // Configuration hierarchy (priority order)
    this.configSources = [
      'environment', // Highest priority
      'encrypted_file',
      'secure_vault',
      'defaults' // Lowest priority
    ];
    
    this.initializeConfigManager();
  }

  /**
   * Initialize configuration manager
   */
  async initializeConfigManager() {
    try {
      this.schema = await this.loadConfigurationSchema();
      this.config = await this.loadConfiguration();
      await this.validateConfiguration();
      await this.setupConfigurationWatching();
      
      console.log('🔐 Secure Configuration Manager initialized');
    } catch (error) {
      console.error('❌ CRITICAL: Configuration Manager initialization failed', error);
      process.exit(1);
    }
  }

  /**
   * Load configuration schema for validation
   */
  async loadConfigurationSchema() {
    return {
      // Database Configuration
      database: {
        encryption_key: { type: 'string', required: true, sensitive: true, minLength: 32 },
        backup_encryption_key: { type: 'string', required: true, sensitive: true, minLength: 32 },
        connection_string: { type: 'string', required: false, sensitive: true }
      },
      
      // Blockchain Configuration
      blockchain: {
        wallet_address: { 
          type: 'string', 
          required: true, 
          pattern: /^0x[a-fA-F0-9]{40}$/, 
          sensitive: false 
        },
        infura_api_key: { type: 'string', required: true, sensitive: true, minLength: 32 },
        alchemy_api_key: { type: 'string', required: false, sensitive: true, minLength: 32 },
        moralis_api_key: { type: 'string', required: false, sensitive: true, minLength: 32 }
      },
      
      // AI API Configuration
      ai_apis: {
        openai_api_key: { 
          type: 'string', 
          required: false, 
          pattern: /^sk-proj-[A-Za-z0-9_-]{20}T3BlbkFJ[A-Za-z0-9_-]{20}$/, 
          sensitive: true 
        },
        anthropic_api_key: { 
          type: 'string', 
          required: false, 
          pattern: /^sk-ant-api03-[A-Za-z0-9_-]{93}-[A-Za-z0-9_-]{6}AA$/, 
          sensitive: true 
        },
        google_ai_api_key: { 
          type: 'string', 
          required: false, 
          pattern: /^AIza[0-9A-Za-z_-]{35}$/, 
          sensitive: true 
        }
      },
      
      // Security Configuration
      security: {
        jwt_secret: { type: 'string', required: true, sensitive: true, minLength: 32 },
        master_passphrase: { type: 'string', required: true, sensitive: true, minLength: 20 },
        audit_log_key: { type: 'string', required: true, sensitive: true, minLength: 32 },
        session_secret: { type: 'string', required: true, sensitive: true, minLength: 32 }
      },
      
      // External Service Configuration
      external_services: {
        supabase_url: { type: 'string', required: false, sensitive: false },
        supabase_anon_key: { type: 'string', required: false, sensitive: true },
        supabase_service_key: { type: 'string', required: false, sensitive: true },
        webhook_secret: { type: 'string', required: false, sensitive: true }
      },
      
      // Operational Configuration
      operational: {
        rate_limit_redis_url: { type: 'string', required: false, sensitive: true },
        monitoring_webhook: { type: 'string', required: false, sensitive: true },
        alert_email_smtp_password: { type: 'string', required: false, sensitive: true }
      }
    };
  }

  /**
   * Load configuration from all sources with priority
   */
  async loadConfiguration() {
    const config = {};
    
    // Start with defaults
    await this.mergeConfiguration(config, await this.loadDefaultConfiguration());
    
    // Load from secure vault if available
    try {
      await this.mergeConfiguration(config, await this.loadFromSecureVault());
    } catch (error) {
      console.warn('⚠️ Secure vault not available, using fallback methods');
    }
    
    // Load from encrypted file
    try {
      await this.mergeConfiguration(config, await this.loadFromEncryptedFile());
    } catch (error) {
      console.warn('⚠️ Encrypted config file not found, using environment variables');
    }
    
    // Override with environment variables (highest priority)
    await this.mergeConfiguration(config, await this.loadFromEnvironment());
    
    return config;
  }

  /**
   * Load default non-sensitive configuration
   */
  async loadDefaultConfiguration() {
    return {
      database: {
        connection_string: 'sqlite:./data/enterprise.db'
      },
      blockchain: {
        network_endpoints: {
          ETH: 'https://mainnet.infura.io/v3/',
          POLYGON: 'https://polygon-mainnet.infura.io/v3/',
          BSC: 'https://bsc-dataseed.binance.org/'
        },
        contract_addresses: {
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
        }
      },
      security: {
        rate_limits: {
          window_ms: 60000,
          max_requests: 100,
          ddos_threshold: 500
        },
        encryption: {
          algorithm: 'aes-256-gcm',
          key_derivation_iterations: 100000,
          salt_length: 32,
          iv_length: 16,
          tag_length: 16
        }
      },
      operational: {
        server_port: process.env.PORT || 3000,
        log_level: process.env.LOG_LEVEL || 'info',
        environment: process.env.NODE_ENV || 'production'
      }
    };
  }

  /**
   * Load configuration from environment variables
   */
  async loadFromEnvironment() {
    const envConfig = {};
    
    // Database
    if (process.env.DB_ENCRYPTION_KEY) {
      envConfig.database = { encryption_key: process.env.DB_ENCRYPTION_KEY };
    }
    if (process.env.DB_BACKUP_ENCRYPTION_KEY) {
      envConfig.database = { ...envConfig.database, backup_encryption_key: process.env.DB_BACKUP_ENCRYPTION_KEY };
    }
    
    // Blockchain
    if (process.env.WALLET_ADDRESS) {
      envConfig.blockchain = { wallet_address: process.env.WALLET_ADDRESS };
    }
    if (process.env.INFURA_API_KEY) {
      envConfig.blockchain = { ...envConfig.blockchain, infura_api_key: process.env.INFURA_API_KEY };
    }
    if (process.env.ALCHEMY_API_KEY) {
      envConfig.blockchain = { ...envConfig.blockchain, alchemy_api_key: process.env.ALCHEMY_API_KEY };
    }
    
    // AI APIs
    if (process.env.OPENAI_API_KEY) {
      envConfig.ai_apis = { openai_api_key: process.env.OPENAI_API_KEY };
    }
    if (process.env.ANTHROPIC_API_KEY) {
      envConfig.ai_apis = { ...envConfig.ai_apis, anthropic_api_key: process.env.ANTHROPIC_API_KEY };
    }
    if (process.env.GOOGLE_AI_API_KEY) {
      envConfig.ai_apis = { ...envConfig.ai_apis, google_ai_api_key: process.env.GOOGLE_AI_API_KEY };
    }
    
    // Security
    if (process.env.JWT_SECRET) {
      envConfig.security = { jwt_secret: process.env.JWT_SECRET };
    }
    if (process.env.MASTER_PASSPHRASE) {
      envConfig.security = { ...envConfig.security, master_passphrase: process.env.MASTER_PASSPHRASE };
    }
    if (process.env.AUDIT_LOG_KEY) {
      envConfig.security = { ...envConfig.security, audit_log_key: process.env.AUDIT_LOG_KEY };
    }
    
    // External Services
    if (process.env.SUPABASE_URL) {
      envConfig.external_services = { supabase_url: process.env.SUPABASE_URL };
    }
    if (process.env.SUPABASE_ANON_KEY) {
      envConfig.external_services = { ...envConfig.external_services, supabase_anon_key: process.env.SUPABASE_ANON_KEY };
    }
    
    this.auditConfigurationAccess('ENVIRONMENT_VARIABLES_LOADED');
    return envConfig;
  }

  /**
   * Load configuration from encrypted file
   */
  async loadFromEncryptedFile() {
    const configPath = process.env.SECURE_CONFIG_PATH || './config/secure.enc';
    const passphrase = process.env.MASTER_PASSPHRASE;
    
    if (!passphrase) {
      throw new Error('MASTER_PASSPHRASE required for encrypted config');
    }

    try {
      const encryptedData = await fs.readFile(configPath);
      const decryptedConfig = await this.decryptConfiguration(encryptedData, passphrase);
      
      this.auditConfigurationAccess('ENCRYPTED_FILE_LOADED', { configPath });
      return JSON.parse(decryptedConfig);
    } catch (error) {
      if (error.code === 'ENOENT') {
        console.log('📁 Creating new encrypted configuration file...');
        await this.createDefaultEncryptedConfig(configPath, passphrase);
        return {};
      }
      throw error;
    }
  }

  /**
   * Load configuration from secure vault (HashiCorp Vault, AWS Secrets Manager, etc.)
   */
  async loadFromSecureVault() {
    // Implementation would depend on the specific vault system
    // This is a placeholder for future implementation
    
    if (process.env.VAULT_ENABLED === 'true') {
      // Implement vault integration here
      console.log('🏛️ Loading configuration from secure vault...');
      return {};
    }
    
    throw new Error('Secure vault not configured');
  }

  /**
   * Merge configuration objects with deep merge
   */
  async mergeConfiguration(target, source) {
    for (const [key, value] of Object.entries(source)) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        target[key] = target[key] || {};
        await this.mergeConfiguration(target[key], value);
      } else {
        target[key] = value;
      }
    }
  }

  /**
   * Validate configuration against schema
   */
  async validateConfiguration() {
    const errors = [];
    
    await this.validateConfigurationSection('database', this.config.database, this.schema.database, errors);
    await this.validateConfigurationSection('blockchain', this.config.blockchain, this.schema.blockchain, errors);
    await this.validateConfigurationSection('security', this.config.security, this.schema.security, errors);
    
    if (errors.length > 0) {
      console.error('❌ Configuration validation errors:');
      errors.forEach(error => console.error(`   - ${error}`));
      throw new Error(`Configuration validation failed: ${errors.length} errors found`);
    }
    
    this.auditConfigurationAccess('CONFIGURATION_VALIDATED');
    console.log('✅ Configuration validation passed');
  }

  /**
   * Validate a configuration section
   */
  async validateConfigurationSection(sectionName, config, schema, errors) {
    if (!config) config = {};
    
    for (const [key, rules] of Object.entries(schema)) {
      const value = config[key];
      const fieldName = `${sectionName}.${key}`;
      
      // Check required fields
      if (rules.required && (value === undefined || value === null)) {
        errors.push(`Required field missing: ${fieldName}`);
        continue;
      }
      
      if (value === undefined || value === null) continue;
      
      // Check type
      if (rules.type === 'string' && typeof value !== 'string') {
        errors.push(`Invalid type for ${fieldName}: expected string, got ${typeof value}`);
        continue;
      }
      
      // Check minimum length
      if (rules.minLength && value.length < rules.minLength) {
        errors.push(`Invalid length for ${fieldName}: minimum ${rules.minLength} characters`);
      }
      
      // Check pattern
      if (rules.pattern && !rules.pattern.test(value)) {
        errors.push(`Invalid format for ${fieldName}: does not match required pattern`);
      }
    }
  }

  /**
   * Get configuration value with audit logging
   */
  get(keyPath, defaultValue = null) {
    const keys = keyPath.split('.');
    let value = this.config;
    
    for (const key of keys) {
      if (value && typeof value === 'object' && key in value) {
        value = value[key];
      } else {
        value = defaultValue;
        break;
      }
    }
    
    // Audit access to sensitive values
    const isSensitive = this.isConfigurationKeySensitive(keyPath);
    if (isSensitive) {
      this.auditConfigurationAccess('SENSITIVE_CONFIG_ACCESSED', { keyPath });
    }
    
    return value;
  }

  /**
   * Check if a configuration key contains sensitive data
   */
  isConfigurationKeySensitive(keyPath) {
    const keys = keyPath.split('.');
    if (keys.length < 2) return false;
    
    const section = keys[0];
    const field = keys[1];
    
    const sectionSchema = this.schema[section];
    if (!sectionSchema || !sectionSchema[field]) return false;
    
    return sectionSchema[field].sensitive === true;
  }

  /**
   * Create default encrypted configuration file
   */
  async createDefaultEncryptedConfig(configPath, passphrase) {
    const defaultSecureConfig = {
      database: {
        encryption_key: crypto.randomBytes(32).toString('hex'),
        backup_encryption_key: crypto.randomBytes(32).toString('hex')
      },
      security: {
        jwt_secret: crypto.randomBytes(64).toString('hex'),
        audit_log_key: crypto.randomBytes(32).toString('hex'),
        session_secret: crypto.randomBytes(32).toString('hex')
      },
      blockchain: {
        // These should be provided via environment variables
        wallet_address: '',
        infura_api_key: ''
      },
      ai_apis: {
        // These should be provided via environment variables
        openai_api_key: '',
        anthropic_api_key: ''
      }
    };

    const encrypted = await this.encryptConfiguration(JSON.stringify(defaultSecureConfig), passphrase);
    
    await fs.mkdir(path.dirname(configPath), { recursive: true });
    await fs.writeFile(configPath, encrypted);
    
    this.auditConfigurationAccess('DEFAULT_CONFIG_CREATED', { configPath });
    console.log('📁 Default encrypted configuration created');
  }

  /**
   * Encrypt configuration data
   */
  async encryptConfiguration(plaintext, passphrase) {
    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
    
    const cipher = crypto.createCipherGCM('aes-256-gcm', key, iv);
    cipher.setAAD(salt);
    
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return Buffer.concat([salt, iv, tag, Buffer.from(encrypted, 'hex')]);
  }

  /**
   * Decrypt configuration data
   */
  async decryptConfiguration(encryptedBuffer, passphrase) {
    const salt = encryptedBuffer.slice(0, 32);
    const iv = encryptedBuffer.slice(32, 48);
    const tag = encryptedBuffer.slice(48, 64);
    const encrypted = encryptedBuffer.slice(64);
    
    const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
    
    const decipher = crypto.createDecipherGCM('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    decipher.setAAD(salt);
    
    let decrypted = decipher.update(encrypted, null, 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  /**
   * Setup configuration file watching for hot reload
   */
  async setupConfigurationWatching() {
    if (process.env.NODE_ENV === 'production') {
      console.log('🔄 Configuration hot reload disabled in production');
      return;
    }
    
    const configPath = process.env.SECURE_CONFIG_PATH || './config/secure.enc';
    
    try {
      const fs = require('fs');
      const watcher = fs.watch(configPath, async (eventType) => {
        if (eventType === 'change') {
          console.log('🔄 Configuration file changed, reloading...');
          try {
            this.config = await this.loadConfiguration();
            await this.validateConfiguration();
            console.log('✅ Configuration reloaded successfully');
          } catch (error) {
            console.error('❌ Configuration reload failed:', error.message);
          }
        }
      });
      
      this.watchers.set(configPath, watcher);
      console.log('🔄 Configuration hot reload enabled');
    } catch (error) {
      console.warn('⚠️ Could not setup configuration watching:', error.message);
    }
  }

  /**
   * Audit configuration access
   */
  auditConfigurationAccess(event, data = {}) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      pid: process.pid,
      source: 'SecureConfigManager'
    };
    
    console.log(`🔍 CONFIG AUDIT [${event}]:`, JSON.stringify(data));
  }

  /**
   * Get health status
   */
  getHealthStatus() {
    return {
      configuration_loaded: !!this.config,
      schema_loaded: !!this.schema,
      watchers_active: this.watchers.size,
      sensitive_keys_detected: this.countSensitiveKeys(),
      environment: process.env.NODE_ENV || 'unknown'
    };
  }

  /**
   * Count sensitive configuration keys
   */
  countSensitiveKeys() {
    let count = 0;
    
    for (const [sectionName, section] of Object.entries(this.schema)) {
      for (const [fieldName, field] of Object.entries(section)) {
        if (field.sensitive) {
          const value = this.get(`${sectionName}.${fieldName}`);
          if (value) count++;
        }
      }
    }
    
    return count;
  }

  /**
   * Cleanup resources
   */
  async cleanup() {
    for (const watcher of this.watchers.values()) {
      watcher.close();
    }
    this.watchers.clear();
  }
}

module.exports = new SecureConfigManager();