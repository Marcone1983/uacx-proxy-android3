const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// 🔒 Enterprise Authentication System
class AuthSystem {
  constructor() {
    this.JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
    this.REFRESH_SECRET = process.env.REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
    this.sessions = new Map();
    
    this.initDatabase();
  }
  
  initDatabase() {
    const db = require('./smartcache').db;
    
    db.run(`
      CREATE TABLE IF NOT EXISTS clients (
        client_id TEXT PRIMARY KEY,
        email TEXT UNIQUE,
        password_hash TEXT,
        api_key TEXT UNIQUE,
        tier TEXT,
        company_name TEXT,
        created_at INTEGER,
        last_login INTEGER,
        is_active INTEGER DEFAULT 1,
        metadata TEXT
      )
    `);
    
    db.run(`
      CREATE TABLE IF NOT EXISTS api_keys (
        key_id TEXT PRIMARY KEY,
        client_id TEXT,
        api_key TEXT UNIQUE,
        name TEXT,
        permissions TEXT,
        created_at INTEGER,
        last_used INTEGER,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY(client_id) REFERENCES clients(client_id)
      )
    `);
    
    db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        client_id TEXT,
        refresh_token TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at INTEGER,
        expires_at INTEGER,
        FOREIGN KEY(client_id) REFERENCES clients(client_id)
      )
    `);
  }
  
  // Register new client
  async register(email, password, companyName, tier = 'PERSONAL') {
    const db = require('./smartcache').db;
    
    // Generate unique IDs
    const clientId = 'client_' + crypto.randomBytes(16).toString('hex');
    const apiKey = 'sk_live_' + crypto.randomBytes(32).toString('hex');
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);
    
    return new Promise((resolve, reject) => {
      db.run(`
        INSERT INTO clients (
          client_id, email, password_hash, api_key, 
          tier, company_name, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `, [
        clientId, email, passwordHash, apiKey,
        tier, companyName, Date.now()
      ], (err) => {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            reject(new Error('Email already registered'));
          } else {
            reject(err);
          }
        } else {
          resolve({
            clientId,
            email,
            apiKey,
            tier,
            companyName,
            message: '✅ Registration successful! Save your API key securely.'
          });
        }
      });
    });
  }
  
  // Login with email/password
  async login(email, password, ipAddress, userAgent) {
    const db = require('./smartcache').db;
    
    return new Promise((resolve, reject) => {
      db.get(`
        SELECT * FROM clients WHERE email = ? AND is_active = 1
      `, [email], async (err, client) => {
        if (err) return reject(err);
        if (!client) return reject(new Error('Invalid credentials'));
        
        // Verify password
        const validPassword = await bcrypt.compare(password, client.password_hash);
        if (!validPassword) return reject(new Error('Invalid credentials'));
        
        // Generate tokens
        const accessToken = this.generateAccessToken(client);
        const refreshToken = this.generateRefreshToken(client);
        const sessionId = 'session_' + crypto.randomBytes(16).toString('hex');
        
        // Store session
        db.run(`
          INSERT INTO sessions (
            session_id, client_id, refresh_token, 
            ip_address, user_agent, created_at, expires_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
          sessionId, client.client_id, refreshToken,
          ipAddress, userAgent, Date.now(),
          Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days
        ]);
        
        // Update last login
        db.run(`
          UPDATE clients SET last_login = ? WHERE client_id = ?
        `, [Date.now(), client.client_id]);
        
        resolve({
          accessToken,
          refreshToken,
          sessionId,
          clientId: client.client_id,
          email: client.email,
          tier: client.tier,
          apiKey: client.api_key
        });
      });
    });
  }
  
  // Authenticate API request
  async authenticateRequest(req) {
    // Check for API key
    const apiKey = req.headers['x-api-key'] || 
                  req.headers['authorization']?.replace('Bearer ', '');
    
    if (apiKey && apiKey.startsWith('sk_')) {
      return this.authenticateApiKey(apiKey);
    }
    
    // Check for JWT token
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (token) {
      return this.verifyAccessToken(token);
    }
    
    throw new Error('No authentication provided');
  }
  
  // Authenticate with API key
  async authenticateApiKey(apiKey) {
    const db = require('./smartcache').db;
    
    return new Promise((resolve, reject) => {
      db.get(`
        SELECT c.*, k.permissions, k.key_id 
        FROM clients c
        LEFT JOIN api_keys k ON c.client_id = k.client_id
        WHERE (c.api_key = ? OR k.api_key = ?) 
        AND c.is_active = 1 
        AND (k.is_active = 1 OR k.is_active IS NULL)
      `, [apiKey, apiKey], (err, result) => {
        if (err) return reject(err);
        if (!result) return reject(new Error('Invalid API key'));
        
        // Update last used
        db.run(`
          UPDATE api_keys SET last_used = ? WHERE api_key = ?
        `, [Date.now(), apiKey]);
        
        resolve({
          authenticated: true,
          clientId: result.client_id,
          tier: result.tier,
          permissions: result.permissions ? JSON.parse(result.permissions) : ['all']
        });
      });
    });
  }
  
  // Generate tokens
  generateAccessToken(client) {
    return jwt.sign(
      {
        clientId: client.client_id,
        email: client.email,
        tier: client.tier,
        type: 'access'
      },
      this.JWT_SECRET,
      { expiresIn: '1h' }
    );
  }
  
  generateRefreshToken(client) {
    return jwt.sign(
      {
        clientId: client.client_id,
        type: 'refresh'
      },
      this.REFRESH_SECRET,
      { expiresIn: '30d' }
    );
  }
  
  // Verify tokens
  verifyAccessToken(token) {
    try {
      const decoded = jwt.verify(token, this.JWT_SECRET);
      if (decoded.type !== 'access') throw new Error('Invalid token type');
      
      return {
        authenticated: true,
        clientId: decoded.clientId,
        email: decoded.email,
        tier: decoded.tier
      };
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }
  
  async refreshAccessToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, this.REFRESH_SECRET);
      if (decoded.type !== 'refresh') throw new Error('Invalid token type');
      
      // Get client details
      const db = require('./smartcache').db;
      
      return new Promise((resolve, reject) => {
        db.get(`
          SELECT c.* FROM clients c
          JOIN sessions s ON c.client_id = s.client_id
          WHERE s.refresh_token = ? AND s.expires_at > ?
        `, [refreshToken, Date.now()], (err, client) => {
          if (err) return reject(err);
          if (!client) return reject(new Error('Invalid refresh token'));
          
          // Generate new access token
          const accessToken = this.generateAccessToken(client);
          
          resolve({
            accessToken,
            clientId: client.client_id,
            email: client.email,
            tier: client.tier
          });
        });
      });
    } catch (error) {
      throw new Error('Invalid or expired refresh token');
    }
  }
  
  // Create API key
  async createApiKey(clientId, keyName, permissions = ['all']) {
    const db = require('./smartcache').db;
    const keyId = 'key_' + crypto.randomBytes(16).toString('hex');
    const apiKey = 'sk_live_' + crypto.randomBytes(32).toString('hex');
    
    return new Promise((resolve, reject) => {
      db.run(`
        INSERT INTO api_keys (
          key_id, client_id, api_key, name, 
          permissions, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `, [
        keyId, clientId, apiKey, keyName,
        JSON.stringify(permissions), Date.now()
      ], (err) => {
        if (err) reject(err);
        else resolve({
          keyId,
          apiKey,
          name: keyName,
          permissions,
          message: '✅ API key created successfully'
        });
      });
    });
  }
  
  // Revoke API key
  async revokeApiKey(clientId, keyId) {
    const db = require('./smartcache').db;
    
    return new Promise((resolve, reject) => {
      db.run(`
        UPDATE api_keys 
        SET is_active = 0 
        WHERE key_id = ? AND client_id = ?
      `, [keyId, clientId], (err) => {
        if (err) reject(err);
        else resolve({ message: '✅ API key revoked' });
      });
    });
  }
  
  // Authentication middleware
  authMiddleware() {
    return async (req, res, next) => {
      try {
        const auth = await this.authenticateRequest(req);
        req.auth = auth;
        req.clientId = auth.clientId;
        next();
      } catch (error) {
        res.status(401).json({
          error: 'AUTHENTICATION_FAILED',
          message: error.message
        });
      }
    };
  }
  
  // Rate limiting per client
  rateLimitMiddleware(requestsPerMinute = 100) {
    const limiters = new Map();
    
    return (req, res, next) => {
      const clientId = req.clientId || req.ip;
      
      if (!limiters.has(clientId)) {
        limiters.set(clientId, {
          count: 0,
          resetTime: Date.now() + 60000
        });
      }
      
      const limiter = limiters.get(clientId);
      
      if (Date.now() > limiter.resetTime) {
        limiter.count = 0;
        limiter.resetTime = Date.now() + 60000;
      }
      
      if (limiter.count >= requestsPerMinute) {
        return res.status(429).json({
          error: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests',
          retryAfter: Math.ceil((limiter.resetTime - Date.now()) / 1000)
        });
      }
      
      limiter.count++;
      next();
    };
  }
}

module.exports = new AuthSystem();