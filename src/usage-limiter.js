// 🚦 Enterprise Usage Limiter & Enforcement System
class UsageLimiter {
  constructor() {
    this.usage = new Map(); // clientId -> usage stats
    this.limits = new Map(); // clientId -> tier limits
    this.rateLimiters = new Map(); // clientId -> rate limiter
    
    // Initialize database
    this.initDatabase();
  }
  
  initDatabase() {
    const db = require('./smartcache').db;
    
    db.run(`
      CREATE TABLE IF NOT EXISTS usage_stats (
        client_id TEXT,
        date TEXT,
        queries INTEGER DEFAULT 0,
        users INTEGER DEFAULT 0,
        apis_called INTEGER DEFAULT 0,
        cache_hits INTEGER DEFAULT 0,
        data_processed_mb REAL DEFAULT 0,
        cost_saved REAL DEFAULT 0,
        PRIMARY KEY (client_id, date)
      )
    `);
    
    db.run(`
      CREATE TABLE IF NOT EXISTS usage_violations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT,
        violation_type TEXT,
        timestamp INTEGER,
        details TEXT
      )
    `);
  }
  
  // Check if request is allowed
  async checkLimit(clientId, requestType = 'query') {
    const cryptoPayment = require('./crypto-payment');
    const subscription = await cryptoPayment.checkSubscription(clientId);
    
    if (!subscription || subscription.status !== 'ACTIVE') {
      return {
        allowed: false,
        reason: 'NO_ACTIVE_SUBSCRIPTION',
        message: 'Please activate a subscription at https://freeapi.enterprise'
      };
    }
    
    const limits = cryptoPayment.getTierLimits(subscription.tier);
    const usage = await this.getUsageToday(clientId);
    
    // Check query limits
    if (limits.queries !== -1 && usage.queries >= limits.queries) {
      await this.recordViolation(clientId, 'QUERY_LIMIT_EXCEEDED', {
        limit: limits.queries,
        used: usage.queries
      });
      
      return {
        allowed: false,
        reason: 'QUERY_LIMIT_EXCEEDED',
        message: `Daily query limit reached (${limits.queries}). Upgrade to higher tier.`,
        usage: usage,
        limits: limits
      };
    }
    
    // Check rate limiting (prevent abuse)
    if (!this.checkRateLimit(clientId)) {
      return {
        allowed: false,
        reason: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests. Please slow down.',
        retryAfter: this.getRetryAfter(clientId)
      };
    }
    
    // Check user limits (for team size)
    if (limits.users !== -1 && usage.users > limits.users) {
      return {
        allowed: false,
        reason: 'USER_LIMIT_EXCEEDED',
        message: `User limit exceeded (${limits.users}). Please upgrade.`,
        usage: usage,
        limits: limits
      };
    }
    
    // All checks passed - increment usage
    await this.incrementUsage(clientId, requestType);
    
    return {
      allowed: true,
      tier: subscription.tier,
      usage: usage,
      limits: limits,
      remaining: {
        queries: limits.queries === -1 ? 'unlimited' : limits.queries - usage.queries,
        users: limits.users === -1 ? 'unlimited' : limits.users - usage.users
      }
    };
  }
  
  // Get today's usage
  async getUsageToday(clientId) {
    const today = new Date().toISOString().split('T')[0];
    const db = require('./smartcache').db;
    
    return new Promise((resolve, reject) => {
      db.get(`
        SELECT * FROM usage_stats 
        WHERE client_id = ? AND date = ?
      `, [clientId, today], (err, row) => {
        if (err) reject(err);
        else resolve(row || {
          queries: 0,
          users: 0,
          apis_called: 0,
          cache_hits: 0,
          data_processed_mb: 0,
          cost_saved: 0
        });
      });
    });
  }
  
  // Increment usage counter
  async incrementUsage(clientId, type = 'query', amount = 1) {
    const today = new Date().toISOString().split('T')[0];
    const db = require('./smartcache').db;
    
    return new Promise((resolve, reject) => {
      const column = type === 'user' ? 'users' : 'queries';
      
      db.run(`
        INSERT INTO usage_stats (client_id, date, ${column})
        VALUES (?, ?, ?)
        ON CONFLICT(client_id, date) 
        DO UPDATE SET ${column} = ${column} + ?
      `, [clientId, today, amount, amount], err => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
  
  // Rate limiting implementation
  checkRateLimit(clientId) {
    if (!this.rateLimiters.has(clientId)) {
      this.rateLimiters.set(clientId, {
        tokens: 100, // 100 requests per minute
        lastRefill: Date.now(),
        maxTokens: 100,
        refillRate: 100 / 60000 // tokens per ms
      });
    }
    
    const limiter = this.rateLimiters.get(clientId);
    const now = Date.now();
    const timePassed = now - limiter.lastRefill;
    
    // Refill tokens
    limiter.tokens = Math.min(
      limiter.maxTokens,
      limiter.tokens + (timePassed * limiter.refillRate)
    );
    limiter.lastRefill = now;
    
    // Check if request allowed
    if (limiter.tokens >= 1) {
      limiter.tokens -= 1;
      return true;
    }
    
    return false;
  }
  
  getRetryAfter(clientId) {
    const limiter = this.rateLimiters.get(clientId);
    if (!limiter) return 0;
    
    const tokensNeeded = 1;
    const tokensShort = tokensNeeded - limiter.tokens;
    const msToWait = tokensShort / limiter.refillRate;
    
    return Math.ceil(msToWait / 1000); // seconds
  }
  
  // Record violations
  async recordViolation(clientId, type, details) {
    const db = require('./smartcache').db;
    
    return new Promise((resolve, reject) => {
      db.run(`
        INSERT INTO usage_violations (client_id, violation_type, timestamp, details)
        VALUES (?, ?, ?, ?)
      `, [clientId, type, Date.now(), JSON.stringify(details)], err => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
  
  // Get usage analytics
  async getUsageAnalytics(clientId, days = 30) {
    const db = require('./smartcache').db;
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
      .toISOString().split('T')[0];
    
    return new Promise((resolve, reject) => {
      db.all(`
        SELECT 
          date,
          SUM(queries) as total_queries,
          SUM(cache_hits) as total_hits,
          SUM(cost_saved) as total_saved,
          SUM(data_processed_mb) as total_data_mb
        FROM usage_stats
        WHERE client_id = ? AND date >= ?
        GROUP BY date
        ORDER BY date DESC
      `, [clientId, startDate], (err, rows) => {
        if (err) reject(err);
        else {
          const analytics = {
            daily: rows,
            summary: {
              total_queries: rows.reduce((sum, r) => sum + r.total_queries, 0),
              total_hits: rows.reduce((sum, r) => sum + r.total_hits, 0),
              total_saved: rows.reduce((sum, r) => sum + r.total_saved, 0),
              total_data_mb: rows.reduce((sum, r) => sum + r.total_data_mb, 0),
              hit_rate: 0,
              avg_queries_per_day: 0
            }
          };
          
          if (analytics.summary.total_queries > 0) {
            analytics.summary.hit_rate = 
              (analytics.summary.total_hits / analytics.summary.total_queries) * 100;
            analytics.summary.avg_queries_per_day = 
              analytics.summary.total_queries / rows.length;
          }
          
          resolve(analytics);
        }
      });
    });
  }
  
  // Enforce limits middleware for Express
  enforceMiddleware() {
    return async (req, res, next) => {
      const clientId = req.headers['x-client-id'] || 
                      req.ip || 
                      'anonymous';
      
      const check = await this.checkLimit(clientId);
      
      if (!check.allowed) {
        return res.status(429).json({
          error: check.reason,
          message: check.message,
          usage: check.usage,
          limits: check.limits,
          retryAfter: check.retryAfter
        });
      }
      
      // Add usage info to request
      req.usageInfo = check;
      next();
    };
  }
}

module.exports = new UsageLimiter();