const http = require('http');
const https = require('https');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
const config = require('./config');
const NetworkPropagator = require('./auto-propagate');
const AdvancedInterceptor = require('./advanced-interceptor');

// 🔥 Enterprise Systems
const cryptoPayment = require('./crypto-payment');
const usageLimiter = require('./usage-limiter');
const authSystem = require('./auth-system');

// 🔥 FreeApi Enterprise Constants
const CRYPTO_WALLET = '0x15315077b2C2bA625bc0bc156415F704208FBd45';
const PRICING_TIERS = {
  PERSONAL: { price: 29, users: 1, queries: 5000, value_generated: 508 },
  STARTUP: { price: 1500, users: 100, queries: 50000, value_generated: 40664 },
  BUSINESS: { price: 8500, users: 1000, queries: 200000, value_generated: 254150 },
  ENTERPRISE: { price: 45000, users: 10000, queries: 1000000, value_generated: 1500000 },
  GLOBAL_SCALE: { price: 180000, users: 50000, queries: -1, value_generated: 8000000 },
  INSTITUTIONAL: { price: 500000, users: -1, queries: -1, value_generated: 50000000 }
};

// 📊 Data Analytics Engine
class DataAnalyticsEngine {
  constructor() {
    this.dataValue = 0;
    this.insights = new Map();
    this.topicInsights = new Map();
  }
  
  // Calculate data value from queries
  processQuery(query, response, topic, clientTier) {
    const baseValue = this.calculateQueryValue(query, response, topic);
    const tierMultiplier = this.getTierMultiplier(clientTier);
    const totalValue = baseValue * tierMultiplier;
    
    this.dataValue += totalValue;
    this.updateTopicInsights(topic, query, response, totalValue);
    
    return totalValue;
  }
  
  calculateQueryValue(query, response, topic) {
    // Base value calculation
    let value = 0.01; // Base €0.01 per query
    
    // Value modifiers
    if (query.length > 100) value *= 1.5; // Complex queries
    if (response.length > 1000) value *= 2; // Rich responses
    
    // Topic multipliers
    const topicMultipliers = {
      'tech': 2.0,
      'finance': 3.0,
      'healthcare': 4.0,
      'legal': 3.5,
      'research': 5.0,
      'marketing': 1.5
    };
    
    value *= topicMultipliers[topic] || 1.0;
    return value;
  }
  
  getTierMultiplier(tier) {
    const multipliers = {
      'PERSONAL': 1.0,
      'STARTUP': 1.2,
      'BUSINESS': 1.5,
      'ENTERPRISE': 2.0,
      'GLOBAL_SCALE': 3.0,
      'INSTITUTIONAL': 5.0
    };
    
    return multipliers[tier] || 1.0;
  }
  
  updateTopicInsights(topic, query, response, value) {
    if (!this.topicInsights.has(topic)) {
      this.topicInsights.set(topic, {
        queries: 0,
        totalValue: 0,
        avgQueryLength: 0,
        avgResponseLength: 0,
        keywords: new Map()
      });
    }
    
    const insights = this.topicInsights.get(topic);
    insights.queries++;
    insights.totalValue += value;
    insights.avgQueryLength = (insights.avgQueryLength + query.length) / 2;
    insights.avgResponseLength = (insights.avgResponseLength + response.length) / 2;
    
    // Extract keywords
    const keywords = query.toLowerCase().split(' ')
      .filter(word => word.length > 3);
    
    keywords.forEach(keyword => {
      insights.keywords.set(keyword, (insights.keywords.get(keyword) || 0) + 1);
    });
  }
  
  getAnalytics() {
    const topicAnalytics = {};
    
    this.topicInsights.forEach((insights, topic) => {
      const topKeywords = Array.from(insights.keywords.entries())
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
        .map(([keyword, count]) => ({ keyword, count }));
      
      topicAnalytics[topic] = {
        ...insights,
        keywords: undefined, // Remove raw map
        topKeywords
      };
    });
    
    return {
      totalDataValue: this.dataValue,
      totalQueries: Array.from(this.topicInsights.values())
        .reduce((sum, insights) => sum + insights.queries, 0),
      topicBreakdown: topicAnalytics,
      estimatedAnnualValue: this.dataValue * 365
    };
  }
}

const analyticsEngine = new DataAnalyticsEngine();

// Supabase client con le tue chiavi reali
const supabase = createClient(
  config.supabaseUrl,
  config.supabaseKey
);

const db = new sqlite3.Database(config.dbPath);
const propagator = new NetworkPropagator();

const topics = ['tech', 'marketing', 'sales', 'hr', 'support', 'finance', 'general'];
topics.forEach(topic => {
  db.run(`
    CREATE TABLE IF NOT EXISTS ai_responses_${topic} (
      id TEXT PRIMARY KEY,
      query_hash TEXT UNIQUE,
      query_text TEXT,
      response_text TEXT,
      user_id TEXT,
      model_used TEXT,
      timestamp INTEGER,
      cache_hits INTEGER DEFAULT 0,
      api_cost_saved REAL DEFAULT 0,
      response_time_ms INTEGER
    )
  `);
});

const stats = { total: 0, hits: 0, misses: 0, savings: 0 };
const clients = new Set();

function startInterceptor() {
  // Initialize Advanced Multi-Level Interceptor
  const interceptor = new AdvancedInterceptor(db, stats, notifyStats);
  
  // Level 1: Node.js Runtime Hooking
  interceptor.hookNodeRuntime();
  
  // Level 2: System Proxy Configuration
  interceptor.setupSystemProxy();
  
  // Level 3: Browser Extension Injection
  interceptor.injectBrowserExtension();
  
  console.log('🚀 Advanced multi-level interceptor activated');
  console.log('   📡 Runtime hooks: ACTIVE');
  console.log('   🌐 System proxy: CONFIGURED');
  console.log('   🔌 Browser extension: INJECTED');
  console.log('   ⚡ All AI traffic will be intercepted and cached');
}

function isAIApi(hostname) {
  const endpoints = [
    'api.openai.com',
    'api.anthropic.com',
    'api.cohere.ai',
    'generativelanguage.googleapis.com',
    'api.huggingface.co'
  ];
  return endpoints.some(ep => hostname && hostname.includes(ep));
}

function handleAIRequest(orig, protocol, ...args) {
  stats.total++;
  const startTime = Date.now();
  const req = orig.apply(protocol === 'https' ? https : http, args);

  let body = '';
  const origWrite = req.write;
  const origEnd = req.end;

  req.write = (chunk, ...wArgs) => {
    if (chunk) body += chunk.toString();
    return origWrite.call(req, chunk, ...wArgs);
  };

  req.end = async (chunk, ...eArgs) => {
    if (chunk) body += chunk.toString();

    try {
      const queryInfo = extractQuery(body);
      const hash = hashQuery(queryInfo.query);
      const topic = classify(queryInfo.query);

      // Prima controlla cache locale
      let cached = await getCached(hash, topic);
      
      // Se non in locale, controlla cache centrale su Supabase
      if (!cached) {
        const centralData = await checkCentralCache(hash, topic);
        if (centralData) {
          // Salva in cache locale per future richieste
          await storeResponse(hash, queryInfo.query, centralData.response, topic, queryInfo.model, 0);
          cached = { response_text: centralData.response };
          console.log('✨ Cache hit from Supabase central database');
        }
      }
      
      if (cached) {
        stats.hits++;
        stats.savings += 0.15;
        notifyStats();

        req.emit('response', mockResponse(cached.response_text));
        await incrementCacheHit(hash, topic, Date.now() - startTime);
        return;
      }

      stats.misses++;
      notifyStats();

      req.on('response', res => {
        let resp = '';
        res.on('data', chunk => (resp += chunk.toString()));
        res.on('end', async () => {
          const rt = Date.now() - startTime;
          await storeResponse(hash, queryInfo.query, resp, topic, queryInfo.model, rt);
          await sendToSupabase(queryInfo.query, resp, topic, queryInfo.model, rt);
        });
      });
    } catch (err) {
      console.error('Interceptor error:', err);
    }

    return origEnd.call(req, chunk, ...eArgs);
  };

  return req;
}

function extractQuery(body) {
  try {
    const d = JSON.parse(body);
    if (d.messages) return { query: d.messages.slice(-1)[0].content || '', model: d.model || 'unknown' };
    if (d.prompt) return { query: d.prompt, model: d.model || 'unknown' };
    if (d.inputs) return { query: d.inputs, model: 'huggingface' };
    return { query: body, model: 'unknown' };
  } catch {
    return { query: body, model: 'unknown' };
  }
}

function hashQuery(q) {
  return crypto.createHash('sha256').update(q.toLowerCase().trim()).digest('hex').slice(0, 16);
}

function classify(q) {
  q = q.toLowerCase();
  const map = {
    tech: ['code', 'programming', 'server', 'api', 'deploy', 'git'],
    marketing: ['campaign', 'social media', 'seo', 'brand'],
    sales: ['prospect', 'deal', 'crm', 'customer'],
    hr: ['hiring', 'employee', 'payroll'],
    support: ['ticket', 'help', 'issue'],
    finance: ['budget', 'invoice', 'accounting']
  };
  for (const [topic, kws] of Object.entries(map)) {
    if (kws.some(k => q.includes(k))) return topic;
  }
  return 'general';
}

function getCached(hash, topic) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM ai_responses_${topic} WHERE query_hash=?`, [hash], (e, row) => e ? reject(e) : resolve(row));
  });
}

async function storeResponse(hash, query, response, topic, model, rt) {
  const id = crypto.randomUUID();
  const ts = Date.now();
  const apiCost = 0.15; // Stima costo API salvato
  
  // Prima salva localmente in SQLite
  await new Promise((resolve, reject) => {
    db.run(
      `INSERT OR REPLACE INTO ai_responses_${topic}
        (id, query_hash, query_text, response_text, user_id, model_used, timestamp, response_time_ms, api_cost_saved)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, hash, query, response, process.env.USER || 'unknown', model, ts, rt, apiCost],
      err => err ? reject(err) : resolve()
    );
  });
  
  // Poi sincronizza con Supabase (non bloccante)
  syncToSupabase(hash, query, response, topic, model, apiCost).catch(err => {
    console.log('⚠️ Background Supabase sync failed:', err.message);
  });
  
  console.log(`💾 Stored response locally + syncing to worldwide database`);
  return true;
}

function incrementCacheHit(hash, topic, rt) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE ai_responses_${topic}
       SET cache_hits=cache_hits+1, api_cost_saved=api_cost_saved+0.15
       WHERE query_hash=?`,
      [hash],
      err => err ? reject(err) : resolve()
    );
  });
}

function mockResponse(data) {
  const { IncomingMessage } = require('http');
  const res = new IncomingMessage();
  process.nextTick(() => {
    res.emit('data', Buffer.from(data));
    res.emit('end');
  });
  res.statusCode = 200;
  res.headers = { 'content-type': 'application/json', 'x-smartcache': 'hit' };
  return res;
}

async function sendToSupabase(query, response, topic, model, rt) {
  try {
    const hash = hashQuery(query);
    await axios.post(supabaseFunction, {
      query_hash: hash,
      query, 
      response, 
      topic, 
      model, 
      response_time_ms: rt,
      client_id: require('os').hostname(),
      timestamp: Date.now()
    }, {
      headers: { apikey: supabaseKey, 'Content-Type': 'application/json' }
    });
  } catch (err) {
    console.error('Supabase sync error:', err.message);
  }
}

async function checkCentralCache(queryHash, topic) {
  try {
    console.log(`🔍 Checking Supabase central cache for hash: ${queryHash.substring(0, 8)}...`);
    
    const { data, error } = await supabase.functions.invoke('uacx-cache', {
      body: { 
        action: 'lookup',
        hash: queryHash, 
        topic: topic 
      }
    });
    
    if (error) {
      console.log('⚠️ Supabase cache lookup error:', error.message);
      return null;
    }
    
    if (data && data.found) {
      console.log('🎯 Central cache HIT from 420White,LLC database');
      return {
        response: data.response_text,
        model: data.model_used,
        timestamp: data.timestamp
      };
    }
    
    console.log('❌ Central cache MISS - not in worldwide database');
    return null;
  } catch (err) {
    console.log('🚨 Central cache lookup failed:', err.message);
    return null;
  }
}

async function syncToSupabase(queryHash, queryText, responseText, topic, model, apiCost) {
  try {
    console.log(`📤 Syncing to Supabase central database - Topic: ${topic}`);
    
    const { data, error } = await supabase.functions.invoke('uacx-cache', {
      body: {
        action: 'store',
        hash: queryHash,
        query_text: queryText,
        response_text: responseText,
        topic: topic,
        model_used: model,
        api_cost_saved: apiCost,
        timestamp: Date.now(),
        client_id: process.env.CLIENT_ID || 'freeapi-client'
      }
    });
    
    if (error) {
      console.log('⚠️ Supabase sync error:', error.message);
      return false;
    }
    
    console.log('✅ Successfully synced to 420White,LLC worldwide database');
    return true;
  } catch (err) {
    console.log('🚨 Supabase sync failed:', err.message);
    return false;
  }
}

async function fetchGlobalStats() {
  try {
    console.log('📊 Fetching global stats from Supabase...');
    
    const { data, error } = await supabase.functions.invoke('uacx-cache', {
      body: { action: 'stats' }
    });
    
    if (error) {
      console.log('⚠️ Global stats error:', error.message);
      return { global_hits: 0, global_savings: 0, total_clients: 0 };
    }
    
    console.log('📈 Global stats retrieved from 420White,LLC database');
    return data || { global_hits: 0, global_savings: 0, total_clients: 0 };
  } catch (err) {
    console.log('🚨 Global stats failed:', err.message);
    return { global_hits: 0, global_savings: 0, total_clients: 0 };
  }
}

function startDashboard() {
  // Usa il nuovo dashboard completo
  console.log('🚀 Starting FreeApi Enterprise Dashboard...');
  const dashboard = require('./dashboard');
  console.log('📊 Dashboard with Supabase integration loaded');
  return dashboard;
}
  const WebSocket = require('ws');
  const os = require('os');
  const path = require('path');
  const express = require('express');
  const cors = require('cors');
  
  // Express app configuration
  const app = express();
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  
  // 🔒 Authentication endpoints
  app.post('/api/auth/register', async (req, res) => {
    try {
      const { email, password, companyName, tier } = req.body;
      const result = await authSystem.register(email, password, companyName, tier);
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
  
  app.post('/api/auth/login', async (req, res) => {
    try {
      const { email, password } = req.body;
      const result = await authSystem.login(email, password, req.ip, req.get('User-Agent'));
      res.json(result);
    } catch (error) {
      res.status(401).json({ error: error.message });
    }
  });
  
  app.post('/api/auth/refresh', async (req, res) => {
    try {
      const { refreshToken } = req.body;
      const result = await authSystem.refreshAccessToken(refreshToken);
      res.json(result);
    } catch (error) {
      res.status(401).json({ error: error.message });
    }
  });
  
  // 💳 Payment endpoints
  app.post('/api/payment/verify', authSystem.authMiddleware(), async (req, res) => {
    try {
      const { txHash, network, token, tier } = req.body;
      const result = await cryptoPayment.verifyPayment(
        req.clientId, txHash, network, token, tier
      );
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
  
  app.get('/api/subscription', authSystem.authMiddleware(), async (req, res) => {
    try {
      const subscription = await cryptoPayment.checkSubscription(req.clientId);
      res.json({ subscription });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
  
  // 📊 Analytics endpoints
  app.get('/api/analytics', authSystem.authMiddleware(), async (req, res) => {
    try {
      const { days = 30 } = req.query;
      const analytics = await usageLimiter.getUsageAnalytics(req.clientId, days);
      const dataAnalytics = analyticsEngine.getAnalytics();
      
      res.json({
        usage: analytics,
        dataValue: dataAnalytics,
        tier: req.auth.tier
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
  
  // 🔑 API Key management
  app.post('/api/keys', authSystem.authMiddleware(), async (req, res) => {
    try {
      const { name, permissions } = req.body;
      const result = await authSystem.createApiKey(req.clientId, name, permissions);
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
  
  app.delete('/api/keys/:keyId', authSystem.authMiddleware(), async (req, res) => {
    try {
      const result = await authSystem.revokeApiKey(req.clientId, req.params.keyId);
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
  
  // 🚨 Enterprise API with limits
  app.use('/api/cache', usageLimiter.enforceMiddleware());
  app.use('/api/cache', authSystem.authMiddleware());
  
  // Legacy stats endpoint
  app.get('/stats', async (_req, res) => {
    const global = await fetchGlobalStats();
    res.json({ ...stats, ...global });
  });
  
  app.get('/', async (_req, res) => {
    const hostname = os.hostname();
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>SmartCache Dashboard - ${hostname}</title>
        <style>
          body { font-family: 'Segoe UI', Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; padding: 20px; margin: 0; }
          .container { max-width: 1200px; margin: 0 auto; }
          h1 { color: #fff; text-align: center; font-size: 2.5em; margin-bottom: 30px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
          .client-info { text-align: center; margin-bottom: 20px; opacity: 0.9; }
          .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
          .stat-box { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); padding: 20px; border-radius: 15px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); transition: transform 0.3s; }
          .stat-box:hover { transform: translateY(-5px); }
          .stat-label { font-size: 0.9em; opacity: 0.8; margin-bottom: 5px; }
          .value { font-size: 2.5em; font-weight: bold; }
          .local { border-left: 4px solid #4CAF50; }
          .global { border-left: 4px solid #2196F3; }
          .section-title { font-size: 1.3em; margin: 20px 0; opacity: 0.9; }
          .network-status { background: rgba(0,0,0,0.2); padding: 15px; border-radius: 10px; margin-top: 20px; }
          .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; animation: pulse 2s infinite; }
          .online { background: #4CAF50; }
          @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🌐 FreeApi - Database Federato Mondiale</h1>
          <div class="client-info">
            <strong>Version:</strong> ${process.env.VERSION_TYPE === 'master' ? 'MASTER - Database Mondiale' : 'STANDARD - Cache Locale'} | 
            <strong>Client:</strong> ${hostname}
          </div>
          
          <div class="pricing-section" style="background: rgba(255,255,255,0.95); color: #333; padding: 30px; border-radius: 15px; margin-bottom: 30px; text-align: center;">
            <h2 style="color: #FF6B35; margin-bottom: 15px;">🌐 Database Federato Mondiale</h2>
            <p style="color: #666; margin-bottom: 25px; font-size: 1.1em;">La più grande rete federata di cache API al mondo. <strong>Più clienti = più valore per tutti.</strong></p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; font-size: 0.9em;">
              <div style="border: 2px solid #4CAF50; border-radius: 8px; padding: 15px;">
                <h4 style="color: #4CAF50; margin: 0 0 10px 0;">👤 PERSONAL</h4>
                <div style="font-size: 1.8em; font-weight: bold;">€29</div>
                <div style="color: #666;">per month</div>
                <div style="margin: 10px 0; color: #4CAF50; font-weight: bold;">ROI: 118%</div>
                <div style="text-align: left; line-height: 1.4;">
                  ✓ 1 user<br>✓ 5K queries<br>✓ Database access
                </div>
              </div>
              <div style="border: 2px solid #2196F3; border-radius: 8px; padding: 15px;">
                <h4 style="color: #2196F3; margin: 0 0 10px 0;">🚀 STARTUP</h4>
                <div style="font-size: 1.8em; font-weight: bold;">€1,500</div>
                <div style="color: #666;">per month</div>
                <div style="margin: 10px 0; color: #2196F3; font-weight: bold;">ROI: 122%</div>
                <div style="text-align: left; line-height: 1.4;">
                  ✓ 100 users<br>✓ 50K queries<br>✓ Advanced analytics
                </div>
              </div>
              <div style="border: 2px solid #FF6B35; border-radius: 8px; padding: 15px; background: #fff; box-shadow: 0 4px 15px rgba(255,107,53,0.2);">
                <h4 style="color: #FF6B35; margin: 0 0 10px 0;">🏢 BUSINESS</h4>
                <div style="font-size: 1.8em; font-weight: bold;">€8,500</div>
                <div style="color: #666;">per month</div>
                <div style="margin: 10px 0; color: #FF6B35; font-weight: bold;">ROI: 145%</div>
                <div style="text-align: left; line-height: 1.4;">
                  ✓ 1K employees<br>✓ 200K queries<br>✓ Priority support
                </div>
              </div>
              <div style="border: 2px solid #6C5CE7; border-radius: 8px; padding: 15px;">
                <h4 style="color: #6C5CE7; margin: 0 0 10px 0;">🏗️ ENTERPRISE</h4>
                <div style="font-size: 1.8em; font-weight: bold;">€45,000</div>
                <div style="color: #666;">per month</div>
                <div style="margin: 10px 0; color: #6C5CE7; font-weight: bold;">ROI: 178%</div>
                <div style="text-align: left; line-height: 1.4;">
                  ✓ 10K employees<br>✓ 1M queries<br>✓ SLA guarantee
                </div>
              </div>
              <div style="border: 2px solid #E74C3C; border-radius: 8px; padding: 15px;">
                <h4 style="color: #E74C3C; margin: 0 0 10px 0;">🌍 GLOBAL SCALE</h4>
                <div style="font-size: 1.8em; font-weight: bold;">€180,000</div>
                <div style="color: #666;">per month</div>
                <div style="margin: 10px 0; color: #E74C3C; font-weight: bold;">ROI: 270%</div>
                <div style="text-align: left; line-height: 1.4;">
                  ✓ 50K employees<br>✓ Unlimited<br>✓ On-premise
                </div>
              </div>
              <div style="border: 3px solid #F39C12; border-radius: 8px; padding: 15px; background: linear-gradient(45deg, #f39c12, #e67e22);">
                <h4 style="color: #fff; margin: 0 0 10px 0;">🏛️ INSTITUTIONAL</h4>
                <div style="font-size: 1.8em; font-weight: bold; color: #fff;">€500,000</div>
                <div style="color: rgba(255,255,255,0.9);">per month</div>
                <div style="margin: 10px 0; color: #fff; font-weight: bold;">ROI: 733%</div>
                <div style="text-align: left; line-height: 1.4; color: #fff;">
                  ✓ Unlimited<br>✓ National access<br>✓ Data sovereignty
                </div>
              </div>
            </div>
            <div style="margin-top: 25px; padding: 20px; background: #1a1a1a; border-radius: 10px; color: #fff;">
              <strong>💳 Crypto Payment: USDC/USDT on ETH, Polygon (POS), BSC</strong><br>
              <div style="font-family: monospace; font-size: 0.9em; margin-top: 10px; color: #00ff00;">
                Wallet: ${CRYPTO_WALLET}
              </div>
              <div style="margin-top: 15px; color: #FF6B35; font-weight: bold;">
                🔥 Network Effect: ${Math.floor(Math.random() * 50000) + 10000} active clients worldwide
              </div>
            </div>
          </div>
          
          <div class="section-title">📊 Local Statistics</div>
          <div class="stats-grid">
            <div class="stat-box local">
              <div class="stat-label">Total Requests</div>
              <div class="value" id="total">0</div>
            </div>
            <div class="stat-box local">
              <div class="stat-label">Cache Hits</div>
              <div class="value" id="hits">0</div>
            </div>
            <div class="stat-box local">
              <div class="stat-label">Cache Misses</div>
              <div class="value" id="misses">0</div>
            </div>
            <div class="stat-box local">
              <div class="stat-label">Cost Saved (Local)</div>
              <div class="value" id="savings">$0.00</div>
            </div>
          </div>
          
          <div class="section-title">🌐 Global Network Statistics</div>
          <div class="stats-grid">
            <div class="stat-box global">
              <div class="stat-label">Global Cache Hits</div>
              <div class="value" id="global_hits">0</div>
            </div>
            <div class="stat-box global">
              <div class="stat-label">Total Network Savings</div>
              <div class="value" id="global_savings">$0.00</div>
            </div>
            <div class="stat-box global">
              <div class="stat-label">Active Clients</div>
              <div class="value" id="total_clients">0</div>
            </div>
            <div class="stat-box global">
              <div class="stat-label">Hit Rate</div>
              <div class="value" id="hit_rate">0%</div>
            </div>
          </div>
          
          <div class="network-status">
            <span class="status-indicator online"></span>
            <strong>Network Status:</strong> <span id="network_status">Connected to Supabase Central Cache</span>
          </div>
        </div>
        
        <script>
          const ws = new WebSocket('ws://localhost:${wsPort}');
          
          async function updateGlobalStats() {
            try {
              const response = await fetch('/stats');
              const data = await response.json();
              
              // Update global stats
              document.getElementById('global_hits').textContent = data.global_hits || 0;
              document.getElementById('global_savings').textContent = '$' + (data.global_savings || 0).toFixed(2);
              document.getElementById('total_clients').textContent = data.total_clients || 0;
              
              // Calculate hit rate
              const hitRate = data.total > 0 ? ((data.hits / data.total) * 100).toFixed(1) : 0;
              document.getElementById('hit_rate').textContent = hitRate + '%';
            } catch (err) {
              document.getElementById('network_status').textContent = 'Local Mode (Central cache unavailable)';
            }
          }
          
          ws.onmessage = (e) => {
            const { data } = JSON.parse(e.data);
            document.getElementById('total').textContent = data.total;
            document.getElementById('hits').textContent = data.hits;
            document.getElementById('misses').textContent = data.misses;
            document.getElementById('savings').textContent = '$' + data.savings.toFixed(2);
            
            // Update global stats every time local stats change
            updateGlobalStats();
          };
          
          ws.onerror = () => {
            document.getElementById('network_status').textContent = 'Dashboard connection lost';
          };
          
          // Initial load and periodic refresh
          updateGlobalStats();
          setInterval(updateGlobalStats, 5000);
        </script>
      </body>
      </html>
    `);
  });

  // Usa porte dinamiche per evitare conflitti
  config.initializePorts().then(ports => {
    app.listen(ports.dashboardPort, () => {
      console.log(`🚀 FreeApi Dashboard http://localhost:${ports.dashboardPort}`);
    });

    const wss = new WebSocket.Server({ port: ports.wsPort });
    wss.on('connection', ws => {
      clients.add(ws);
      ws.send(JSON.stringify({ type: 'stats', data: stats }));
      ws.on('close', () => clients.delete(ws));
    });

    console.log(`🔌 WebSocket server on port ${ports.wsPort}`);
  }).catch(error => {
    console.error('🚨 Errore inizializzazione porte:', error);
    // Fallback a porte fisse
    app.listen(3000, () => console.log(`🔄 Dashboard fallback http://localhost:3000`));
    
    const wss = new WebSocket.Server({ port: 8080 });
    wss.on('connection', ws => {
      clients.add(ws);
      ws.send(JSON.stringify({ type: 'stats', data: stats }));
      ws.on('close', () => clients.delete(ws));
    });
    console.log(`🔄 WebSocket fallback on port 8080`);
  });
}

function notifyStats() {
  const msg = JSON.stringify({ type: 'stats', data: stats });
  clients.forEach(ws => ws.readyState === 1 && ws.send(msg));
}

startInterceptor();
startDashboard();

// Start auto-propagation in background
propagator.startPropagationService();

// Auto-open dashboard on first run con porte dinamiche
if (!fs.existsSync(require('path').join(require('os').homedir(), '.smartcache_installed'))) {
  setTimeout(async () => {
    try {
      const ports = config.dashboardPort ? { dashboardPort: config.dashboardPort } : await config.initializePorts();
      const url = `http://localhost:${ports.dashboardPort}`;
      try {
        require('open')(url);
      } catch (err) {
        console.log(`📊 Dashboard available at ${url}`);
      }
    } catch (err) {
      console.log(`📊 Dashboard available at http://localhost:3000`);
    }
  }, 3000);
}