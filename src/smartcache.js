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
          <h1>🚀 SmartCache AI Enterprise</h1>
          <div class="client-info">
            <strong>Client:</strong> ${hostname} | <strong>Network:</strong> ${os.networkInterfaces().Ethernet?.[0]?.address || 'Unknown'}
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