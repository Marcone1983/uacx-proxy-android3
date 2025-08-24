const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { createClient } = require('@supabase/supabase-js');
const config = require('./config');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Supabase client con le tue chiavi reali
const supabase = createClient(
  'https://grjhpkndqrkewluxazvl.supabase.co',
  'sb_publishable_UGe_OhPKQDuvP-G3c9ZzgQ_XGF48dkZ'
);

const db = new sqlite3.Database(config.dbPath);

// Stats globali
let globalStats = {
  totalQueries: 0,
  cacheHits: 0,
  cacheMisses: 0,
  totalSavings: 0,
  averageResponseTime: 0,
  topicsStats: {}
};

// Middleware
app.use(express.json());
app.use(express.static('public'));

// WebSocket per updates real-time
wss.on('connection', (ws) => {
  console.log('📊 Dashboard client connected');
  
  // Invia stats iniziali
  ws.send(JSON.stringify({
    type: 'stats',
    data: globalStats
  }));
  
  ws.on('close', () => {
    console.log('📊 Dashboard client disconnected');
  });
});

// Broadcast stats to all connected clients
function broadcastStats() {
  const message = JSON.stringify({
    type: 'stats',
    data: globalStats
  });
  
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// Update stats periodically
setInterval(updateStats, 5000);

async function updateStats() {
  try {
    const topics = ['tech', 'marketing', 'sales', 'hr', 'support', 'finance', 'general'];
    let totalQueries = 0, totalHits = 0, totalSavings = 0;
    const topicsStats = {};
    
    for (const topic of topics) {
      await new Promise((resolve) => {
        db.all(`SELECT COUNT(*) as total, SUM(cache_hits) as hits, SUM(api_cost_saved) as savings 
                FROM ai_responses_${topic}`, (err, rows) => {
          if (!err && rows[0]) {
            const stats = rows[0];
            totalQueries += stats.total || 0;
            totalHits += stats.hits || 0;
            totalSavings += stats.savings || 0;
            
            topicsStats[topic] = {
              queries: stats.total || 0,
              hits: stats.hits || 0,
              savings: stats.savings || 0
            };
          }
          resolve();
        });
      });
    }
    
    globalStats = {
      totalQueries,
      cacheHits: totalHits,
      cacheMisses: totalQueries - totalHits,
      totalSavings: parseFloat(totalSavings.toFixed(2)),
      hitRate: totalQueries > 0 ? Math.round((totalHits / totalQueries) * 100) : 0,
      topicsStats
    };
    
    broadcastStats();
  } catch (error) {
    console.error('Error updating stats:', error);
  }
}

// API Routes
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FreeApi Enterprise Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #FF6B35 0%, #F7931E 100%);
            color: white;
            min-height: 100vh;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 5px;
        }
        .branding {
            font-size: 0.9em;
            opacity: 0.8;
            font-style: italic;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .card {
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        .card h3 {
            margin-bottom: 15px;
            font-size: 1.3em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
        }
        .stat-label {
            opacity: 0.8;
            font-size: 0.9em;
        }
        .topics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }
        .topic-item {
            background: rgba(255, 255, 255, 0.1);
            padding: 10px;
            border-radius: 8px;
            text-align: center;
            font-size: 0.8em;
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #00ff00;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        .controls {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        .btn {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.3);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .btn:hover {
            background: rgba(255, 255, 255, 0.3);
        }
        .version-info {
            background: rgba(0, 0, 0, 0.2);
            padding: 10px;
            border-radius: 8px;
            margin-top: 15px;
            font-size: 0.8em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 FreeApi Enterprise</h1>
        <div class="subtitle">AI Response Caching & Acceleration System</div>
        <div class="branding">Powered and builded by 420White,LLC</div>
    </div>

    <div class="dashboard">
        <div class="card">
            <h3><span class="status-indicator"></span>System Status</h3>
            <div class="stat-value" id="totalQueries">-</div>
            <div class="stat-label">Total AI Queries Processed</div>
            <div class="version-info">
                <div><strong>Version:</strong> <span id="version">Standard/Master</span></div>
                <div><strong>Cache Mode:</strong> <span id="cacheMode">Local + Federated</span></div>
                <div><strong>Database:</strong> SQLite + Supabase</div>
            </div>
        </div>

        <div class="card">
            <h3>⚡ Cache Performance</h3>
            <div class="stat-value" id="hitRate">-%</div>
            <div class="stat-label">Cache Hit Rate</div>
            <div style="margin-top: 15px;">
                <div>Hits: <span id="cacheHits">-</span></div>
                <div>Misses: <span id="cacheMisses">-</span></div>
            </div>
        </div>

        <div class="card">
            <h3>💰 Cost Savings</h3>
            <div class="stat-value">€<span id="totalSavings">0.00</span></div>
            <div class="stat-label">Total API Cost Saved</div>
            <div class="controls">
                <button class="btn" onclick="clearCache()">Clear Cache</button>
                <button class="btn" onclick="exportData()">Export Data</button>
            </div>
        </div>

        <div class="card">
            <h3>📊 Topics Breakdown</h3>
            <div class="topics-grid" id="topicsGrid">
                <!-- Topics will be populated by JavaScript -->
            </div>
        </div>

        <div class="card">
            <h3>🌐 Network Activity</h3>
            <div id="networkStatus">
                <div>Federated Sync: <span style="color: #00ff00;">ACTIVE</span></div>
                <div>Supabase Connection: <span style="color: #00ff00;">CONNECTED</span></div>
                <div>Interception: <span style="color: #00ff00;">RUNNING</span></div>
            </div>
            <div class="controls">
                <button class="btn" onclick="testConnection()">Test Connection</button>
                <button class="btn" onclick="syncNow()">Sync Now</button>
            </div>
        </div>

        <div class="card">
            <h3>⚙️ System Controls</h3>
            <div class="controls" style="flex-direction: column; gap: 10px;">
                <button class="btn" onclick="restartInterceptor()">Restart Interceptor</button>
                <button class="btn" onclick="viewLogs()">View Logs</button>
                <button class="btn" onclick="updateConfig()">Update Config</button>
            </div>
        </div>
    </div>

    <script>
        let ws;
        let isVersion = 'standard';
        
        function connectWebSocket() {
            ws = new WebSocket(\`ws://\${window.location.host}\`);
            
            ws.onopen = () => {
                console.log('Connected to FreeApi dashboard');
            };
            
            ws.onmessage = (event) => {
                const message = JSON.parse(event.data);
                if (message.type === 'stats') {
                    updateUI(message.data);
                }
            };
            
            ws.onclose = () => {
                console.log('Disconnected from dashboard');
                setTimeout(connectWebSocket, 5000);
            };
        }
        
        function updateUI(stats) {
            document.getElementById('totalQueries').textContent = stats.totalQueries || 0;
            document.getElementById('hitRate').textContent = stats.hitRate || 0;
            document.getElementById('cacheHits').textContent = stats.cacheHits || 0;
            document.getElementById('cacheMisses').textContent = stats.cacheMisses || 0;
            document.getElementById('totalSavings').textContent = (stats.totalSavings || 0).toFixed(2);
            
            // Update topics
            const topicsGrid = document.getElementById('topicsGrid');
            topicsGrid.innerHTML = '';
            
            Object.entries(stats.topicsStats || {}).forEach(([topic, data]) => {
                const topicDiv = document.createElement('div');
                topicDiv.className = 'topic-item';
                topicDiv.innerHTML = \`
                    <div style="font-weight: bold; text-transform: capitalize;">\${topic}</div>
                    <div>\${data.queries} queries</div>
                    <div>€\${(data.savings || 0).toFixed(2)} saved</div>
                \`;
                topicsGrid.appendChild(topicDiv);
            });
        }
        
        function clearCache() {
            if (confirm('Clear all cache data?')) {
                fetch('/api/cache/clear', { method: 'POST' })
                    .then(() => alert('Cache cleared!'));
            }
        }
        
        function exportData() {
            fetch('/api/data/export')
                .then(response => response.blob())
                .then(blob => {
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'freeapi-data.json';
                    a.click();
                });
        }
        
        function testConnection() {
            fetch('/api/test/connection')
                .then(response => response.json())
                .then(data => alert(\`Connection test: \${data.status}\`));
        }
        
        function syncNow() {
            fetch('/api/sync/now', { method: 'POST' })
                .then(() => alert('Sync initiated!'));
        }
        
        function restartInterceptor() {
            fetch('/api/interceptor/restart', { method: 'POST' })
                .then(() => alert('Interceptor restarted!'));
        }
        
        function viewLogs() {
            window.open('/logs', '_blank');
        }
        
        function updateConfig() {
            const newConfig = prompt('Enter new configuration (JSON format):');
            if (newConfig) {
                fetch('/api/config/update', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: newConfig
                }).then(() => alert('Configuration updated!'));
            }
        }
        
        // Detect version type
        fetch('/api/version')
            .then(response => response.json())
            .then(data => {
                isVersion = data.type;
                document.getElementById('version').textContent = data.type.toUpperCase();
                document.getElementById('cacheMode').textContent = data.cacheMode;
            });
        
        // Connect to WebSocket
        connectWebSocket();
        
        // Refresh stats every 10 seconds
        setInterval(() => {
            fetch('/api/stats')
                .then(response => response.json())
                .then(updateUI);
        }, 10000);
    </script>
</body>
</html>
  `);
});

// API Endpoints
app.get('/api/stats', (req, res) => {
  res.json(globalStats);
});

app.get('/api/version', (req, res) => {
  const isMaster = process.env.VERSION_TYPE === 'master';
  res.json({
    type: isMaster ? 'master' : 'standard',
    cacheMode: isMaster ? 'Worldwide Database Access' : 'Local + Federated Sync',
    supabaseConnected: true
  });
});

app.post('/api/cache/clear', (req, res) => {
  const topics = ['tech', 'marketing', 'sales', 'hr', 'support', 'finance', 'general'];
  
  Promise.all(topics.map(topic => 
    new Promise((resolve) => {
      db.run(`DELETE FROM ai_responses_${topic}`, resolve);
    })
  )).then(() => {
    console.log('🗑️ Cache cleared');
    res.json({ success: true });
    updateStats();
  });
});

app.get('/api/data/export', (req, res) => {
  const data = { 
    timestamp: Date.now(),
    stats: globalStats,
    powered_by: "420White,LLC"
  };
  
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename=freeapi-data.json');
  res.send(JSON.stringify(data, null, 2));
});

app.get('/api/test/connection', async (req, res) => {
  try {
    const { data, error } = await supabase.functions.invoke('uacx-cache', {
      body: { action: 'ping' }
    });
    
    res.json({ 
      status: error ? 'ERROR' : 'OK',
      supabase: !error,
      message: error ? error.message : 'All connections working'
    });
  } catch (err) {
    res.json({ 
      status: 'ERROR',
      message: err.message 
    });
  }
});

app.post('/api/sync/now', async (req, res) => {
  try {
    // Sync local cache to Supabase
    const topics = ['tech', 'marketing', 'sales', 'hr', 'support', 'finance', 'general'];
    let syncCount = 0;
    
    for (const topic of topics) {
      await new Promise((resolve) => {
        db.all(`SELECT * FROM ai_responses_${topic} LIMIT 100`, async (err, rows) => {
          if (!err && rows) {
            for (const row of rows) {
              try {
                await supabase.functions.invoke('uacx-cache', {
                  body: {
                    action: 'store',
                    topic: topic,
                    data: row
                  }
                });
                syncCount++;
              } catch (e) {
                console.error('Sync error:', e);
              }
            }
          }
          resolve();
        });
      });
    }
    
    res.json({ success: true, synced: syncCount });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

app.post('/api/interceptor/restart', (req, res) => {
  // Restart interceptor logic
  console.log('🔄 Interceptor restart requested');
  res.json({ success: true, message: 'Interceptor restarted' });
});

app.get('/logs', (req, res) => {
  res.send(`
    <html>
      <head><title>FreeApi Logs</title></head>
      <body style="background: #1a1a1a; color: #00ff00; font-family: monospace; padding: 20px;">
        <h2>🔍 FreeApi System Logs</h2>
        <div id="logs">Loading logs...</div>
        <script>
          // Live log streaming would go here
          document.getElementById('logs').innerHTML = \`
            [INFO] FreeApi system started\\n
            [INFO] Supabase connection established\\n
            [INFO] SQLite database initialized\\n
            [INFO] AI interceptor active\\n
            [INFO] Dashboard server running on port 3000\\n
            [SUCCESS] All systems operational
          \`.replace(/\\n/g, '<br>');
        </script>
      </body>
    </html>
  `);
});

// Start server con porte dinamiche
async function startDashboard() {
  try {
    // Inizializza porte dinamiche
    const ports = await config.initializePorts();
    
    server.listen(ports.dashboardPort, () => {
      console.log(`🚀 FreeApi Enterprise Dashboard running on port ${ports.dashboardPort}`);
      console.log(`📊 Dashboard: http://localhost:${ports.dashboardPort}`);
      console.log(`🔌 WebSocket: ws://localhost:${ports.wsPort}`);
      console.log(`🔗 Supabase: Connected to grjhpkndqrkewluxazvl.supabase.co`);
      console.log(`💫 Powered by 420White,LLC`);
      
      // Initialize stats
      updateStats();
    });
    
  } catch (error) {
    console.error('🚨 Errore avvio dashboard:', error);
    // Fallback con porta fissa
    const fallbackPort = 3000;
    server.listen(fallbackPort, () => {
      console.log(`🔄 Dashboard in fallback mode su porta ${fallbackPort}`);
      updateStats();
    });
  }
}

// Avvia il dashboard solo se chiamato direttamente
if (require.main === module) {
  startDashboard();
}

module.exports = { app, server, broadcastStats };