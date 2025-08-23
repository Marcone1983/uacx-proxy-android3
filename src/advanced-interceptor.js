const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { exec } = require('child_process');
const os = require('os');

class AdvancedInterceptor {
  constructor(db, stats, notifyStats) {
    this.db = db;
    this.stats = stats;
    this.notifyStats = notifyStats;
    this.aiEndpoints = [
      'api.openai.com',
      'api.anthropic.com',
      'api.cohere.ai',
      'generativelanguage.googleapis.com',
      'api.huggingface.co',
      'copilot-proxy.githubusercontent.com',
      'api.github.com/copilot',
      'api.replicate.com',
      'api.stability.ai',
      'api.midjourney.com',
      'claude.ai',
      'chat.openai.com',
      'gemini.google.com',
      'perplexity.ai'
    ];
  }

  // Level 1: Runtime HTTP/HTTPS Hooking (Node.js)
  hookNodeRuntime() {
    const originalHttpRequest = http.request;
    const originalHttpsRequest = https.request;
    
    const self = this;

    // Hook HTTP
    http.request = function(...args) {
      return self.interceptRequest('http', originalHttpRequest, ...args);
    };

    // Hook HTTPS  
    https.request = function(...args) {
      return self.interceptRequest('https', originalHttpsRequest, ...args);
    };

    // Hook fetch if exists
    if (global.fetch) {
      const originalFetch = global.fetch;
      global.fetch = async function(url, options) {
        return self.interceptFetch(originalFetch, url, options);
      };
    }

    // Hook axios if loaded
    try {
      const axios = require('axios');
      axios.interceptors.request.use(
        config => self.interceptAxiosRequest(config),
        error => Promise.reject(error)
      );
      axios.interceptors.response.use(
        response => self.interceptAxiosResponse(response),
        error => Promise.reject(error)
      );
    } catch (e) {
      // Axios not installed
    }

    console.log('✅ Advanced Node.js runtime hooks installed');
  }

  // Level 2: System Proxy Configuration
  setupSystemProxy() {
    const platform = os.platform();
    const proxyPort = 8888;

    if (platform === 'win32') {
      // Windows proxy
      exec(`netsh winhttp set proxy proxy-server="127.0.0.1:${proxyPort}"`, (err) => {
        if (!err) console.log('✅ Windows system proxy configured');
      });
    } else if (platform === 'darwin') {
      // macOS proxy
      exec(`networksetup -setwebproxy "Wi-Fi" 127.0.0.1 ${proxyPort}`, () => {});
      exec(`networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 ${proxyPort}`, () => {
        console.log('✅ macOS system proxy configured');
      });
    } else if (platform === 'linux') {
      // Linux iptables
      this.aiEndpoints.forEach(endpoint => {
        exec(`iptables -t nat -A OUTPUT -p tcp --dport 443 -d ${endpoint} -j REDIRECT --to-port ${proxyPort}`, () => {});
      });
      console.log('✅ Linux iptables rules configured');
    }

    // Start proxy server
    this.startProxyServer(proxyPort);
  }

  // Proxy server to handle system-level interception
  startProxyServer(port) {
    const proxyServer = http.createServer((req, res) => {
      const url = req.url;
      const host = req.headers.host;

      if (this.isAIEndpoint(host)) {
        this.handleProxiedRequest(req, res);
      } else {
        // Pass through non-AI requests
        this.forwardRequest(req, res);
      }
    });

    proxyServer.listen(port, () => {
      console.log(`🌐 Proxy server listening on port ${port}`);
    });
  }

  // Level 3: Browser Extension Injection
  injectBrowserExtension() {
    const extensionCode = `
(function() {
  // Intercept fetch globally
  const originalFetch = window.fetch;
  
  window.fetch = async function(url, options = {}) {
    const aiEndpoints = [
      'api.openai.com',
      'api.anthropic.com',
      'generativelanguage.googleapis.com',
      'api.cohere.ai',
      'claude.ai',
      'chat.openai.com'
    ];
    
    const isAICall = aiEndpoints.some(endpoint => url.includes(endpoint));
    
    if (isAICall) {
      console.log('🎯 AI API call intercepted:', url);
      
      // Extract query from request body
      let query = '';
      if (options.body) {
        try {
          const body = JSON.parse(options.body);
          query = body.messages?.[body.messages.length - 1]?.content || 
                  body.prompt || 
                  body.inputs || 
                  JSON.stringify(body);
        } catch (e) {
          query = options.body;
        }
      }
      
      // Check local cache via extension storage
      const cacheKey = 'ai_cache_' + btoa(query).slice(0, 20);
      const cached = localStorage.getItem(cacheKey);
      
      if (cached) {
        console.log('⚡ Cache HIT from browser extension');
        return new Response(cached, {
          status: 200,
          headers: { 'x-smartcache': 'hit' }
        });
      }
      
      // Make real request
      const response = await originalFetch(url, options);
      const responseText = await response.text();
      
      // Cache response
      localStorage.setItem(cacheKey, responseText);
      
      // Track stats
      const stats = JSON.parse(localStorage.getItem('ai_stats') || '{}');
      stats.total = (stats.total || 0) + 1;
      stats.misses = (stats.misses || 0) + 1;
      localStorage.setItem('ai_stats', JSON.stringify(stats));
      
      return new Response(responseText, response);
    }
    
    return originalFetch(url, options);
  };
  
  // Intercept XMLHttpRequest
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;
  
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this._smartcache_url = url;
    this._smartcache_method = method;
    return originalXHROpen.call(this, method, url, ...args);
  };
  
  XMLHttpRequest.prototype.send = function(body) {
    const url = this._smartcache_url;
    
    if (url && url.includes('api.openai.com')) {
      console.log('🎯 XHR AI call intercepted');
      // Similar caching logic
    }
    
    return originalXHRSend.call(this, body);
  };
  
  console.log('✅ SmartCache browser extension injected');
})();
    `;

    // Save as browser extension
    require('fs').writeFileSync(
      '/data/data/com.termux/files/home/smartcache/browser-extension/content.js',
      extensionCode
    );
  }

  // Helper methods
  isAIEndpoint(hostname) {
    return this.aiEndpoints.some(endpoint => 
      hostname && hostname.includes(endpoint)
    );
  }

  interceptRequest(protocol, originalMethod, ...args) {
    const options = typeof args[0] === 'string' ? new URL(args[0]) : args[0];
    const hostname = options.hostname || options.host;

    if (this.isAIEndpoint(hostname)) {
      return this.handleAIRequest(originalMethod, protocol, ...args);
    }

    return originalMethod.apply(protocol === 'https' ? https : http, args);
  }

  async interceptFetch(originalFetch, url, options) {
    if (this.isAIEndpoint(url)) {
      console.log('🎯 Fetch AI call intercepted:', url);
      
      const body = options?.body;
      const query = this.extractQuery(body);
      const cached = await this.checkCache(query);
      
      if (cached) {
        this.stats.hits++;
        this.stats.savings += 0.15;
        this.notifyStats();
        return new Response(cached, { status: 200 });
      }
      
      const response = await originalFetch(url, options);
      const responseText = await response.text();
      await this.saveToCache(query, responseText);
      
      return new Response(responseText, response);
    }
    
    return originalFetch(url, options);
  }

  interceptAxiosRequest(config) {
    if (this.isAIEndpoint(config.url)) {
      config.metadata = { startTime: Date.now() };
      console.log('🎯 Axios AI request intercepted');
    }
    return config;
  }

  async interceptAxiosResponse(response) {
    if (response.config.metadata) {
      const responseTime = Date.now() - response.config.metadata.startTime;
      console.log(`✅ AI response received in ${responseTime}ms`);
      
      // Cache the response
      const query = this.extractQuery(response.config.data);
      await this.saveToCache(query, JSON.stringify(response.data));
    }
    return response;
  }

  extractQuery(body) {
    try {
      if (typeof body === 'string') {
        const parsed = JSON.parse(body);
        return parsed.messages?.[parsed.messages.length - 1]?.content || 
               parsed.prompt || 
               parsed.inputs || 
               body;
      }
      return body?.messages?.[body.messages.length - 1]?.content || 
             body?.prompt || 
             JSON.stringify(body);
    } catch {
      return body || '';
    }
  }

  async checkCache(query) {
    const hash = crypto.createHash('sha256').update(query).digest('hex').slice(0, 16);
    const topic = this.classifyTopic(query);
    
    return new Promise((resolve) => {
      this.db.get(
        `SELECT response_text FROM ai_responses_${topic} WHERE query_hash = ?`,
        [hash],
        (err, row) => {
          if (row) {
            console.log('⚡ Cache HIT');
            resolve(row.response_text);
          } else {
            resolve(null);
          }
        }
      );
    });
  }

  async saveToCache(query, response) {
    const hash = crypto.createHash('sha256').update(query).digest('hex').slice(0, 16);
    const topic = this.classifyTopic(query);
    const id = crypto.randomUUID();
    
    this.db.run(
      `INSERT OR REPLACE INTO ai_responses_${topic} 
       (id, query_hash, query_text, response_text, timestamp)
       VALUES (?, ?, ?, ?, ?)`,
      [id, hash, query, response, Date.now()]
    );
  }

  classifyTopic(query) {
    const q = query.toLowerCase();
    const patterns = {
      tech: /\b(code|function|api|bug|error|programming|javascript|python|react)\b/i,
      marketing: /\b(campaign|social|seo|brand|content|email|audience)\b/i,
      sales: /\b(prospect|deal|crm|customer|lead|pipeline|quota)\b/i,
      hr: /\b(hiring|employee|payroll|benefits|recruiting|onboarding)\b/i,
      support: /\b(ticket|help|issue|problem|troubleshoot|resolve)\b/i,
      finance: /\b(budget|invoice|accounting|revenue|profit|expense)\b/i
    };

    for (const [topic, pattern] of Object.entries(patterns)) {
      if (pattern.test(q)) return topic;
    }
    return 'general';
  }

  handleAIRequest(originalMethod, protocol, ...args) {
    // Complex request handling with full interception
    const req = originalMethod.apply(protocol === 'https' ? https : http, args);
    
    let requestBody = '';
    const originalWrite = req.write;
    const originalEnd = req.end;

    req.write = (chunk, ...writeArgs) => {
      if (chunk) requestBody += chunk.toString();
      return originalWrite.call(req, chunk, ...writeArgs);
    };

    req.end = async (chunk, ...endArgs) => {
      if (chunk) requestBody += chunk.toString();
      
      const query = this.extractQuery(requestBody);
      const cached = await this.checkCache(query);
      
      if (cached) {
        // Emit cached response
        const mockRes = this.createMockResponse(cached);
        req.emit('response', mockRes);
        
        this.stats.hits++;
        this.stats.savings += 0.15;
        this.notifyStats();
        
        return;
      }
      
      // Continue with real request
      req.on('response', (res) => {
        let responseData = '';
        res.on('data', chunk => responseData += chunk);
        res.on('end', async () => {
          await this.saveToCache(query, responseData);
          this.stats.misses++;
          this.notifyStats();
        });
      });
      
      return originalEnd.call(req, chunk, ...endArgs);
    };

    return req;
  }

  createMockResponse(data) {
    const { IncomingMessage } = require('http');
    const res = new IncomingMessage();
    
    process.nextTick(() => {
      res.emit('data', Buffer.from(data));
      res.emit('end');
    });
    
    res.statusCode = 200;
    res.headers = { 
      'content-type': 'application/json',
      'x-smartcache': 'hit'
    };
    
    return res;
  }
}

module.exports = AdvancedInterceptor;