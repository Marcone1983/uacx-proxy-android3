require('dotenv').config();
const net = require('net');

// Funzione per trovare porta libera
async function findFreePort(startPort = 3000, endPort = 3050) {
  for (let port = startPort; port <= endPort; port++) {
    if (await isPortFree(port)) {
      return port;
    }
  }
  throw new Error(`Nessuna porta libera trovata tra ${startPort}-${endPort}`);
}

function isPortFree(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(port, () => {
      server.once('close', () => resolve(true));
      server.close();
    });
    server.on('error', () => resolve(false));
  });
}

// Configurazione con porte dinamiche
const config = {
  supabaseUrl: process.env.SUPABASE_URL || 'https://grjhpkndqrkewluxazvl.supabase.co',
  supabaseKey: process.env.SUPABASE_ANON_KEY || 'sb_publishable_UGe_OhPKQDuvP-G3c9ZzgQ_XGF48dkZ',
  supabaseFunction: process.env.SUPABASE_FUNCTION_URL || 'https://grjhpkndqrkewluxazvl.supabase.co/functions/v1/uacx-cache',
  dbPath: process.env.DB_PATH || './freeapi.db',
  dashboardPort: null, // Sarà assegnata dinamicamente
  wsPort: null, // Sarà assegnata dinamicamente
  findFreePort,
  isPortFree
};

// Inizializza porte dinamiche
config.initializePorts = async function() {
  try {
    // Cerca porte libere in range più ampio per evitare conflitti
    console.log('🔍 Cercando porte libere per evitare conflitti...');
    
    // Per Dashboard: prova dal 3000 al 3100
    let dashboardFound = false;
    for (let port = 3000; port <= 3100 && !dashboardFound; port++) {
      if (await isPortFree(port)) {
        config.dashboardPort = port;
        console.log(`✅ Dashboard su porta: ${port}`);
        dashboardFound = true;
      }
    }
    
    if (!dashboardFound) {
      // Fallback a range alto
      config.dashboardPort = 8000 + Math.floor(Math.random() * 100);
      console.log(`🔄 Dashboard fallback su porta: ${config.dashboardPort}`);
    }
    
    // Per WebSocket: prova dal 8080 al 8200
    let wsFound = false;
    for (let port = 8080; port <= 8200 && !wsFound; port++) {
      if (await isPortFree(port)) {
        config.wsPort = port;
        console.log(`✅ WebSocket su porta: ${port}`);
        wsFound = true;
      }
    }
    
    if (!wsFound) {
      // Fallback a range alto
      config.wsPort = 9000 + Math.floor(Math.random() * 100);
      console.log(`🔄 WebSocket fallback su porta: ${config.wsPort}`);
    }
    
    console.log(`🚀 FreeApi Dashboard: http://localhost:${config.dashboardPort}`);
    console.log(`🔌 WebSocket: ws://localhost:${config.wsPort}`);
    
    return { dashboardPort: config.dashboardPort, wsPort: config.wsPort };
  } catch (error) {
    console.error('🚨 Errore inizializzazione porte:', error.message);
    // Fallback sicuro con porte casuali alte
    config.dashboardPort = 8000 + Math.floor(Math.random() * 1000);
    config.wsPort = 9000 + Math.floor(Math.random() * 1000);
    console.log(`🎲 Fallback porte casuali sicure: Dashboard ${config.dashboardPort}, WS ${config.wsPort}`);
    return { dashboardPort: config.dashboardPort, wsPort: config.wsPort };
  }
};

module.exports = config;