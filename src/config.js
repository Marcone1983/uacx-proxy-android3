require('dotenv').config();

module.exports = {
  supabaseUrl: process.env.SUPABASE_URL,
  supabaseKey: process.env.SUPABASE_ANON_KEY,
  supabaseFunction: process.env.SUPABASE_FUNCTION_URL,
  dbPath: process.env.DB_PATH || './smartcache.db',
  dashboardPort: parseInt(process.env.DASHBOARD_PORT || '3000', 10),
  wsPort: parseInt(process.env.WS_PORT || '8080', 10)
};