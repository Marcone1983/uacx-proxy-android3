# SmartCache AI Enterprise - Sistema Federato

Sistema enterprise **federato** di caching AI con propagazione automatica in rete e sincronizzazione centrale Supabase.

## 🚀 Caratteristiche Principali

### 🌐 Architettura Federata
- **Cache a 2 livelli**: Locale (SQLite) + Centrale (Supabase)
- **Cache globale condivisa**: Le risposte salvate da un client sono disponibili per tutti
- **Zero chiamate API duplicate**: Se qualcuno ha già fatto la domanda, tutti ottengono la risposta dalla cache
- **Auto-propagazione in rete**: L'exe si installa automaticamente su tutti i PC della rete

### ⚡ Funzionalità Core Avanzate
- **Interceptor multi-livello**: 
  - Runtime HTTP/HTTPS hooking (Node.js, fetch, axios)
  - System proxy configuration (Windows, macOS, Linux)  
  - Browser extension injection (Chrome, Firefox, Edge)
  - Process-level API interception
- **Dashboard enterprise**: Statistiche locali + globali in tempo reale
- **Partizionamento semantico**: AI automatico per topic classification
- **Sincronizzazione federata**: Cache globale istantanea cross-client
- **Auto-propagation**: Deploy silenzioso via Active Directory / SSH
- **Browser universale**: Intercetta ChatGPT, Claude.ai, Gemini web apps

## 📋 Prerequisiti

- Node.js 18+ installato
- Account Supabase con API key
- SQLite3

## 🎯 Come Funziona il Sistema Federato

1. **Primo avvio**: Un utente esegue `smartcache.exe`
2. **Auto-propagazione**: Il sistema scansiona la rete e si installa automaticamente su tutti i PC raggiungibili
3. **Dashboard locale**: Ogni PC apre la sua dashboard su `http://localhost:3000`
4. **Cache condivisa**: 
   - Utente A fa una domanda a ChatGPT → risposta salvata in Supabase
   - Utente B fa la stessa domanda → riceve la risposta dalla cache centrale (nessuna chiamata API!)
5. **Risparmio massivo**: L'intera azienda paga solo UNA volta per ogni domanda unica

## 🔧 Installazione

### 🚀 Metodo Rapido: EXE Auto-Propagante

```bash
# Scarica l'exe precompilato
curl -L -o smartcache.exe https://github.com/Marcone1983/uacx-proxy-android3/releases/latest/download/smartcache.exe

# Esegui come amministratore
smartcache.exe

# Il sistema:
# 1. Si installa localmente
# 2. Scansiona la rete
# 3. Si auto-installa su tutti i PC trovati
# 4. Apre la dashboard automaticamente
```

### 🏢 Deploy Enterprise (Active Directory)

```powershell
# 1. Clona e prepara deployment
git clone https://github.com/Marcone1983/uacx-proxy-android3 smartcache
cd smartcache
npm install

# 2. Configura .env con Supabase credentials
# SUPABASE_ANON_KEY=your_key_here

# 3. Build enterprise deployment
npm run deploy:enterprise

# 4. Esegui da Domain Controller
.\deployment\deploy-enterprise.ps1

# Auto-installa su TUTTI i computer del dominio AD!
```

### Metodo 2: Build da sorgente

```bash
# Clone del repository
git clone https://github.com/Marcone1983/uacx-proxy-android3 smartcache
cd smartcache

# Installazione dipendenze
npm install

# Configurazione ambiente
cp .env.example .env
# Modifica .env inserendo la tua SUPABASE_ANON_KEY

# Avvio servizio
npm start
```

### Metodo 2: Installer automatici

#### Windows (PowerShell come Admin)
```powershell
.\src\installers\install_windows.ps1
```

#### macOS
```bash
sudo sh src/installers/install_macos.sh
```

#### Linux
```bash
sudo sh src/installers/install_linux.sh
```

### Metodo 3: Deploy di rete (Windows AD)
```powershell
# Da un controller di dominio
.\src\installers\network_deploy.ps1
```

## 🧪 Testing del Sistema

Verifica che l'intercettazione funzioni:

```bash
# Test completo di tutte le funzionalità
npm run test:intercept

# Output atteso:
# ✅ OpenAI API interception working
# ✅ Anthropic/Claude interception working  
# ✅ Browser extension injection successful
# ⚡ Cache performance optimized
```

## 🖥️ Dashboard Enterprise

Ogni client ha la sua dashboard completa:
```
http://localhost:3000
```

**Statistiche Locali:**
- Richieste totali del PC
- Cache hits/misses locali
- Costi risparmiati localmente

**Statistiche Globali:**
- Cache hits di tutta l'azienda  
- Risparmio totale network-wide
- Numero di client attivi
- Hit rate globale

**Analytics Real-time:**
- Traffic per topic (tech, marketing, sales, etc.)
- Top queries più frequenti
- Performance trends

## 📦 Build eseguibile

Per creare un eseguibile standalone:

```bash
# Installa pkg globalmente
npm install -g pkg

# Build per tutte le piattaforme
npm run build

# Trova gli eseguibili in dist/
```

## 🔐 Configurazione Supabase

1. Crea un progetto su [Supabase](https://supabase.com)
2. Copia l'URL del progetto e l'anon key
3. Inserisci i valori nel file `.env`:
   ```
   SUPABASE_URL=https://tuoprogetto.supabase.co
   SUPABASE_ANON_KEY=tua_api_key_qui
   ```

## 📊 Topics supportati

Il sistema classifica automaticamente le query in:
- `tech`: programmazione, API, deploy
- `marketing`: campagne, SEO, social media
- `sales`: CRM, prospect, deal
- `hr`: hiring, payroll
- `support`: ticket, help desk
- `finance`: budget, accounting
- `general`: tutto il resto

## 🛠️ Comandi utili

```bash
# Avvia solo interceptor
node src/smartcache.js

# Avvia solo dashboard
node src/dashboard.js

# Test connessione Supabase
curl -X POST https://grjhpkndqrkewluxazvl.functions.supabase.co/uacx-cache \
  -H "apikey: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query":"test","response":"ok"}'
```

## 📝 Struttura Database

Ogni tabella `ai_responses_[topic]` contiene:
- `query_hash`: hash SHA256 della query
- `query_text`: testo originale
- `response_text`: risposta AI
- `cache_hits`: numero di hit dalla cache
- `api_cost_saved`: costo totale risparmiato
- `response_time_ms`: tempo di risposta

## ⚙️ Variabili ambiente

| Variabile | Default | Descrizione |
|-----------|---------|-------------|
| SUPABASE_URL | - | URL progetto Supabase |
| SUPABASE_ANON_KEY | - | Chiave API Supabase |
| DB_PATH | ./smartcache.db | Path database SQLite |
| DASHBOARD_PORT | 3000 | Porta dashboard web |
| WS_PORT | 8080 | Porta WebSocket |

## 🚨 Troubleshooting

### Errore "EADDRINUSE"
Le porte 3000 o 8080 sono già in uso. Modifica `.env`:
```
DASHBOARD_PORT=3001
WS_PORT=8081
```

### Supabase sync fallisce
Verifica:
1. API key corretta in `.env`
2. Connessione internet attiva
3. Function endpoint corretto

### Cache non funziona
Controlla che l'applicazione usi una delle librerie supportate:
- axios
- node fetch
- XMLHttpRequest

## 📄 Licenza

MIT

## 🤝 Contributi

Pull request benvenute! Per modifiche importanti, apri prima una issue.

## 📧 Supporto

Per problemi o domande: [apri una issue](https://github.com/Marcone1983/uacx-proxy-android3/issues)