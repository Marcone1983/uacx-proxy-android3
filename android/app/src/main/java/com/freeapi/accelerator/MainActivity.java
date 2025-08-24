package com.freeapi.accelerator;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;
import android.util.Log;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class MainActivity extends Activity {
    private WebView webView;
    private LinearLayout splashLayout;
    private LinearLayout languageLayout;
    private TextView statusText;
    private ProgressBar progressBar;
    private SharedPreferences prefs;
    private boolean isMasterVersion = false;
    private String selectedLanguage = "it";
    private int retryCount = 0;
    private final int MAX_RETRIES = 15;
    
    private static final String TAG = "MainActivity";
    private static final int PERMISSIONS_REQUEST_CODE = 1000;
    private static final String[] REQUIRED_PERMISSIONS = {
        Manifest.permission.INTERNET,
        Manifest.permission.ACCESS_NETWORK_STATE,
        Manifest.permission.ACCESS_WIFI_STATE,
        Manifest.permission.WAKE_LOCK,
        Manifest.permission.FOREGROUND_SERVICE,
        Manifest.permission.RECEIVE_BOOT_COMPLETED
    };
    
    private Map<String, Map<String, String>> translations = new HashMap<>();
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        Log.i(TAG, "🚀 FreeApi Enterprise MainActivity starting...");
        
        prefs = getSharedPreferences("FreeApiPrefs", MODE_PRIVATE);
        selectedLanguage = prefs.getString("language", "it");
        
        initializeTranslations();
        detectVersionType();
        createSplashUI();
        
        if (prefs.contains("language")) {
            Log.i(TAG, "Language already selected: " + selectedLanguage);
            checkAndRequestPermissions();
        } else {
            Log.i(TAG, "No language selected, showing language selection");
            showLanguageSelection();
        }
    }
    
    private void initializeTranslations() {
        Log.i(TAG, "🌍 Initializing multilingual support...");
        
        Map<String, String> italian = new HashMap<>();
        italian.put("welcome", "Benvenuto in FreeApi");
        italian.put("select_language", "Seleziona la tua lingua");
        italian.put("powered_by", "Powered and builded by 420White,LLC");
        italian.put("ai_accelerator", "Acceleratore AI Enterprise");
        italian.put("version_standard", "Versione Standard - Cache Locale + Sync Federato");
        italian.put("version_master", "Versione Master - Accesso Database Mondiale");
        italian.put("loading", "Caricamento in corso...");
        italian.put("connecting", "Connessione al server...");
        italian.put("permissions_required", "Autorizzazioni Necessarie");
        italian.put("grant_permissions", "Concedi Autorizzazioni");
        italian.put("continue", "Continua");
        italian.put("server_starting", "Avvio server in corso...");
        italian.put("diagnostics_running", "Diagnostica Enterprise attiva...");
        
        Map<String, String> english = new HashMap<>();
        english.put("welcome", "Welcome to FreeApi");
        english.put("select_language", "Select your language");
        english.put("powered_by", "Powered and builded by 420White,LLC");
        english.put("ai_accelerator", "Enterprise AI Accelerator");
        english.put("version_standard", "Standard Version - Local Cache + Federated Sync");
        english.put("version_master", "Master Version - Worldwide Database Access");
        english.put("loading", "Loading...");
        english.put("connecting", "Connecting to server...");
        english.put("permissions_required", "Permissions Required");
        english.put("grant_permissions", "Grant Permissions");
        english.put("continue", "Continue");
        english.put("server_starting", "Starting server...");
        english.put("diagnostics_running", "Enterprise diagnostics running...");
        
        Map<String, String> spanish = new HashMap<>();
        spanish.put("welcome", "Bienvenido a FreeApi");
        spanish.put("select_language", "Selecciona tu idioma");
        spanish.put("powered_by", "Powered and builded by 420White,LLC");
        spanish.put("ai_accelerator", "Acelerador AI Enterprise");
        spanish.put("version_standard", "Versión Estándar - Caché Local + Sync Federado");
        spanish.put("version_master", "Versión Master - Acceso Base de Datos Mundial");
        spanish.put("loading", "Cargando...");
        spanish.put("connecting", "Conectando al servidor...");
        spanish.put("permissions_required", "Permisos Requeridos");
        spanish.put("grant_permissions", "Conceder Permisos");
        spanish.put("continue", "Continuar");
        spanish.put("server_starting", "Iniciando servidor...");
        spanish.put("diagnostics_running", "Diagnósticos Enterprise activos...");
        
        Map<String, String> french = new HashMap<>();
        french.put("welcome", "Bienvenue dans FreeApi");
        french.put("select_language", "Sélectionnez votre langue");
        french.put("powered_by", "Powered and builded by 420White,LLC");
        french.put("ai_accelerator", "Accélérateur AI Enterprise");
        french.put("version_standard", "Version Standard - Cache Local + Sync Fédéré");
        french.put("version_master", "Version Master - Accès Base de Données Mondiale");
        french.put("loading", "Chargement...");
        french.put("connecting", "Connexion au serveur...");
        french.put("permissions_required", "Autorisations Requises");
        french.put("grant_permissions", "Accorder les Autorisations");
        french.put("continue", "Continuer");
        french.put("server_starting", "Démarrage du serveur...");
        french.put("diagnostics_running", "Diagnostics Enterprise en cours...");
        
        Map<String, String> german = new HashMap<>();
        german.put("welcome", "Willkommen bei FreeApi");
        german.put("select_language", "Wählen Sie Ihre Sprache");
        german.put("powered_by", "Powered and builded by 420White,LLC");
        german.put("ai_accelerator", "Enterprise AI-Beschleuniger");
        german.put("version_standard", "Standard Version - Lokaler Cache + Föderierte Sync");
        german.put("version_master", "Master Version - Weltweiter Datenbankzugriff");
        german.put("loading", "Laden...");
        german.put("connecting", "Verbindung zum Server...");
        german.put("permissions_required", "Berechtigungen Erforderlich");
        german.put("grant_permissions", "Berechtigungen Erteilen");
        german.put("continue", "Fortfahren");
        german.put("server_starting", "Server wird gestartet...");
        german.put("diagnostics_running", "Enterprise Diagnostik läuft...");
        
        translations.put("it", italian);
        translations.put("en", english);
        translations.put("es", spanish);
        translations.put("fr", french);
        translations.put("de", german);
        
        Log.i(TAG, "✅ Multilingual support initialized for " + translations.size() + " languages");
    }
    
    private String getText(String key) {
        Map<String, String> lang = translations.get(selectedLanguage);
        return lang != null ? lang.get(key) : translations.get("en").get(key);
    }
    
    private void detectVersionType() {
        try {
            Class<?> buildConfigClass = Class.forName(getPackageName() + ".BuildConfig");
            Field isMasterField = buildConfigClass.getField("IS_MASTER");
            isMasterVersion = (Boolean) isMasterField.get(null);
            Log.i(TAG, "🎯 Version detected: " + (isMasterVersion ? "MASTER" : "STANDARD"));
        } catch (Exception e) {
            Log.w(TAG, "Could not detect version type, defaulting to STANDARD", e);
            isMasterVersion = false;
        }
    }
    
    private void createSplashUI() {
        Log.i(TAG, "🎨 Creating enterprise splash UI...");
        
        LinearLayout mainLayout = new LinearLayout(this);
        mainLayout.setOrientation(LinearLayout.VERTICAL);
        mainLayout.setGravity(Gravity.CENTER);
        mainLayout.setBackgroundColor(Color.parseColor("#FF6B35"));
        mainLayout.setPadding(50, 50, 50, 50);
        
        // Logo placeholder
        ImageView logo = new ImageView(this);
        logo.setLayoutParams(new LinearLayout.LayoutParams(200, 200));
        logo.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        mainLayout.addView(logo);
        
        // Title
        TextView title = new TextView(this);
        title.setText("FreeApi");
        title.setTextSize(32);
        title.setTextColor(Color.WHITE);
        title.setTypeface(null, Typeface.BOLD);
        title.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        titleParams.setMargins(0, 30, 0, 10);
        title.setLayoutParams(titleParams);
        mainLayout.addView(title);
        
        // Subtitle
        TextView subtitle = new TextView(this);
        subtitle.setText(getText("ai_accelerator"));
        subtitle.setTextSize(16);
        subtitle.setTextColor(Color.WHITE);
        subtitle.setGravity(Gravity.CENTER);
        mainLayout.addView(subtitle);
        
        // Version info
        TextView versionInfo = new TextView(this);
        versionInfo.setText(isMasterVersion ? getText("version_master") : getText("version_standard"));
        versionInfo.setTextSize(14);
        versionInfo.setTextColor(Color.parseColor("#FFE4B5"));
        versionInfo.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams versionParams = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        versionParams.setMargins(0, 10, 0, 30);
        versionInfo.setLayoutParams(versionParams);
        mainLayout.addView(versionInfo);
        
        // Status text
        statusText = new TextView(this);
        statusText.setText(getText("loading"));
        statusText.setTextSize(16);
        statusText.setTextColor(Color.WHITE);
        statusText.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        statusParams.setMargins(0, 20, 0, 20);
        statusText.setLayoutParams(statusParams);
        mainLayout.addView(statusText);
        
        // Progress bar
        progressBar = new ProgressBar(this);
        progressBar.setIndeterminate(true);
        mainLayout.addView(progressBar);
        
        // Powered by
        TextView poweredBy = new TextView(this);
        poweredBy.setText(getText("powered_by"));
        poweredBy.setTextSize(12);
        poweredBy.setTextColor(Color.parseColor("#FFE4B5"));
        poweredBy.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams poweredParams = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        poweredParams.setMargins(0, 50, 0, 0);
        poweredBy.setLayoutParams(poweredParams);
        mainLayout.addView(poweredBy);
        
        splashLayout = mainLayout;
        setContentView(splashLayout);
        
        Log.i(TAG, "✅ Splash UI created successfully");
    }
    
    private void showLanguageSelection() {
        Log.i(TAG, "🌍 Showing language selection...");
        
        LinearLayout langLayout = new LinearLayout(this);
        langLayout.setOrientation(LinearLayout.VERTICAL);
        langLayout.setGravity(Gravity.CENTER);
        langLayout.setBackgroundColor(Color.parseColor("#FF6B35"));
        langLayout.setPadding(50, 50, 50, 50);
        
        TextView selectLang = new TextView(this);
        selectLang.setText("Select Language / Seleziona Lingua");
        selectLang.setTextSize(18);
        selectLang.setTextColor(Color.WHITE);
        selectLang.setTypeface(null, Typeface.BOLD);
        selectLang.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams selectParams = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        selectParams.setMargins(0, 0, 0, 30);
        selectLang.setLayoutParams(selectParams);
        langLayout.addView(selectLang);
        
        String[][] languages = {
            {"it", "🇮🇹 Italiano"},
            {"en", "🇬🇧 English"},
            {"es", "🇪🇸 Español"},
            {"fr", "🇫🇷 Français"},
            {"de", "🇩🇪 Deutsch"}
        };
        
        for (String[] lang : languages) {
            Button langButton = new Button(this);
            langButton.setText(lang[1]);
            langButton.setTextSize(16);
            langButton.setBackgroundColor(Color.parseColor("#E85A2B"));
            langButton.setTextColor(Color.WHITE);
            LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            buttonParams.setMargins(0, 10, 0, 10);
            langButton.setLayoutParams(buttonParams);
            
            langButton.setOnClickListener(v -> {
                selectedLanguage = lang[0];
                prefs.edit().putString("language", selectedLanguage).apply();
                Log.i(TAG, "Language selected: " + selectedLanguage);
                recreate();
            });
            
            langLayout.addView(langButton);
        }
        
        languageLayout = langLayout;
        setContentView(languageLayout);
    }
    
    private void checkAndRequestPermissions() {
        Log.i(TAG, "🔐 Checking permissions...");
        
        List<String> permissionsNeeded = new ArrayList<>();
        for (String permission : REQUIRED_PERMISSIONS) {
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                permissionsNeeded.add(permission);
                Log.w(TAG, "Permission needed: " + permission);
            }
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                permissionsNeeded.add(Manifest.permission.POST_NOTIFICATIONS);
            }
        }
        
        if (!permissionsNeeded.isEmpty()) {
            Log.w(TAG, "Requesting " + permissionsNeeded.size() + " permissions");
            showPermissionDialog(permissionsNeeded);
        } else {
            Log.i(TAG, "✅ All permissions granted");
            startApp();
        }
    }
    
    private void showPermissionDialog(List<String> permissions) {
        new AlertDialog.Builder(this)
            .setTitle(getText("permissions_required"))
            .setMessage("FreeApi " + (isMasterVersion ? getText("version_master") : getText("version_standard")) + 
                       "\n\n" + getText("powered_by"))
            .setPositiveButton(getText("grant_permissions"), (dialog, which) -> {
                ActivityCompat.requestPermissions(this, 
                    permissions.toArray(new String[0]), 
                    PERMISSIONS_REQUEST_CODE);
            })
            .setNegativeButton(getText("continue"), (dialog, which) -> startApp())
            .setCancelable(false)
            .show();
    }
    
    private void startApp() {
        Log.i(TAG, "🚀 Starting FreeApi Enterprise application...");
        
        statusText.setText(getText("server_starting"));
        
        Intent serviceIntent = new Intent(this, SmartCacheService.class);
        serviceIntent.putExtra("isMaster", isMasterVersion);
        serviceIntent.putExtra("language", selectedLanguage);
        
        Log.i(TAG, "Starting SmartCacheService with isMaster=" + isMasterVersion + ", language=" + selectedLanguage);
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }
        
        // Show diagnostics message
        statusText.setText(getText("diagnostics_running"));
        
        // Longer wait time to allow for comprehensive diagnostics
        new Handler().postDelayed(this::setupWebView, 8000);
    }
    
    private void setupWebView() {
        Log.i(TAG, "🌐 Setting up WebView with enterprise features...");
        
        webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setDomStorageEnabled(true);
        webView.getSettings().setAllowFileAccess(true);
        webView.getSettings().setLoadWithOverviewMode(true);
        webView.getSettings().setUseWideViewPort(true);
        
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                Log.i(TAG, "✅ Dashboard loaded successfully: " + url);
                splashLayout.setVisibility(View.GONE);
                webView.setVisibility(View.VISIBLE);
                retryCount = 0;
            }
            
            @Override
            public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
                super.onReceivedError(view, errorCode, description, failingUrl);
                Log.e(TAG, "❌ WebView error: " + description + " for URL: " + failingUrl + " (code: " + errorCode + ")");
                
                if (retryCount < MAX_RETRIES) {
                    retryCount++;
                    String connectingText = getText("connecting") + " (" + retryCount + "/" + MAX_RETRIES + ")";
                    statusText.setText(connectingText);
                    
                    // Enterprise dynamic port detection
                    int[] portsToTry = {3000, 3001, 3002, 3003, 3004, 3005, 8000, 8001, 8002, 8003};
                    int portIndex = (retryCount - 1) % portsToTry.length;
                    String retryUrl = "http://localhost:" + portsToTry[portIndex];
                    
                    Log.i(TAG, "🔄 Retry attempt " + retryCount + " with URL: " + retryUrl);
                    
                    new Handler().postDelayed(() -> {
                        if (retryCount <= MAX_RETRIES) {
                            view.loadUrl(retryUrl);
                        }
                    }, 3000);
                } else {
                    String errorMessage = "Errore connessione server. Controllare logs per dettagli.";
                    statusText.setText(errorMessage);
                    Log.e(TAG, "💀 All " + MAX_RETRIES + " connection attempts failed");
                    
                    // Show detailed error information for debugging
                    showConnectionErrorDialog(description, failingUrl);
                }
            }
        });
        
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                super.onProgressChanged(view, newProgress);
                if (newProgress > 0 && newProgress < 100) {
                    statusText.setText(getText("loading") + " " + newProgress + "%");
                }
            }
        });
        
        LinearLayout mainContainer = new LinearLayout(this);
        mainContainer.setOrientation(LinearLayout.VERTICAL);
        mainContainer.addView(splashLayout);
        
        webView.setVisibility(View.GONE);
        mainContainer.addView(webView, new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.MATCH_PARENT));
        
        setContentView(mainContainer);
        
        Log.i(TAG, "🌐 Starting dashboard connection with dynamic port detection...");
        statusText.setText(getText("connecting"));
        
        // Start with primary port
        webView.loadUrl("http://localhost:3000");
    }
    
    private void showConnectionErrorDialog(String errorDescription, String failedUrl) {
        new AlertDialog.Builder(this)
            .setTitle("🚨 Connection Debug Info")
            .setMessage("Error: " + errorDescription + "\n" +
                       "Failed URL: " + failedUrl + "\n" +
                       "Attempts: " + retryCount + "/" + MAX_RETRIES + "\n\n" +
                       "Check Android logs (tag: SmartCacheService) for detailed diagnostics.")
            .setPositiveButton("Retry", (dialog, which) -> {
                retryCount = 0;
                setupWebView();
            })
            .setNegativeButton("Exit", (dialog, which) -> finish())
            .show();
    }
    
    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSIONS_REQUEST_CODE) {
            int granted = 0;
            for (int result : grantResults) {
                if (result == PackageManager.PERMISSION_GRANTED) granted++;
            }
            Log.i(TAG, "Permissions result: " + granted + "/" + permissions.length + " granted");
            startApp();
        }
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        Log.d(TAG, "MainActivity resumed");
    }
    
    @Override
    protected void onPause() {
        super.onPause();
        Log.d(TAG, "MainActivity paused");
    }
    
    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}