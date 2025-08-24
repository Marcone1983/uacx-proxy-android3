package com.freeapi.accelerator;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.res.AssetManager;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import java.io.*;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SmartCacheService extends Service {
    private static final String TAG = "SmartCacheService";
    private static final String CHANNEL_ID = "SmartCacheChannel";
    private static final int NOTIFICATION_ID = 1;
    private ExecutorService executor;
    private Process nodeProcess;
    
    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        executor = Executors.newSingleThreadExecutor();
    }
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        boolean isMaster = intent != null && intent.getBooleanExtra("isMaster", false);
        String language = intent != null ? intent.getStringExtra("language") : "en";
        
        String notificationTitle = isMaster ? "FreeApi Master Active" : "FreeApi Standard Active";
        String notificationText = isMaster ? "Master Database Access Running" : "Local Cache + Federated Sync Running";
        
        startForeground(NOTIFICATION_ID, createNotification(notificationTitle, notificationText));
        
        executor.execute(() -> {
            try {
                // Extract Node.js project from assets with comprehensive verification
                extractNodeProject();
                
                // Configure environment for Standard vs Master
                configureEnvironment(isMaster, language);
                
                // Start Node.js FreeApi with enhanced monitoring
                startNodeProcess();
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to start FreeApi", e);
            }
        });
        
        return START_STICKY;
    }
    
    private void extractNodeProject() throws IOException {
        File projectDir = new File(getFilesDir(), "nodejs-project");
        
        Log.i(TAG, "🔍 ENTERPRISE DEBUG: Starting Node.js project extraction");
        Log.i(TAG, "Target directory: " + projectDir.getAbsolutePath());
        Log.i(TAG, "App files dir: " + getFilesDir().getAbsolutePath());
        Log.i(TAG, "Available space: " + getFilesDir().getFreeSpace() / (1024*1024) + " MB");
        
        if (projectDir.exists()) {
            Log.i(TAG, "Node.js project directory exists, verifying integrity...");
            
            // Verify critical files exist
            File nodeExecutable = new File(projectDir, "bin/node");
            File mainScript = new File(projectDir, "src/smartcache.js");
            File nodeModules = new File(projectDir, "node_modules");
            
            Log.i(TAG, "Node binary exists: " + nodeExecutable.exists() + " (" + nodeExecutable.length() / (1024*1024) + " MB)");
            Log.i(TAG, "Main script exists: " + mainScript.exists());
            Log.i(TAG, "node_modules exists: " + nodeModules.exists() + " (" + countFiles(nodeModules) + " files)");
            
            if (!nodeExecutable.exists() || !mainScript.exists() || !nodeModules.exists()) {
                Log.w(TAG, "Incomplete extraction detected, re-extracting...");
                deleteRecursively(projectDir);
            } else {
                Log.i(TAG, "✅ Extraction verification passed");
                return;
            }
        }
        
        Log.i(TAG, "🔄 Starting fresh extraction from assets...");
        
        long startTime = System.currentTimeMillis();
        copyAssets("nodejs-project", projectDir);
        long extractTime = System.currentTimeMillis() - startTime;
        
        Log.i(TAG, "📊 Extraction completed in " + extractTime + "ms");
        
        // Detailed verification of extracted content
        verifyExtractedContent(projectDir);
        
        // Set executable permissions with detailed logging
        setExecutablePermissions(projectDir);
        
        // Test Node.js binary functionality
        testNodeBinary(projectDir);
    }
    
    private void verifyExtractedContent(File projectDir) {
        Log.i(TAG, "🔍 DETAILED CONTENT VERIFICATION:");
        
        File binDir = new File(projectDir, "bin");
        File srcDir = new File(projectDir, "src");
        File nodeModules = new File(projectDir, "node_modules");
        File packageJson = new File(projectDir, "package.json");
        
        Log.i(TAG, "📁 bin/ directory: " + binDir.exists() + " (" + countFiles(binDir) + " files)");
        if (binDir.exists() && binDir.listFiles() != null) {
            for (File f : binDir.listFiles()) {
                Log.i(TAG, "  📄 " + f.getName() + " - " + f.length() / 1024 + "KB - executable: " + f.canExecute());
            }
        }
        
        Log.i(TAG, "📁 src/ directory: " + srcDir.exists() + " (" + countFiles(srcDir) + " files)");
        if (srcDir.exists() && srcDir.listFiles() != null) {
            for (File f : srcDir.listFiles()) {
                if (f.isFile() && f.getName().endsWith(".js")) {
                    Log.i(TAG, "  📄 " + f.getName() + " - " + f.length() / 1024 + "KB");
                }
            }
        }
        
        Log.i(TAG, "📁 node_modules/: " + nodeModules.exists() + " (" + countFiles(nodeModules) + " total files)");
        if (nodeModules.exists()) {
            String[] criticalModules = {"express", "sqlite3", "@supabase/supabase-js", "ws"};
            for (String module : criticalModules) {
                File moduleDir = new File(nodeModules, module);
                Log.i(TAG, "  📦 " + module + ": " + moduleDir.exists());
                if (moduleDir.exists()) {
                    File packageJsonModule = new File(moduleDir, "package.json");
                    Log.i(TAG, "    📄 package.json: " + packageJsonModule.exists());
                }
            }
        }
        
        Log.i(TAG, "📄 package.json: " + packageJson.exists());
        
        // Calculate total extracted size
        long totalSize = calculateDirectorySize(projectDir);
        Log.i(TAG, "💾 Total extracted size: " + totalSize / (1024*1024) + " MB");
        
        if (totalSize < 50 * 1024 * 1024) { // Less than 50MB indicates problem
            Log.e(TAG, "⚠️ Extracted size too small! Expected ~100MB, got " + totalSize / (1024*1024) + "MB");
        }
    }
    
    private void setExecutablePermissions(File projectDir) {
        Log.i(TAG, "🔐 Setting executable permissions...");
        
        File nodeExecutable = new File(projectDir, "bin/node");
        if (nodeExecutable.exists()) {
            boolean success = nodeExecutable.setExecutable(true, false);
            Log.i(TAG, "Node binary permissions: " + success + " (can execute: " + nodeExecutable.canExecute() + ")");
            
            // Try chmod as fallback
            if (!nodeExecutable.canExecute()) {
                try {
                    Runtime.getRuntime().exec("chmod +x " + nodeExecutable.getAbsolutePath()).waitFor();
                    Log.i(TAG, "chmod fallback result: " + nodeExecutable.canExecute());
                } catch (Exception e) {
                    Log.e(TAG, "chmod fallback failed", e);
                }
            }
        } else {
            Log.e(TAG, "❌ Node.js executable not found for permission setting!");
        }
        
        File startScript = new File(projectDir, "start.sh");
        if (startScript.exists()) {
            boolean success = startScript.setExecutable(true, false);
            Log.i(TAG, "Start script permissions: " + success);
        }
    }
    
    private void testNodeBinary(File projectDir) {
        Log.i(TAG, "🧪 Testing Node.js binary functionality...");
        
        File nodeExecutable = new File(projectDir, "bin/node");
        if (!nodeExecutable.exists() || !nodeExecutable.canExecute()) {
            Log.e(TAG, "❌ Cannot test Node.js - binary not executable");
            return;
        }
        
        try {
            // Test Node.js version
            ProcessBuilder pb = new ProcessBuilder(nodeExecutable.getAbsolutePath(), "--version");
            pb.directory(projectDir);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String version = reader.readLine();
            int exitCode = process.waitFor();
            
            Log.i(TAG, "Node.js version test: " + version + " (exit code: " + exitCode + ")");
            
            if (exitCode == 0) {
                Log.i(TAG, "✅ Node.js binary is functional!");
                
                // Test basic JavaScript execution
                pb = new ProcessBuilder(nodeExecutable.getAbsolutePath(), "-e", "console.log('Node.js test successful')");
                pb.directory(projectDir);
                process = pb.start();
                
                reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String testResult = reader.readLine();
                exitCode = process.waitFor();
                
                Log.i(TAG, "Node.js execution test: '" + testResult + "' (exit code: " + exitCode + ")");
                
            } else {
                Log.e(TAG, "❌ Node.js binary test failed with exit code: " + exitCode);
            }
            
        } catch (Exception e) {
            Log.e(TAG, "❌ Node.js binary test exception", e);
        }
    }
    
    private void startNodeProcess() throws IOException {
        File projectDir = new File(getFilesDir(), "nodejs-project");
        File nodeExecutable = new File(projectDir, "bin/node");
        File smartcacheScript = new File(projectDir, "src/smartcache.js");
        
        Log.i(TAG, "🚀 ENTERPRISE DEBUG: Node.js Process Startup Analysis");
        Log.i(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        
        Log.i(TAG, "📁 Project directory: " + projectDir.getAbsolutePath());
        Log.i(TAG, "📁 Directory exists: " + projectDir.exists());
        Log.i(TAG, "📁 Directory readable: " + projectDir.canRead());
        Log.i(TAG, "📁 Directory writable: " + projectDir.canWrite());
        
        Log.i(TAG, "🔧 Node executable: " + nodeExecutable.getAbsolutePath());
        Log.i(TAG, "🔧 Binary exists: " + nodeExecutable.exists());
        Log.i(TAG, "🔧 Binary size: " + (nodeExecutable.exists() ? nodeExecutable.length() / (1024*1024) + " MB" : "N/A"));
        Log.i(TAG, "🔧 Binary executable: " + nodeExecutable.canExecute());
        Log.i(TAG, "🔧 Binary readable: " + nodeExecutable.canRead());
        
        Log.i(TAG, "📄 SmartCache script: " + smartcacheScript.getAbsolutePath());
        Log.i(TAG, "📄 Script exists: " + smartcacheScript.exists());
        Log.i(TAG, "📄 Script size: " + (smartcacheScript.exists() ? smartcacheScript.length() / 1024 + " KB" : "N/A"));
        Log.i(TAG, "📄 Script readable: " + smartcacheScript.canRead());
        
        // Verify critical dependencies before starting
        verifyCriticalDependencies(projectDir);
        
        if (!nodeExecutable.exists()) {
            Log.e(TAG, "❌ CRITICAL: Node.js executable not found");
            logDirectoryContents(new File(projectDir, "bin"), "bin");
            throw new IOException("Node.js executable missing");
        }
        
        if (!nodeExecutable.canExecute()) {
            Log.e(TAG, "❌ CRITICAL: Node.js executable not executable");
            throw new IOException("Node.js executable permissions issue");
        }
        
        if (!smartcacheScript.exists()) {
            Log.e(TAG, "❌ CRITICAL: SmartCache script not found");
            logDirectoryContents(new File(projectDir, "src"), "src");
            throw new IOException("SmartCache script missing");
        }
        
        // Test Node.js binary before full startup
        if (!testNodeExecutableFunctionality(nodeExecutable, projectDir)) {
            throw new IOException("Node.js binary is not functional");
        }
        
        Log.i(TAG, "🎬 Starting Node.js process with enhanced monitoring...");
        
        ProcessBuilder pb = new ProcessBuilder(
            nodeExecutable.getAbsolutePath(),
            smartcacheScript.getAbsolutePath()
        );
        pb.directory(projectDir);
        
        // Enhanced environment setup
        Map<String, String> env = pb.environment();
        env.put("NODE_PATH", new File(projectDir, "node_modules").getAbsolutePath());
        env.put("HOME", projectDir.getAbsolutePath());
        env.put("DEBUG", "*");
        env.put("NODE_ENV", "production");
        env.put("FORCE_COLOR", "0"); // Disable colors in Android logs
        
        // Android-specific environment
        env.put("ANDROID_ROOT", "/system");
        env.put("ANDROID_DATA", "/data");
        
        Log.i(TAG, "🌍 Environment Variables:");
        for (Map.Entry<String, String> entry : env.entrySet()) {
            if (entry.getKey().startsWith("NODE_") || entry.getKey().startsWith("DEBUG") || entry.getKey().startsWith("HOME")) {
                Log.i(TAG, "  " + entry.getKey() + "=" + entry.getValue());
            }
        }
        
        // Start process with enhanced error handling
        try {
            nodeProcess = pb.start();
            Log.i(TAG, "✅ Process created successfully");
            
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                Log.i(TAG, "🆔 Process PID: " + nodeProcess.pid());
                Log.i(TAG, "🔄 Process alive: " + nodeProcess.isAlive());
            }
            
        } catch (IOException e) {
            Log.e(TAG, "❌ CRITICAL: Failed to start Node.js process", e);
            throw e;
        }
        
        // Enhanced output monitoring with startup detection
        startEnhancedOutputMonitoring();
        
        // Monitor process health
        startProcessHealthMonitoring();
        
        Log.i(TAG, "🏁 Node.js process startup sequence initiated");
    }
    
    private void verifyCriticalDependencies(File projectDir) {
        Log.i(TAG, "🔍 Verifying critical dependencies...");
        
        File nodeModules = new File(projectDir, "node_modules");
        String[] criticalDeps = {"express", "sqlite3", "@supabase/supabase-js", "ws", "axios"};
        
        for (String dep : criticalDeps) {
            File depDir = new File(nodeModules, dep);
            boolean exists = depDir.exists();
            Log.i(TAG, "📦 " + dep + ": " + (exists ? "✅" : "❌"));
            
            if (exists && dep.equals("sqlite3")) {
                // Special check for sqlite3 native binding
                File binding = new File(depDir, "lib/binding");
                Log.i(TAG, "  🔗 SQLite3 binding: " + (binding.exists() ? "✅" : "❌"));
            }
        }
        
        // Check package.json
        File packageJson = new File(projectDir, "package.json");
        Log.i(TAG, "📄 package.json: " + (packageJson.exists() ? "✅" : "❌"));
        
        // Check config files
        File configJs = new File(projectDir, "src/config.js");
        Log.i(TAG, "⚙️ config.js: " + (configJs.exists() ? "✅" : "❌"));
    }
    
    private boolean testNodeExecutableFunctionality(File nodeExecutable, File projectDir) {
        Log.i(TAG, "🧪 Testing Node.js executable functionality...");
        
        try {
            // Test 1: Version check
            ProcessBuilder pb = new ProcessBuilder(nodeExecutable.getAbsolutePath(), "--version");
            pb.directory(projectDir);
            Process process = pb.start();
            
            String version = new BufferedReader(new InputStreamReader(process.getInputStream())).readLine();
            int exitCode = process.waitFor();
            
            if (exitCode != 0) {
                Log.e(TAG, "❌ Node.js version test failed with exit code: " + exitCode);
                return false;
            }
            
            Log.i(TAG, "✅ Node.js version: " + version);
            
            // Test 2: Basic execution
            pb = new ProcessBuilder(nodeExecutable.getAbsolutePath(), "-e", "console.log('TEST_OK')");
            pb.directory(projectDir);
            process = pb.start();
            
            String output = new BufferedReader(new InputStreamReader(process.getInputStream())).readLine();
            exitCode = process.waitFor();
            
            if (exitCode != 0 || !"TEST_OK".equals(output)) {
                Log.e(TAG, "❌ Node.js execution test failed. Output: " + output + ", Exit: " + exitCode);
                return false;
            }
            
            Log.i(TAG, "✅ Node.js execution test passed");
            
            // Test 3: Module loading test
            pb = new ProcessBuilder(nodeExecutable.getAbsolutePath(), "-e", "console.log(require('fs').existsSync('.'))");
            pb.directory(projectDir);
            pb.environment().put("NODE_PATH", new File(projectDir, "node_modules").getAbsolutePath());
            process = pb.start();
            
            output = new BufferedReader(new InputStreamReader(process.getInputStream())).readLine();
            exitCode = process.waitFor();
            
            if (exitCode != 0 || !"true".equals(output)) {
                Log.w(TAG, "⚠️ Node.js module loading test inconclusive. Output: " + output);
            } else {
                Log.i(TAG, "✅ Node.js module loading test passed");
            }
            
            return true;
            
        } catch (Exception e) {
            Log.e(TAG, "❌ Node.js functionality test failed", e);
            return false;
        }
    }
    
    private void startEnhancedOutputMonitoring() {
        // STDOUT monitoring with startup detection
        new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(nodeProcess.getInputStream()))) {
                String line;
                boolean serverStarted = false;
                long startTime = System.currentTimeMillis();
                
                while ((line = reader.readLine()) != null) {
                    Log.i(TAG, "📤 Node.js: " + line);
                    
                    // Detect server startup
                    if (!serverStarted && (line.contains("Dashboard running") || line.contains("localhost:") || line.contains("server") || line.contains("listening"))) {
                        serverStarted = true;
                        long startupTime = System.currentTimeMillis() - startTime;
                        Log.i(TAG, "🎉 SERVER STARTUP DETECTED! (" + startupTime + "ms)");
                        Log.i(TAG, "🌐 Server ready for connections");
                    }
                    
                    // Detect errors
                    if (line.toLowerCase().contains("error") || line.toLowerCase().contains("exception")) {
                        Log.e(TAG, "🚨 ERROR DETECTED: " + line);
                    }
                    
                    // Detect port information
                    if (line.contains("port") && (line.contains("3000") || line.contains("8080"))) {
                        Log.i(TAG, "🔌 PORT INFO: " + line);
                    }
                }
                
                Log.w(TAG, "📤 Node.js STDOUT stream ended");
                
            } catch (IOException e) {
                Log.e(TAG, "❌ Error monitoring Node.js stdout", e);
            }
        }).start();
        
        // STDERR monitoring
        new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(nodeProcess.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    Log.e(TAG, "📥 Node.js ERROR: " + line);
                    
                    // Detect specific error patterns
                    if (line.contains("EADDRINUSE")) {
                        Log.e(TAG, "🚨 PORT CONFLICT DETECTED: " + line);
                    } else if (line.contains("Cannot find module")) {
                        Log.e(TAG, "🚨 MISSING MODULE: " + line);
                    } else if (line.contains("Permission denied")) {
                        Log.e(TAG, "🚨 PERMISSION ERROR: " + line);
                    }
                }
                
                Log.w(TAG, "📥 Node.js STDERR stream ended");
                
            } catch (IOException e) {
                Log.e(TAG, "❌ Error monitoring Node.js stderr", e);
            }
        }).start();
    }
    
    private void startProcessHealthMonitoring() {
        new Thread(() -> {
            try {
                Thread.sleep(5000); // Wait 5 seconds
                
                if (nodeProcess != null) {
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                        boolean alive = nodeProcess.isAlive();
                        Log.i(TAG, "💓 Process health check (5s): " + (alive ? "ALIVE" : "DEAD"));
                        
                        if (!alive) {
                            try {
                                int exitCode = nodeProcess.exitValue();
                                Log.e(TAG, "💀 Process died with exit code: " + exitCode);
                            } catch (IllegalThreadStateException e) {
                                Log.w(TAG, "Process state unclear");
                            }
                        }
                    }
                    
                    // Test server responsiveness
                    testServerResponsiveness();
                }
                
            } catch (InterruptedException e) {
                Log.w(TAG, "Health monitoring interrupted");
            }
        }).start();
    }
    
    private void testServerResponsiveness() {
        Log.i(TAG, "🏥 Testing server responsiveness...");
        
        int[] portsToTest = {3000, 3001, 3002, 8000, 8001, 8002};
        
        for (int port : portsToTest) {
            try (java.net.Socket socket = new java.net.Socket()) {
                socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 2000);
                Log.i(TAG, "✅ Server responding on port " + port);
                return;
            } catch (Exception e) {
                Log.d(TAG, "🔍 Port " + port + " not responding: " + e.getMessage());
            }
        }
        
        Log.w(TAG, "⚠️ No server response detected on tested ports");
    }
    
    private void configureEnvironment(boolean isMaster, String language) throws IOException {
        File projectDir = new File(getFilesDir(), "nodejs-project");
        File envFile = new File(projectDir, ".env");
        
        // Create configuration based on version type
        StringBuilder envConfig = new StringBuilder();
        envConfig.append("# FreeApi Configuration - Powered by 420White,LLC\n");
        envConfig.append("LANGUAGE=").append(language).append("\n");
        envConfig.append("DB_PATH=./freeapi.db\n");
        envConfig.append("DASHBOARD_PORT=3000\n");
        envConfig.append("WS_PORT=8080\n");
        envConfig.append("NODE_ENV=production\n");
        envConfig.append("ANDROID_BUILD=true\n");
        
        if (isMaster) {
            // Master version: direct access to worldwide database
            envConfig.append("# MASTER VERSION - Worldwide Database Access\n");
            envConfig.append("VERSION_TYPE=master\n");
            envConfig.append("CACHE_MODE=worldwide\n");
            envConfig.append("SUPABASE_URL=https://grjhpkndqrkewluxazvl.supabase.co\n");
            envConfig.append("SUPABASE_ANON_KEY=sb_publishable_UGe_OhPKQDuvP-G3c9ZzgQ_XGF48dkZ\n");
            envConfig.append("SUPABASE_FUNCTION_URL=https://grjhpkndqrkewluxazvl.supabase.co/functions/v1/uacx-cache\n");
            envConfig.append("ENABLE_DIRECT_DB_ACCESS=true\n");
            envConfig.append("ADMIN_MODE=true\n");
            envConfig.append("CACHE_ALL_QUERIES=true\n");
        } else {
            // Standard version: local cache + federated sync
            envConfig.append("# STANDARD VERSION - Local Cache + Federated Sync\n");
            envConfig.append("VERSION_TYPE=standard\n");
            envConfig.append("CACHE_MODE=federated\n");
            envConfig.append("SUPABASE_URL=https://grjhpkndqrkewluxazvl.supabase.co\n");
            envConfig.append("SUPABASE_ANON_KEY=sb_publishable_UGe_OhPKQDuvP-G3c9ZzgQ_XGF48dkZ\n");
            envConfig.append("SUPABASE_FUNCTION_URL=https://grjhpkndqrkewluxazvl.supabase.co/functions/v1/uacx-cache\n");
            envConfig.append("ENABLE_LOCAL_CACHE=true\n");
            envConfig.append("SYNC_TO_FEDERATED=true\n");
            envConfig.append("ADMIN_MODE=false\n");
        }
        
        // Write configuration to file
        try (FileWriter writer = new FileWriter(envFile)) {
            writer.write(envConfig.toString());
        }
        
        Log.i(TAG, "Configuration created for " + (isMaster ? "MASTER" : "STANDARD") + " version");
    }
    
    private void copyAssets(String assetPath, File targetDir) throws IOException {
        AssetManager assetManager = getAssets();
        String[] files = assetManager.list(assetPath);
        
        if (!targetDir.exists()) {
            targetDir.mkdirs();
        }
        
        if (files != null && files.length > 0) {
            // It's a directory
            for (String file : files) {
                copyAssets(assetPath + "/" + file, new File(targetDir, file));
            }
        } else {
            // It's a file
            try (InputStream in = assetManager.open(assetPath);
                 FileOutputStream out = new FileOutputStream(targetDir)) {
                byte[] buffer = new byte[1024];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
            }
        }
    }
    
    private int countFiles(File dir) {
        if (!dir.exists() || !dir.isDirectory()) return 0;
        int count = 0;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) {
                if (f.isFile()) count++;
                else if (f.isDirectory()) count += countFiles(f);
            }
        }
        return count;
    }
    
    private long calculateDirectorySize(File dir) {
        if (!dir.exists()) return 0;
        long size = 0;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) {
                if (f.isFile()) size += f.length();
                else if (f.isDirectory()) size += calculateDirectorySize(f);
            }
        }
        return size;
    }
    
    private void deleteRecursively(File file) {
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File child : files) {
                    deleteRecursively(child);
                }
            }
        }
        file.delete();
    }
    
    private void logDirectoryContents(File dir, String dirName) {
        Log.i(TAG, "📁 Contents of " + dirName + "/ directory:");
        if (dir.exists() && dir.isDirectory()) {
            File[] files = dir.listFiles();
            if (files != null && files.length > 0) {
                for (File f : files) {
                    Log.i(TAG, "  📄 " + f.getName() + 
                        " (size: " + f.length() / 1024 + "KB, " +
                        "executable: " + f.canExecute() + ", " +
                        "readable: " + f.canRead() + ")");
                }
            } else {
                Log.w(TAG, "  📂 Directory is empty");
            }
        } else {
            Log.e(TAG, "  ❌ Directory does not exist or is not a directory");
        }
    }
    
    private Notification createNotification(String title, String text) {
        return new Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text + " - Powered by 420White,LLC")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .build();
    }
    
    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "SmartCache Service",
                NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }
    
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
    
    @Override
    public void onDestroy() {
        super.onDestroy();
        if (nodeProcess != null) {
            nodeProcess.destroy();
        }
        if (executor != null) {
            executor.shutdown();
        }
    }
}