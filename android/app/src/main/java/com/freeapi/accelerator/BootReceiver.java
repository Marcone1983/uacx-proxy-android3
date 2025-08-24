package com.freeapi.accelerator;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "BootReceiver";
    
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction()) || 
            "android.intent.action.QUICKBOOT_POWERON".equals(intent.getAction())) {
            
            Log.i(TAG, "🔄 Boot completed - Starting FreeApi Enterprise service");
            
            // Check if user has completed initial setup
            SharedPreferences prefs = context.getSharedPreferences("FreeApiPrefs", Context.MODE_PRIVATE);
            boolean hasCompletedSetup = prefs.contains("language");
            
            if (hasCompletedSetup) {
                Intent serviceIntent = new Intent(context, SmartCacheService.class);
                serviceIntent.putExtra("autostart", true);
                
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent);
                } else {
                    context.startService(serviceIntent);
                }
                
                Log.i(TAG, "✅ FreeApi Enterprise service auto-started on boot");
            } else {
                Log.i(TAG, "⏸️ Skipping auto-start - initial setup not completed");
            }
        }
    }
}