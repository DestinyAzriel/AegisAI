package com.aegisai.android;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "AegisAI-Boot";
    
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        Log.d(TAG, "Boot receiver triggered with action: " + action);
        
        if (Intent.ACTION_BOOT_COMPLETED.equals(action) || 
            Intent.ACTION_QUICKBOOT_POWERON.equals(action)) {
            
            Log.d(TAG, "Device boot completed, starting AegisAI service");
            
            // Start the AegisAI service
            Intent serviceIntent = new Intent(context, AegisAIService.class);
            context.startForegroundService(serviceIntent);
        }
    }
}