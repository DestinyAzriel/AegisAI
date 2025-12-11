package com.aegisai.android;

import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AegisAIService extends Service {
    private static final String TAG = "AegisAI-Service";
    public static final String ACTION_SCAN = "com.aegisai.android.ACTION_SCAN";
    public static final String ACTION_THREAT_DETECTED = "com.aegisai.android.ACTION_THREAT_DETECTED";
    
    private ExecutorService executorService;
    private FileMonitor fileMonitor;
    private ThreatScanner threatScanner;
    private NetworkMonitor networkMonitor;
    
    private BroadcastReceiver commandReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (ACTION_SCAN.equals(action)) {
                performScan();
            }
        }
    };
    
    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "AegisAI Service created");
        
        // Initialize components
        executorService = Executors.newFixedThreadPool(3);
        fileMonitor = new FileMonitor(this);
        threatScanner = new ThreatScanner(this);
        networkMonitor = new NetworkMonitor(this);
        
        // Register broadcast receiver for commands
        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_SCAN);
        registerReceiver(commandReceiver, filter);
        
        // Start monitoring
        startMonitoring();
    }
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "AegisAI Service started");
        return START_STICKY; // Restart service if killed
    }
    
    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "AegisAI Service destroyed");
        
        // Clean up
        stopMonitoring();
        if (executorService != null) {
            executorService.shutdown();
        }
        unregisterReceiver(commandReceiver);
    }
    
    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null; // Not a bound service
    }
    
    private void startMonitoring() {
        Log.d(TAG, "Starting monitoring components");
        
        // Start file monitoring
        executorService.submit(() -> {
            try {
                fileMonitor.startMonitoring();
            } catch (Exception e) {
                Log.e(TAG, "Error in file monitoring", e);
            }
        });
        
        // Start network monitoring
        executorService.submit(() -> {
            try {
                networkMonitor.startMonitoring();
            } catch (Exception e) {
                Log.e(TAG, "Error in network monitoring", e);
            }
        });
        
        // Start periodic scanning
        executorService.submit(() -> {
            try {
                threatScanner.startPeriodicScan();
            } catch (Exception e) {
                Log.e(TAG, "Error in periodic scanning", e);
            }
        });
    }
    
    private void stopMonitoring() {
        Log.d(TAG, "Stopping monitoring components");
        fileMonitor.stopMonitoring();
        networkMonitor.stopMonitoring();
        threatScanner.stopPeriodicScan();
    }
    
    private void performScan() {
        Log.d(TAG, "Performing manual scan");
        executorService.submit(() -> {
            try {
                threatScanner.performScan();
            } catch (Exception e) {
                Log.e(TAG, "Error during manual scan", e);
            }
        });
    }
}