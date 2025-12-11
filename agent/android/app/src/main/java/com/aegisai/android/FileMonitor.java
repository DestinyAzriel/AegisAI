package com.aegisai.android;

import android.content.Context;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

public class FileMonitor {
    private static final String TAG = "AegisAI-FileMonitor";
    
    private Context context;
    private Set<String> monitoredPaths;
    private ContentObserver fileObserver;
    private boolean isMonitoring = false;
    
    public FileMonitor(Context context) {
        this.context = context;
        this.monitoredPaths = new HashSet<>();
        initMonitoredPaths();
    }
    
    private void initMonitoredPaths() {
        // Add commonly targeted directories
        monitoredPaths.add("/sdcard/Download/");
        monitoredPaths.add("/sdcard/Documents/");
        monitoredPaths.add("/sdcard/Music/");
        monitoredPaths.add("/sdcard/Pictures/");
        monitoredPaths.add("/sdcard/Movies/");
        monitoredPaths.add("/data/data/" + context.getPackageName() + "/files/");
    }
    
    public void startMonitoring() {
        if (isMonitoring) {
            Log.w(TAG, "File monitoring already started");
            return;
        }
        
        isMonitoring = true;
        Log.d(TAG, "Starting file monitoring");
        
        // Register content observer for file changes
        fileObserver = new ContentObserver(new Handler(Looper.getMainLooper())) {
            @Override
            public void onChange(boolean selfChange, Uri uri) {
                super.onChange(selfChange, uri);
                if (uri != null) {
                    handleFileChange(uri);
                }
            }
        };
        
        // Monitor external storage changes
        context.getContentResolver().registerContentObserver(
                android.provider.MediaStore.Files.getContentUri("external"),
                true,
                fileObserver);
                
        Log.d(TAG, "File monitoring started");
    }
    
    public void stopMonitoring() {
        if (!isMonitoring) {
            Log.w(TAG, "File monitoring not started");
            return;
        }
        
        isMonitoring = false;
        Log.d(TAG, "Stopping file monitoring");
        
        if (fileObserver != null) {
            context.getContentResolver().unregisterContentObserver(fileObserver);
            fileObserver = null;
        }
        
        Log.d(TAG, "File monitoring stopped");
    }
    
    private void handleFileChange(Uri uri) {
        Log.d(TAG, "File change detected: " + uri.toString());
        
        try {
            String path = uri.getPath();
            if (path != null && shouldScanFile(path)) {
                // Check if this is a file we should scan
                ThreatScanner scanner = new ThreatScanner(context);
                scanner.scanFileAsync(path);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error handling file change", e);
        }
    }
    
    private boolean shouldScanFile(String filePath) {
        // Check if file is in monitored paths
        for (String monitoredPath : monitoredPaths) {
            if (filePath.startsWith(monitoredPath)) {
                // Check file extension
                String extension = getFileExtension(filePath);
                return isScannableExtension(extension);
            }
        }
        return false;
    }
    
    private String getFileExtension(String filePath) {
        if (filePath == null || filePath.lastIndexOf('.') == -1) {
            return "";
        }
        return filePath.substring(filePath.lastIndexOf('.') + 1).toLowerCase();
    }
    
    private boolean isScannableExtension(String extension) {
        // Common executable and archive extensions that should be scanned
        switch (extension) {
            case "apk":
            case "jar":
            case "zip":
            case "rar":
            case "exe":
            case "bat":
            case "scr":
            case "com":
            case "js":
            case "sh":
                return true;
            default:
                return false;
        }
    }
}