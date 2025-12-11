package com.aegisai.android;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class ThreatScanner {
    private static final String TAG = "AegisAI-Scanner";
    private static final String PREFS_NAME = "AegisAIPrefs";
    private static final String API_ENDPOINT = "https://api.aegisai.com/scan";
    
    private Context context;
    private ScheduledExecutorService scheduler;
    private OkHttpClient httpClient;
    private Gson gson;
    
    public ThreatScanner(Context context) {
        this.context = context;
        this.httpClient = new OkHttpClient();
        this.gson = new Gson();
    }
    
    public void startPeriodicScan() {
        Log.d(TAG, "Starting periodic scanning");
        
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> {
            try {
                performScan();
            } catch (Exception e) {
                Log.e(TAG, "Error during periodic scan", e);
            }
        }, 0, 30, TimeUnit.MINUTES); // Scan every 30 minutes
    }
    
    public void stopPeriodicScan() {
        Log.d(TAG, "Stopping periodic scanning");
        
        if (scheduler != null) {
            scheduler.shutdown();
            scheduler = null;
        }
    }
    
    public void performScan() {
        Log.d(TAG, "Performing full system scan");
        
        // Scan common directories
        scanDirectory("/sdcard/Download/");
        scanDirectory("/sdcard/Documents/");
        scanDirectory("/sdcard/Pictures/");
        
        // Scan app-specific directories
        File appFilesDir = context.getFilesDir();
        if (appFilesDir != null) {
            scanDirectory(appFilesDir.getAbsolutePath());
        }
        
        Log.d(TAG, "Full system scan completed");
    }
    
    public void scanFileAsync(String filePath) {
        // Scan a single file asynchronously
        new Thread(() -> {
            try {
                ThreatResult result = scanFile(filePath);
                if (result.isThreat) {
                    handleThreatDetected(filePath, result);
                }
            } catch (Exception e) {
                Log.e(TAG, "Error scanning file: " + filePath, e);
            }
        }).start();
    }
    
    private ThreatResult scanFile(String filePath) {
        Log.d(TAG, "Scanning file: " + filePath);
        
        try {
            File file = new File(filePath);
            if (!file.exists()) {
                return new ThreatResult(false, "");
            }
            
            // Calculate file hash
            String fileHash = calculateFileHash(file);
            
            // Check local cache first
            if (isFileInCache(fileHash)) {
                boolean isThreat = isCachedFileThreat(fileHash);
                return new ThreatResult(isThreat, "Cached result");
            }
            
            // Send to cloud for analysis
            return sendToCloudForAnalysis(file, fileHash);
            
        } catch (Exception e) {
            Log.e(TAG, "Error scanning file: " + filePath, e);
            return new ThreatResult(false, "Scan error: " + e.getMessage());
        }
    }
    
    private void scanDirectory(String directoryPath) {
        Log.d(TAG, "Scanning directory: " + directoryPath);
        
        File directory = new File(directoryPath);
        if (!directory.exists() || !directory.isDirectory()) {
            return;
        }
        
        File[] files = directory.listFiles();
        if (files == null) {
            return;
        }
        
        for (File file : files) {
            if (file.isDirectory()) {
                // Recursively scan subdirectories
                scanDirectory(file.getAbsolutePath());
            } else {
                // Check if this is a file we should scan
                String extension = getFileExtension(file.getName());
                if (isScannableExtension(extension)) {
                    ThreatResult result = scanFile(file.getAbsolutePath());
                    if (result.isThreat) {
                        handleThreatDetected(file.getAbsolutePath(), result);
                    }
                }
            }
        }
    }
    
    private String calculateFileHash(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        FileInputStream fis = new FileInputStream(file);
        
        byte[] buffer = new byte[8192];
        int bytesRead;
        
        while ((bytesRead = fis.read(buffer)) != -1) {
            digest.update(buffer, 0, bytesRead);
        }
        
        fis.close();
        
        byte[] hashBytes = digest.digest();
        StringBuilder hexString = new StringBuilder();
        
        for (byte b : hashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        
        return hexString.toString();
    }
    
    private boolean isFileInCache(String fileHash) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        return prefs.contains("threat_" + fileHash);
    }
    
    private boolean isCachedFileThreat(String fileHash) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        return prefs.getBoolean("threat_" + fileHash, false);
    }
    
    private void cacheFileResult(String fileHash, boolean isThreat) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putBoolean("threat_" + fileHash, isThreat);
        editor.apply();
    }
    
    private ThreatResult sendToCloudForAnalysis(File file, String fileHash) {
        try {
            // Prepare JSON payload
            JsonObject payload = new JsonObject();
            payload.addProperty("file_hash", fileHash);
            payload.addProperty("file_name", file.getName());
            payload.addProperty("file_size", file.length());
            payload.addProperty("device_id", getDeviceId());
            
            // Send request to cloud API
            RequestBody body = RequestBody.create(
                gson.toJson(payload),
                MediaType.get("application/json; charset=utf-8")
            );
            
            Request request = new Request.Builder()
                .url(API_ENDPOINT)
                .post(body)
                .addHeader("Authorization", "Bearer " + getAuthToken())
                .build();
            
            Response response = httpClient.newCall(request).execute();
            
            if (response.isSuccessful()) {
                String responseBody = response.body().string();
                JsonObject result = gson.fromJson(responseBody, JsonObject.class);
                
                boolean isThreat = result.has("is_threat") && result.get("is_threat").getAsBoolean();
                String message = result.has("message") ? result.get("message").getAsString() : "";
                
                // Cache the result
                cacheFileResult(fileHash, isThreat);
                
                return new ThreatResult(isThreat, message);
            } else {
                Log.e(TAG, "Cloud API request failed with code: " + response.code());
                return new ThreatResult(false, "API error: " + response.code());
            }
        } catch (Exception e) {
            Log.e(TAG, "Error sending file to cloud for analysis", e);
            return new ThreatResult(false, "Network error: " + e.getMessage());
        }
    }
    
    private void handleThreatDetected(String filePath, ThreatResult result) {
        Log.w(TAG, "Threat detected in file: " + filePath + " - " + result.message);
        
        // Send broadcast about threat detection
        android.content.Intent threatIntent = new android.content.Intent(AegisAIService.ACTION_THREAT_DETECTED);
        threatIntent.putExtra("file_path", filePath);
        threatIntent.putExtra("threat_message", result.message);
        context.sendBroadcast(threatIntent);
        
        // Log the threat
        logThreat(filePath, result.message);
    }
    
    private void logThreat(String filePath, String message) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putLong("last_threat_time", System.currentTimeMillis());
        editor.putString("last_threat_file", filePath);
        editor.putString("last_threat_message", message);
        editor.apply();
    }
    
    private String getDeviceId() {
        // In a real implementation, this would return a unique device identifier
        return "device_" + android.os.Build.SERIAL;
    }
    
    private String getAuthToken() {
        // In a real implementation, this would return a valid auth token
        return "sample_auth_token";
    }
    
    private String getFileExtension(String fileName) {
        if (fileName == null || fileName.lastIndexOf('.') == -1) {
            return "";
        }
        return fileName.substring(fileName.lastIndexOf('.') + 1).toLowerCase();
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
    
    // Inner class to represent scan results
    private static class ThreatResult {
        boolean isThreat;
        String message;
        
        ThreatResult(boolean isThreat, String message) {
            this.isThreat = isThreat;
            this.message = message;
        }
    }
}