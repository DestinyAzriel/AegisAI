package com.aegisai.android;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class NetworkMonitor {
    private static final String TAG = "AegisAI-Network";
    private static final String PREFS_NAME = "AegisAIPrefs";
    private static final String THREAT_INTEL_ENDPOINT = "https://api.aegisai.com/threat-intel";
    
    private Context context;
    private ScheduledExecutorService scheduler;
    private OkHttpClient httpClient;
    private Gson gson;
    private Set<String> blockedDomains;
    
    // Suspicious C2 patterns
    private static final String[] SUSPICIOUS_PATTERNS = {
        ".*\\.(tk|ml|ga|cf)$",  // Free domains often used by malware
        ".*[0-9]{5,}.*",        // Domains with long number sequences
        ".*[a-z]{20,}.*",       // Domains with very long random strings
        ".*rapid.*",            // Domains with "rapid" (often used by malware)
        ".*free.*",             // Domains with "free" (often used by malware)
    };
    
    // Known C2 ports
    private static final int[] C2_PORTS = {
        4444, 5555, 8080, 10000, 1337, 31337
    };
    
    public NetworkMonitor(Context context) {
        this.context = context;
        this.httpClient = new OkHttpClient();
        this.gson = new Gson();
        this.blockedDomains = new HashSet<>();
        loadBlockedDomains();
    }
    
    public void startMonitoring() {
        Log.d(TAG, "Starting network monitoring");
        
        scheduler = Executors.newScheduledThreadPool(2);
        
        // Schedule threat intelligence updates every 10 minutes
        scheduler.scheduleAtFixedRate(() -> {
            try {
                updateThreatIntelligence();
            } catch (Exception e) {
                Log.e(TAG, "Error updating threat intelligence", e);
            }
        }, 0, 10, TimeUnit.MINUTES);
        
        // Schedule network connection checks every 30 seconds
        scheduler.scheduleAtFixedRate(() -> {
            try {
                checkNetworkConnections();
            } catch (Exception e) {
                Log.e(TAG, "Error checking network connections", e);
            }
        }, 0, 30, TimeUnit.SECONDS);
        
        // Schedule DNS query monitoring every 5 seconds
        scheduler.scheduleAtFixedRate(() -> {
            try {
                monitorDNSQueries();
            } catch (Exception e) {
                Log.e(TAG, "Error monitoring DNS queries", e);
            }
        }, 0, 5, TimeUnit.SECONDS);
    }
    
    public void stopMonitoring() {
        Log.d(TAG, "Stopping network monitoring");
        
        if (scheduler != null) {
            scheduler.shutdown();
            scheduler = null;
        }
    }
    
    private void updateThreatIntelligence() {
        Log.d(TAG, "Updating threat intelligence");
        
        try {
            // Prepare JSON payload
            JsonObject payload = new JsonObject();
            payload.addProperty("device_id", getDeviceId());
            payload.addProperty("last_update", getLastThreatIntelUpdate());
            
            // Send request to threat intelligence API
            RequestBody body = RequestBody.create(
                gson.toJson(payload),
                MediaType.get("application/json; charset=utf-8")
            );
            
            Request request = new Request.Builder()
                .url(THREAT_INTEL_ENDPOINT)
                .post(body)
                .addHeader("Authorization", "Bearer " + getAuthToken())
                .build();
            
            Response response = httpClient.newCall(request).execute();
            
            if (response.isSuccessful()) {
                String responseBody = response.body().string();
                JsonObject result = gson.fromJson(responseBody, JsonObject.class);
                
                if (result.has("blocked_domains")) {
                    blockedDomains.clear();
                    for (String domain : result.getAsJsonArray("blocked_domains")) {
                        blockedDomains.add(domain);
                    }
                    
                    // Save updated list
                    saveBlockedDomains();
                    setLastThreatIntelUpdate(System.currentTimeMillis());
                    
                    Log.d(TAG, "Updated threat intelligence with " + blockedDomains.size() + " domains");
                }
            } else {
                Log.e(TAG, "Threat intelligence update failed with code: " + response.code());
            }
        } catch (Exception e) {
            Log.e(TAG, "Error updating threat intelligence", e);
        }
    }
    
    private void checkNetworkConnections() {
        Log.d(TAG, "Checking network connections");
        
        try {
            // Read active network connections from /proc/net/
            checkTCPConnections();
            checkUDPConnections();
        } catch (Exception e) {
            Log.e(TAG, "Error checking network connections", e);
        }
    }
    
    private void checkTCPConnections() {
        try {
            File tcpFile = new File("/proc/net/tcp");
            if (tcpFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(tcpFile));
                String line;
                
                // Skip header line
                reader.readLine();
                
                while ((line = reader.readLine()) != null) {
                    // Parse connection info
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length >= 4) {
                        // Extract remote address and port
                        String remoteAddr = parts[2];
                        String[] addrParts = remoteAddr.split(":");
                        if (addrParts.length == 2) {
                            String ipHex = addrParts[0];
                            String portHex = addrParts[1];
                            
                            // Convert hex to decimal
                            int port = Integer.parseInt(portHex, 16);
                            
                            // Check if port is a known C2 port
                            for (int c2Port : C2_PORTS) {
                                if (port == c2Port) {
                                    Log.w(TAG, "Suspicious C2 connection detected on port " + port);
                                    // In a real implementation, we would take action here
                                    break;
                                }
                            }
                        }
                    }
                }
                reader.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error checking TCP connections", e);
        }
    }
    
    private void checkUDPConnections() {
        try {
            File udpFile = new File("/proc/net/udp");
            if (udpFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(udpFile));
                String line;
                
                // Skip header line
                reader.readLine();
                
                while ((line = reader.readLine()) != null) {
                    // Parse connection info
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length >= 4) {
                        // Extract remote address and port
                        String remoteAddr = parts[2];
                        String[] addrParts = remoteAddr.split(":");
                        if (addrParts.length == 2) {
                            String ipHex = addrParts[0];
                            String portHex = addrParts[1];
                            
                            // Convert hex to decimal
                            int port = Integer.parseInt(portHex, 16);
                            
                            // Check if port is a known C2 port
                            for (int c2Port : C2_PORTS) {
                                if (port == c2Port) {
                                    Log.w(TAG, "Suspicious C2 connection detected on UDP port " + port);
                                    // In a real implementation, we would take action here
                                    break;
                                }
                            }
                        }
                    }
                }
                reader.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error checking UDP connections", e);
        }
    }
    
    private void monitorDNSQueries() {
        // Monitor DNS queries by checking /proc/net/ files or using other methods
        // This is a simplified implementation
        
        try {
            // Check for DNS queries in /proc/net/tcp6 (IPv6 DNS is on port 53)
            File tcp6File = new File("/proc/net/tcp6");
            if (tcp6File.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(tcp6File));
                String line;
                
                // Skip header line
                reader.readLine();
                
                while ((line = reader.readLine()) != null) {
                    if (line.contains(":0035")) { // Port 53 in hex
                        // This might be a DNS query
                        Log.d(TAG, "DNS query detected (IPv6)");
                    }
                }
                reader.close();
            }
            
            // Check for DNS queries in /proc/net/udp (IPv4 DNS is on port 53)
            File udpFile = new File("/proc/net/udp");
            if (udpFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(udpFile));
                String line;
                
                // Skip header line
                reader.readLine();
                
                while ((line = reader.readLine()) != null) {
                    if (line.contains(":0035")) { // Port 53 in hex
                        // This might be a DNS query
                        Log.d(TAG, "DNS query detected (IPv4)");
                        analyzeDNSTraffic(line);
                    }
                }
                reader.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error monitoring DNS queries", e);
        }
    }
    
    private void analyzeDNSTraffic(String line) {
        // Analyze DNS traffic for suspicious patterns
        try {
            String[] parts = line.trim().split("\\s+");
            if (parts.length >= 2) {
                // Extract remote address
                String remoteAddr = parts[2];
                String[] addrParts = remoteAddr.split(":");
                if (addrParts.length == 2) {
                    // In a real implementation, we would analyze the DNS query
                    // For now, we'll just log that we detected DNS traffic
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error analyzing DNS traffic", e);
        }
    }
    
    public boolean isDomainBlocked(String domain) {
        // Check if domain is in blocked list
        if (blockedDomains.contains(domain)) {
            return true;
        }
        
        // Check for suspicious patterns
        for (String pattern : SUSPICIOUS_PATTERNS) {
            if (Pattern.matches(pattern, domain)) {
                Log.w(TAG, "Suspicious domain pattern detected: " + domain);
                return true;
            }
        }
        
        return false;
    }
    
    public boolean isIpAddressBlocked(String ipAddress) {
        // Try to resolve IP to domain and check
        try {
            InetAddress addr = InetAddress.getByName(ipAddress);
            String hostname = addr.getHostName();
            return isDomainBlocked(hostname);
        } catch (UnknownHostException e) {
            Log.d(TAG, "Could not resolve IP to hostname: " + ipAddress);
            return false;
        }
    }
    
    private void loadBlockedDomains() {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String blockedDomainsStr = prefs.getString("blocked_domains", "");
        
        if (!blockedDomainsStr.isEmpty()) {
            String[] domains = blockedDomainsStr.split(",");
            for (String domain : domains) {
                blockedDomains.add(domain.trim());
            }
        }
        
        Log.d(TAG, "Loaded " + blockedDomains.size() + " blocked domains");
    }
    
    private void saveBlockedDomains() {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        
        StringBuilder sb = new StringBuilder();
        for (String domain : blockedDomains) {
            if (sb.length() > 0) {
                sb.append(",");
            }
            sb.append(domain);
        }
        
        editor.putString("blocked_domains", sb.toString());
        editor.apply();
    }
    
    private long getLastThreatIntelUpdate() {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        return prefs.getLong("last_threat_intel_update", 0);
    }
    
    private void setLastThreatIntelUpdate(long timestamp) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putLong("last_threat_intel_update", timestamp);
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
}