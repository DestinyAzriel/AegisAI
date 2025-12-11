package com.aegisai.android;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Memory Scanner for AegisAI Android Agent
 * Detects fileless malware by scanning process memory and system information
 */
public class MemoryScanner {
    private static final String TAG = "AegisAI_MemoryScanner";
    private Context context;
    
    // Suspicious patterns for fileless malware detection
    private static final String[] SUSPICIOUS_PATTERNS = {
        ".*exec.*sh.*",
        ".*chmod.*777.*",
        ".*wget.*http.*",
        ".*curl.*http.*",
        ".*su.*",
        ".*root.*",
        ".*hack.*",
        ".*malware.*",
        ".*payload.*",
        ".*reverse.*shell.*",
        ".*bind.*shell.*",
        ".*meterpreter.*",
        ".*empire.*",
        ".*cobalt.*strike.*"
    };
    
    // Suspicious process names
    private static final String[] SUSPICIOUS_PROCESSES = {
        "su",
        "busybox",
        "magisk",
        "supersu",
        "xposed",
        "substrate"
    };
    
    public MemoryScanner(Context context) {
        this.context = context;
    }
    
    /**
     * Scan system for fileless malware indicators
     * @return List of scan results
     */
    public List<ScanResult> scanForFilelessMalware() {
        List<ScanResult> results = new ArrayList<>();
        
        try {
            // Scan running processes
            scanProcesses(results);
            
            // Scan system properties
            scanSystemProperties(results);
            
            // Scan temporary directories
            scanTemporaryDirectories(results);
            
            // Scan for suspicious network connections
            scanNetworkConnections(results);
            
        } catch (Exception e) {
            Log.e(TAG, "Error during memory scan: " + e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Scan running processes for suspicious activity
     * @param results List to store scan results
     */
    private void scanProcesses(List<ScanResult> results) {
        try {
            // Read process list from /proc
            File procDir = new File("/proc");
            if (procDir.exists() && procDir.isDirectory()) {
                File[] pidDirs = procDir.listFiles();
                if (pidDirs != null) {
                    for (File pidDir : pidDirs) {
                        if (pidDir.isDirectory() && pidDir.getName().matches("\\d+")) {
                            scanProcess(pidDir, results);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error scanning processes: " + e.getMessage());
        }
    }
    
    /**
     * Scan individual process for suspicious activity
     * @param pidDir Process directory
     * @param results List to store scan results
     */
    private void scanProcess(File pidDir, List<ScanResult> results) {
        try {
            String pid = pidDir.getName();
            
            // Read command line
            File cmdlineFile = new File(pidDir, "cmdline");
            if (cmdlineFile.exists()) {
                StringBuilder cmdline = new StringBuilder();
                BufferedReader reader = new BufferedReader(new FileReader(cmdlineFile));
                String line;
                while ((line = reader.readLine()) != null) {
                    cmdline.append(line).append(" ");
                }
                reader.close();
                
                String cmdlineStr = cmdline.toString();
                
                // Check for suspicious patterns in command line
                for (String pattern : SUSPICIOUS_PATTERNS) {
                    if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(cmdlineStr).find()) {
                        results.add(new ScanResult(
                            "suspicious_process",
                            "Suspicious process command line: " + pattern,
                            0.8,
                            pid
                        ));
                    }
                }
                
                // Check for suspicious process names
                for (String suspiciousProcess : SUSPICIOUS_PROCESSES) {
                    if (cmdlineStr.contains(suspiciousProcess)) {
                        results.add(new ScanResult(
                            "suspicious_process_name",
                            "Suspicious process name: " + suspiciousProcess,
                            0.9,
                            pid
                        ));
                    }
                }
            }
            
            // Read process environment
            File environFile = new File(pidDir, "environ");
            if (environFile.exists()) {
                // Environment scanning would go here
                // Note: Reading environ file requires root access in most cases
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Error scanning process " + pidDir.getName() + ": " + e.getMessage());
        }
    }
    
    /**
     * Scan system properties for suspicious values
     * @param results List to store scan results
     */
    private void scanSystemProperties(List<ScanResult> results) {
        try {
            // Check for root detection bypass properties
            String[] properties = {
                "ro.secure",
                "ro.debuggable",
                "ro.build.type",
                "ro.build.tags"
            };
            
            for (String prop : properties) {
                String value = getSystemProperty(prop);
                if (value != null) {
                    // Check for suspicious property values
                    if ("ro.secure".equals(prop) && "0".equals(value)) {
                        results.add(new ScanResult(
                            "suspicious_property",
                            "Device may be insecure (ro.secure=0)",
                            0.7,
                            prop
                        ));
                    } else if ("ro.debuggable".equals(prop) && "1".equals(value)) {
                        results.add(new ScanResult(
                            "suspicious_property",
                            "Debugging enabled (ro.debuggable=1)",
                            0.6,
                            prop
                        ));
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error scanning system properties: " + e.getMessage());
        }
    }
    
    /**
     * Get system property value
     * @param key Property key
     * @return Property value or null if not found
     */
    private String getSystemProperty(String key) {
        try {
            Class<?> clazz = Class.forName("android.os.SystemProperties");
            return (String) clazz.getMethod("get", String.class).invoke(null, key);
        } catch (Exception e) {
            Log.e(TAG, "Error getting system property " + key + ": " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Scan temporary directories for suspicious files
     * @param results List to store scan results
     */
    private void scanTemporaryDirectories(List<ScanResult> results) {
        String[] tempDirs = {
            "/data/local/tmp",
            "/cache",
            "/sdcard/Download"
        };
        
        for (String tempDir : tempDirs) {
            File dir = new File(tempDir);
            if (dir.exists() && dir.isDirectory()) {
                scanDirectory(dir, results);
            }
        }
    }
    
    /**
     * Scan directory for suspicious files
     * @param dir Directory to scan
     * @param results List to store scan results
     */
    private void scanDirectory(File dir, List<ScanResult> results) {
        try {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isFile()) {
                        // Check file name for suspicious patterns
                        String fileName = file.getName().toLowerCase();
                        for (String pattern : SUSPICIOUS_PATTERNS) {
                            if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(fileName).find()) {
                                results.add(new ScanResult(
                                    "suspicious_file",
                                    "Suspicious file found: " + fileName,
                                    0.7,
                                    file.getAbsolutePath()
                                ));
                            }
                        }
                    } else if (file.isDirectory()) {
                        // Recursively scan subdirectories
                        scanDirectory(file, results);
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error scanning directory " + dir.getAbsolutePath() + ": " + e.getMessage());
        }
    }
    
    /**
     * Scan network connections for suspicious activity
     * @param results List to store scan results
     */
    private void scanNetworkConnections(List<ScanResult> results) {
        try {
            // Read network connections from /proc/net/
            File tcpFile = new File("/proc/net/tcp");
            if (tcpFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(tcpFile));
                String line;
                while ((line = reader.readLine()) != null) {
                    // Look for suspicious connections
                    // This is a simplified check - real implementation would be more sophisticated
                    if (line.contains(":1F90") || line.contains(":2710")) { // Ports 8080, 10000
                        results.add(new ScanResult(
                            "suspicious_connection",
                            "Suspicious network connection detected",
                            0.6,
                            line
                        ));
                    }
                }
                reader.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error scanning network connections: " + e.getMessage());
        }
    }
    
    /**
     * Scan result class
     */
    public static class ScanResult {
        private String type;
        private String description;
        private double confidence;
        private String details;
        private long timestamp;
        
        public ScanResult(String type, String description, double confidence, String details) {
            this.type = type;
            this.description = description;
            this.confidence = confidence;
            this.details = details;
            this.timestamp = System.currentTimeMillis();
        }
        
        // Getters
        public String getType() { return type; }
        public String getDescription() { return description; }
        public double getConfidence() { return confidence; }
        public String getDetails() { return details; }
        public long getTimestamp() { return timestamp; }
        
        @Override
        public String toString() {
            return String.format("ScanResult{type='%s', description='%s', confidence=%.2f, details='%s'}",
                type, description, confidence, details);
        }
    }
}