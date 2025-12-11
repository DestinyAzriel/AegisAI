package com.aegisai.android;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Ransomware Protection for AegisAI Android Agent
 * Provides protection against ransomware through canary files and behavioral monitoring
 */
public class RansomwareProtection {
    private static final String TAG = "AegisAI_Ransomware";
    private static final String PREFS_NAME = "AegisAI_RansomwarePrefs";
    private static final String CANARY_DIR = "/data/data/com.aegisai.android/canaries";
    
    private Context context;
    private SharedPreferences prefs;
    private ScheduledExecutorService scheduler;
    private Map<String, String> canaryFiles;
    private List<RansomwareListener> listeners;
    
    // File extensions commonly targeted by ransomware
    private static final String[] TARGETED_EXTENSIONS = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".txt", ".jpg", ".jpeg", ".png", ".bmp",
        ".mp3", ".mp4", ".avi", ".mov", ".zip", ".rar"
    };
    
    // Suspicious ransomware file extensions
    private static final String[] RANSOMWARE_EXTENSIONS = {
        ".encrypted", ".locked", ".crypto", ".vault", ".onion",
        ".zepto", ".odin", ".cerber", ".locky", ".crypt",
        ".aaa", ".abc", ".xyz", ".zzz", ".ecc", ".exx",
        ".ezz", ".rrk", ".xrtn", ".XTBL", ".RDM", ".RRK"
    };
    
    // Ransomware note file names
    private static final String[] RANSOMWARE_NOTES = {
        "README.txt", "README.md", "HOW TO DECRYPT.txt",
        "FILES.txt", "DECRYPT.txt", "INSTRUCTION.txt",
        "HELP.txt", "HELP_ME.txt", "HELP_ME_PLEASE.txt"
    };
    
    public interface RansomwareListener {
        void onRansomwareDetected(String details);
        void onSuspiciousActivity(String details);
    }
    
    public RansomwareProtection(Context context) {
        this.context = context;
        this.prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        this.scheduler = Executors.newScheduledThreadPool(2);
        this.canaryFiles = new HashMap<>();
        this.listeners = new ArrayList<>();
        
        // Initialize canary directory
        initializeCanarySystem();
    }
    
    /**
     * Initialize the canary file system
     */
    private void initializeCanarySystem() {
        try {
            File canaryDir = new File(CANARY_DIR);
            if (!canaryDir.exists()) {
                canaryDir.mkdirs();
            }
            
            // Create canary files
            createCanaryFiles();
            
            // Load existing canary hashes
            loadCanaryHashes();
            
        } catch (Exception e) {
            Log.e(TAG, "Error initializing canary system: " + e.getMessage());
        }
    }
    
    /**
     * Create canary files for ransomware detection
     */
    private void createCanaryFiles() {
        try {
            for (int i = 0; i < 15; i++) { // Increased from 10 to 15
                String fileName = "canary_" + i + ".txt";
                File canaryFile = new File(CANARY_DIR, fileName);
                
                if (!canaryFile.exists()) {
                    // Create a unique canary file with known content
                    String content = "AegisAI Ransomware Canary File #" + i + 
                                   "\nThis file is used for ransomware detection." +
                                   "\nModification of this file may indicate ransomware activity." +
                                   "\nDO NOT MODIFY THIS FILE!" +
                                   "\nTimestamp: " + System.currentTimeMillis() +
                                   "\nUnique ID: " + java.util.UUID.randomUUID().toString();
                    
                    java.io.FileWriter writer = new java.io.FileWriter(canaryFile);
                    writer.write(content);
                    writer.close();
                }
                
                // Calculate and store hash
                String hash = calculateFileHash(canaryFile);
                if (hash != null) {
                    canaryFiles.put(canaryFile.getAbsolutePath(), hash);
                    prefs.edit().putString("canary_" + i, hash).apply();
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error creating canary files: " + e.getMessage());
        }
    }
    
    /**
     * Load existing canary file hashes
     */
    private void loadCanaryHashes() {
        for (int i = 0; i < 15; i++) { // Increased from 10 to 15
            String hash = prefs.getString("canary_" + i, null);
            if (hash != null) {
                String fileName = "canary_" + i + ".txt";
                File canaryFile = new File(CANARY_DIR, fileName);
                canaryFiles.put(canaryFile.getAbsolutePath(), hash);
            }
        }
    }
    
    /**
     * Calculate SHA-256 hash of a file
     * @param file File to hash
     * @return Hash string or null if error
     */
    private String calculateFileHash(File file) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            java.io.FileInputStream fis = new java.io.FileInputStream(file);
            
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
            fis.close();
            
            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException | IOException e) {
            Log.e(TAG, "Error calculating file hash: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Start monitoring for ransomware activity
     */
    public void startMonitoring() {
        // Schedule canary file checking every 3 seconds
        scheduler.scheduleAtFixedRate(() -> {
            try {
                // Check canary files
                checkCanaryFiles();
            } catch (Exception e) {
                Log.e(TAG, "Error checking canary files: " + e.getMessage());
            }
        }, 0, 3, TimeUnit.SECONDS);
        
        // Schedule suspicious extension checking every 5 seconds
        scheduler.scheduleAtFixedRate(() -> {
            try {
                // Check for suspicious file extensions
                checkSuspiciousExtensions();
            } catch (Exception e) {
                Log.e(TAG, "Error checking suspicious extensions: " + e.getMessage());
            }
        }, 0, 5, TimeUnit.SECONDS);
        
        // Schedule rapid encryption detection every 2 seconds
        scheduler.scheduleAtFixedRate(() -> {
            try {
                // Check for rapid encryption patterns
                checkForRapidEncryptionPatterns();
            } catch (Exception e) {
                Log.e(TAG, "Error checking rapid encryption: " + e.getMessage());
            }
        }, 0, 2, TimeUnit.SECONDS);
    }
    
    /**
     * Stop monitoring for ransomware activity
     */
    public void stopMonitoring() {
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdownNow();
        }
    }
    
    /**
     * Check canary files for modifications
     */
    private void checkCanaryFiles() {
        for (Map.Entry<String, String> entry : canaryFiles.entrySet()) {
            String filePath = entry.getKey();
            String expectedHash = entry.getValue();
            
            File canaryFile = new File(filePath);
            if (canaryFile.exists()) {
                String currentHash = calculateFileHash(canaryFile);
                if (currentHash != null && !currentHash.equals(expectedHash)) {
                    // Canary file has been modified - possible ransomware activity
                    Log.w(TAG, "Canary file modified: " + filePath);
                    notifyRansomwareDetected("Canary file modified: " + filePath);
                }
            } else {
                // Canary file has been deleted - possible ransomware activity
                Log.w(TAG, "Canary file deleted: " + filePath);
                notifyRansomwareDetected("Canary file deleted: " + filePath);
            }
        }
    }
    
    /**
     * Check for suspicious file extensions that indicate ransomware
     */
    private void checkSuspiciousExtensions() {
        // Check common directories for files with ransomware extensions
        String[] directories = {
            context.getFilesDir().getAbsolutePath(),
            android.os.Environment.getExternalStorageDirectory().getAbsolutePath()
        };
        
        for (String directory : directories) {
            checkDirectoryForRansomware(new File(directory));
        }
    }
    
    /**
     * Check directory for files with ransomware extensions
     * @param directory Directory to check
     */
    private void checkDirectoryForRansomware(File directory) {
        if (!directory.exists() || !directory.isDirectory()) {
            return;
        }
        
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    // Recursively check subdirectories
                    checkDirectoryForRansomware(file);
                } else {
                    String fileName = file.getName().toLowerCase();
                    
                    // Check for ransomware extensions
                    for (String ext : RANSOMWARE_EXTENSIONS) {
                        if (fileName.endsWith(ext)) {
                            Log.w(TAG, "Suspicious ransomware file detected: " + file.getAbsolutePath());
                            notifyRansomwareDetected("Ransomware file detected: " + file.getAbsolutePath());
                            // Try to quarantine the file
                            quarantineFile(file);
                            break;
                        }
                    }
                    
                    // Check for ransomware note files
                    for (String note : RANSOMWARE_NOTES) {
                        if (fileName.equals(note.toLowerCase())) {
                            Log.w(TAG, "Ransomware note detected: " + file.getAbsolutePath());
                            notifyRansomwareDetected("Ransomware note detected: " + file.getAbsolutePath());
                            break;
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Attempt to quarantine a suspicious file
     * @param file File to quarantine
     */
    private void quarantineFile(File file) {
        try {
            String quarantineDirPath = context.getFilesDir().getAbsolutePath() + "/quarantine";
            File quarantineDir = new File(quarantineDirPath);
            if (!quarantineDir.exists()) {
                quarantineDir.mkdirs();
            }
            
            String newFileName = "quarantined_" + System.currentTimeMillis() + "_" + file.getName();
            File newFile = new File(quarantineDir, newFileName);
            
            // Move file to quarantine directory
            if (file.renameTo(newFile)) {
                Log.i(TAG, "File quarantined successfully: " + newFile.getAbsolutePath());
            } else {
                Log.w(TAG, "Failed to quarantine file: " + file.getAbsolutePath());
            }
        } catch (Exception e) {
            Log.e(TAG, "Error quarantining file: " + e.getMessage());
        }
    }
    
    /**
     * Check for rapid encryption patterns across multiple files
     */
    private void checkForRapidEncryptionPatterns() {
        // This is a more sophisticated check for ransomware behavior
        // It looks for patterns of multiple files being encrypted rapidly
        
        String[] directories = {
            context.getFilesDir().getAbsolutePath(),
            android.os.Environment.getExternalStorageDirectory().getAbsolutePath()
        };
        
        for (String directory : directories) {
            analyzeEncryptionPatterns(new File(directory));
        }
    }
    
    /**
     * Analyze directory for encryption patterns
     * @param directory Directory to analyze
     */
    private void analyzeEncryptionPatterns(File directory) {
        if (!directory.exists() || !directory.isDirectory()) {
            return;
        }
        
        // Track recently modified files
        long currentTime = System.currentTimeMillis();
        int recentModifications = 0;
        List<File> recentFiles = new ArrayList<>();
        
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    long lastModified = file.lastModified();
                    
                    // Check if file was modified in the last 30 seconds
                    if ((currentTime - lastModified) < 30000) {
                        recentModifications++;
                        recentFiles.add(file);
                        
                        // Check if file has a targeted extension
                        String fileName = file.getName().toLowerCase();
                        for (String ext : TARGETED_EXTENSIONS) {
                            if (fileName.endsWith(ext)) {
                                // File is targeted and recently modified
                                break;
                            }
                        }
                    }
                } else if (file.isDirectory()) {
                    // Recursively analyze subdirectories
                    analyzeEncryptionPatterns(file);
                }
            }
            
            // If more than 5 files were recently modified, this might indicate encryption
            if (recentModifications > 5) {
                Log.w(TAG, "Rapid file modification detected: " + recentModifications + " files in 30 seconds");
                notifySuspiciousActivity("Rapid file modification detected: " + recentModifications + " files");
                
                // Check if these files have suspicious extensions
                int suspiciousCount = 0;
                for (File file : recentFiles) {
                    String fileName = file.getName().toLowerCase();
                    for (String ext : RANSOMWARE_EXTENSIONS) {
                        if (fileName.endsWith(ext)) {
                            suspiciousCount++;
                            break;
                        }
                    }
                }
                
                // If more than 30% of recent files have suspicious extensions, high probability of ransomware
                if (suspiciousCount > (recentModifications * 0.3)) {
                    Log.w(TAG, "High probability ransomware activity detected");
                    notifyRansomwareDetected("High probability ransomware activity detected");
                }
            }
        }
    }
    
    /**
     * Add a listener for ransomware detection events
     * @param listener Listener to add
     */
    public void addRansomwareListener(RansomwareListener listener) {
        if (!listeners.contains(listener)) {
            listeners.add(listener);
        }
    }
    
    /**
     * Remove a listener for ransomware detection events
     * @param listener Listener to remove
     */
    public void removeRansomwareListener(RansomwareListener listener) {
        listeners.remove(listener);
    }
    
    /**
     * Notify listeners of ransomware detection
     * @param details Detection details
     */
    private void notifyRansomwareDetected(String details) {
        for (RansomwareListener listener : listeners) {
            try {
                listener.onRansomwareDetected(details);
            } catch (Exception e) {
                Log.e(TAG, "Error notifying ransomware listener: " + e.getMessage());
            }
        }
    }
    
    /**
     * Notify listeners of suspicious activity
     * @param details Activity details
     */
    private void notifySuspiciousActivity(String details) {
        for (RansomwareListener listener : listeners) {
            try {
                listener.onSuspiciousActivity(details);
            } catch (Exception e) {
                Log.e(TAG, "Error notifying suspicious activity listener: " + e.getMessage());
            }
        }
    }
    
    /**
     * Restore canary files if they've been compromised
     */
    public void restoreCanaryFiles() {
        createCanaryFiles();
        loadCanaryHashes();
        Log.i(TAG, "Canary files restored");
    }
    
    /**
     * Get the current status of the ransomware protection system
     * @return Status information
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("canary_files_count", canaryFiles.size());
        status.put("monitoring_active", !scheduler.isShutdown());
        status.put("canary_directory", CANARY_DIR);
        return status;
    }
}