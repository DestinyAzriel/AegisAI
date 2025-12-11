package com.aegisai.android;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "AegisAI-MainActivity";
    private static final int REQUEST_CODE_ENABLE_ADMIN = 1;
    
    private DevicePolicyManager devicePolicyManager;
    private ComponentName adminComponent;
    private AegisAIService aegisService;
    
    private TextView statusText;
    private Button startServiceButton;
    private Button stopServiceButton;
    private Button scanButton;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        initViews();
        initDeviceAdmin();
        setupEventHandlers();
        
        // Start the background service
        startAegisService();
    }
    
    private void initViews() {
        statusText = findViewById(R.id.statusText);
        startServiceButton = findViewById(R.id.startServiceButton);
        stopServiceButton = findViewById(R.id.stopServiceButton);
        scanButton = findViewById(R.id.scanButton);
    }
    
    private void initDeviceAdmin() {
        devicePolicyManager = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        adminComponent = new ComponentName(this, AegisDeviceAdminReceiver.class);
        
        // Check if admin is already enabled
        if (!devicePolicyManager.isAdminActive(adminComponent)) {
            requestDeviceAdmin();
        }
    }
    
    private void requestDeviceAdmin() {
        Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
        intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent);
        intent.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "AegisAI needs device admin permissions to protect your device");
        startActivityForResult(intent, REQUEST_CODE_ENABLE_ADMIN);
    }
    
    private void setupEventHandlers() {
        startServiceButton.setOnClickListener(v -> startAegisService());
        stopServiceButton.setOnClickListener(v -> stopAegisService());
        scanButton.setOnClickListener(v -> performScan());
    }
    
    private void startAegisService() {
        Intent serviceIntent = new Intent(this, AegisAIService.class);
        startService(serviceIntent);
        statusText.setText("AegisAI Service Running");
        Toast.makeText(this, "AegisAI protection started", Toast.LENGTH_SHORT).show();
    }
    
    private void stopAegisService() {
        Intent serviceIntent = new Intent(this, AegisAIService.class);
        stopService(serviceIntent);
        statusText.setText("AegisAI Service Stopped");
        Toast.makeText(this, "AegisAI protection stopped", Toast.LENGTH_SHORT).show();
    }
    
    private void performScan() {
        // Trigger a manual scan
        Intent scanIntent = new Intent(AegisAIService.ACTION_SCAN);
        sendBroadcast(scanIntent);
        Toast.makeText(this, "Scan initiated", Toast.LENGTH_SHORT).show();
    }
    
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        
        if (requestCode == REQUEST_CODE_ENABLE_ADMIN) {
            if (resultCode == Activity.RESULT_OK) {
                Log.d(TAG, "Device admin enabled");
                Toast.makeText(this, "Device admin permissions granted", Toast.LENGTH_SHORT).show();
            } else {
                Log.d(TAG, "Device admin request denied");
                Toast.makeText(this, "Device admin permissions required for full protection", Toast.LENGTH_LONG).show();
            }
        }
    }
}