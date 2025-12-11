// AegisAI Security Module
// =======================

#ifndef AEGISAI_SECURITY_H
#define AEGISAI_SECURITY_H

#include <string>
#include <windows.h>

class SecurityManager {
private:
    std::string encryptionKey;
    std::string jwtSecret;
    
    // Base64 helper functions
    std::string Base64Encode(const std::string& data);
    std::string Base64Decode(const std::string& data);
    
public:
    SecurityManager();
    
    // JWT Token Management
    std::string GenerateJWTToken(const std::string& agentId);
    bool VerifyJWTToken(const std::string& token, std::string& agentId);
    
    // Data Encryption
    std::string EncryptData(const std::string& data);
    std::string DecryptData(const std::string& encryptedData);
    
    // Secure Credential Storage
    bool StoreCredentialsSecurely(const std::string& token);
    std::string RetrieveCredentialsSecurely();
    
    // Certificate Pinning
    bool VerifyServerCertificate(const std::string& serverCert);
    
    // Code Signing Verification
    bool VerifyCodeSignature(const std::string& filePath);
    
    // Privacy Controls
    bool IsTelemetryEnabled();
    void SetTelemetryEnabled(bool enabled);
    
    // GDPR/CCPA Compliance
    bool IsDataAnonymized();
    std::string AnonymizeData(const std::string& data);
};

// Global security manager instance
extern SecurityManager* g_securityManager;

#endif // AEGISAI_SECURITY_H