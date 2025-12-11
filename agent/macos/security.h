#ifndef SECURITY_H
#define SECURITY_H

#include <string>
#include <ctime>

// OpenSSL headers - macOS specific paths
#if defined(__APPLE__)
#include <openssl/sha.h>
#include <openssl/hmac.h>
#else
#include <openssl/sha.h>
#include <openssl/hmac.h>
#endif

class SecurityManager {
private:
    std::string secret_key;
    
public:
    SecurityManager();
    ~SecurityManager();
    
    std::string GenerateJWTToken(const std::string& agent_id);
    bool VerifyJWTToken(const std::string& token);
    std::string EncryptData(const std::string& data);
    std::string DecryptData(const std::string& encrypted_data);
    std::string Base64Encode(const std::string& data);
    std::string Base64Decode(const std::string& encoded_data);
    bool VerifyCodeSignature(const std::string& file_path);
    bool IsTelemetryEnabled();
};

#endif // SECURITY_H