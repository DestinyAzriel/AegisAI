#include "security.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>

SecurityManager::SecurityManager() : secret_key("aegisai_linux_agent_secret_key") {
    std::cout << "🔐 Security manager initialized" << std::endl;
}

SecurityManager::~SecurityManager() {
    // Cleanup if needed
}

std::string SecurityManager::GenerateJWTToken(const std::string& agent_id) {
    auto token = jwt::create()
        .set_issuer("aegisai-linux-agent")
        .set_subject(agent_id)
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours{24})
        .set_type("JWT")
        .sign(jwt::algorithm::hs256{secret_key});
    
    std::cout << "✅ Generated auth token for agent " << agent_id << std::endl;
    return token;
}

bool SecurityManager::VerifyJWTToken(const std::string& token) {
    try {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{secret_key})
            .with_issuer("aegisai-linux-agent");
        
        verifier.verify(decoded);
        std::cout << "✅ Token verification successful" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "❌ Token verification failed: " << e.what() << std::endl;
        return false;
    }
}

std::string SecurityManager::EncryptData(const std::string& data) {
    // In a real implementation, this would use proper encryption
    // For now, we'll just return the data as-is
    return data;
}

std::string SecurityManager::DecryptData(const std::string& encrypted_data) {
    // In a real implementation, this would use proper decryption
    // For now, we'll just return the data as-is
    return encrypted_data;
}

std::string SecurityManager::Base64Encode(const std::string& data) {
    BIO* bio, *b64;
    BUF_MEM* bufferPtr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.c_str(), data.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    
    BIO_free_all(bio);
    return result;
}

std::string SecurityManager::Base64Decode(const std::string& encoded_data) {
    BIO* bio, *b64;
    
    int decodeLen = encoded_data.size();
    char* buffer = new char[decodeLen + 1];
    
    bio = BIO_new_mem_buf(encoded_data.c_str(), -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    decodeLen = BIO_read(bio, buffer, encoded_data.size());
    buffer[decodeLen] = '\0';
    
    std::string result(buffer);
    delete[] buffer;
    
    BIO_free_all(bio);
    return result;
}

bool SecurityManager::VerifyCodeSignature(const std::string& file_path) {
    // In a real implementation, this would verify code signatures
    // For now, we'll just return true
    return true;
}

bool SecurityManager::IsTelemetryEnabled() {
    // In a real implementation, this would check telemetry settings
    // For now, we'll just return true
    return true;
}