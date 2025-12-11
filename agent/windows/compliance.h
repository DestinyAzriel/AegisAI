// AegisAI Compliance Module
// ========================

#ifndef AEGISAI_COMPLIANCE_H
#define AEGISAI_COMPLIANCE_H

#include <string>
#include <vector>
#include <map>

class ComplianceManager {
private:
    bool gdprCompliant;
    bool ccpaCompliant;
    bool malawiDPACompliant;
    
    // User consent tracking
    std::map<std::string, bool> userConsents;
    
    // Data retention policies
    int dataRetentionDays;
    
public:
    ComplianceManager();
    
    // GDPR Compliance
    bool IsGDPRCompliant();
    void SetGDPRCompliant(bool compliant);
    bool HasUserConsent(const std::string& consentType);
    void SetUserConsent(const std::string& consentType, bool consent);
    std::string GetPrivacyNotice();
    
    // CCPA Compliance
    bool IsCCPACompliant();
    void SetCCPACompliant(bool compliant);
    bool HasUserOptOut();
    void SetUserOptOut(bool optOut);
    std::string GetCCPANotice();
    
    // Malawi Data Protection Act Compliance
    bool IsMalawiDPACompliant();
    void SetMalawiDPACompliant(bool compliant);
    
    // Data Retention
    int GetDataRetentionDays();
    void SetDataRetentionDays(int days);
    
    // Data Processing Records
    void LogDataProcessingActivity(const std::string& activity, const std::string& purpose);
    std::vector<std::string> GetDataProcessingRecords();
    
    // Right to Access & Erasure
    bool CanUserAccessData(const std::string& userId);
    bool CanUserRequestErasure(const std::string& userId);
    bool ProcessDataAccessRequest(const std::string& userId);
    bool ProcessDataErasureRequest(const std::string& userId);
    
    // Audit Trail
    void LogComplianceEvent(const std::string& event, const std::string& details);
    std::vector<std::string> GetComplianceAuditTrail();
};

// Global compliance manager instance
extern ComplianceManager* g_complianceManager;

#endif // AEGISAI_COMPLIANCE_H