#ifndef COMPLIANCE_H
#define COMPLIANCE_H

#include <string>
#include <vector>

class ComplianceManager {
private:
    std::vector<std::string> applicable_regulations;
    
public:
    ComplianceManager();
    ~ComplianceManager();
    
    bool IsGDPRCompliant();
    bool IsCCPACompliant();
    bool IsMalawiCompliant();
    void LogComplianceEvent(const std::string& event);
    std::string GetComplianceStatus();
    bool CheckDataHandlingCompliance();
    void GenerateComplianceReport();
};

#endif // COMPLIANCE_H