// AegisAI Windows Filtering Platform (WFP) Integration
// ====================================================

#ifndef AEGISAI_WFP_FILTER_H
#define AEGISAI_WFP_FILTER_H

#include <windows.h>
#include <fwpmu.h>
#include <fwpmtypes.h>
#include <string>
#include <vector>
#include <memory>

// Forward declarations
class WebProtectionEngine;

// Network event structure
struct NetworkEvent {
    std::wstring processName;
    DWORD processId;
    std::wstring sourceIp;
    std::wstring destinationIp;
    UINT16 sourcePort;
    UINT16 destinationPort;
    UINT32 protocol;
    bool isBlocked;
    std::wstring blockedReason;
    LARGE_INTEGER timestamp;
};

// WFP Network Filter class
class WFPNetworkFilter {
private:
    HANDLE m_engineHandle;
    HANDLE m_inboundLayerId;
    HANDLE m_outboundLayerId;
    std::unique_ptr<WebProtectionEngine> m_webProtection;
    bool m_initialized;
    bool m_filteringActive;
    std::wstring m_logFilePath;
    
    // Statistics
    size_t m_packetsProcessed;
    size_t m_packetsBlocked;
    size_t m_packetsAllowed;

public:
    WFPNetworkFilter();
    ~WFPNetworkFilter();
    
    // Initialization and cleanup
    bool Initialize();
    void Cleanup();
    
    // Filter management
    bool StartFiltering();
    void StopFiltering();
    
    // Configuration
    void SetBlockAds(bool block);
    void SetBlockTracking(bool block);
    void SetBlockMalware(bool block);
    
    // Statistics
    size_t GetPacketsProcessed() const { return m_packetsProcessed; }
    size_t GetPacketsBlocked() const { return m_packetsBlocked; }
    size_t GetPacketsAllowed() const { return m_packetsAllowed; }
    
    // Logging
    void SetLogFilePath(const std::wstring& logPath);
    void LogNetworkEvent(const NetworkEvent& event);
    
private:
    // Internal helper methods
    bool RegisterLayers();
    bool RegisterFilters();
    bool UnregisterFilters();
    
    // Static callback functions
    static void NTAPI PacketCallback(
        _In_ const FWPS_INCOMING_VALUES* inFixedValues,
        _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
        _Inout_opt_ void* layerData,
        _In_opt_ const void* reserved,
        _In_ const FWPS_FILTER* filter,
        _In_ UINT64 reserved1,
        _Inout_ FWPS_CLASSIFY_OUT* classifyOut
    );
};

// Global WFP filter instance
extern WFPNetworkFilter* g_wfpFilter;

#endif // AEGISAI_WFP_FILTER_H