// AegisAI WFP Filter Test
// ======================

#include "wfp_filter.h"
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    std::cout << "🛡️  AegisAI WFP Filter Test" << std::endl;
    std::cout << "===========================" << std::endl;
    
    // Create WFP filter instance
    WFPNetworkFilter* wfpFilter = new WFPNetworkFilter();
    
    // Initialize the filter
    std::cout << "Initializing WFP filter..." << std::endl;
    if (wfpFilter->Initialize()) {
        std::cout << "✅ WFP filter initialized successfully" << std::endl;
        
        // Start filtering
        std::cout << "Starting network filtering..." << std::endl;
        if (wfpFilter->StartFiltering()) {
            std::cout << "✅ Network filtering started" << std::endl;
            
            // Let it run for a few seconds
            std::cout << "Filter running for 5 seconds..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            // Show statistics
            std::cout << "📊 Statistics:" << std::endl;
            std::cout << "   Packets processed: " << wfpFilter->GetPacketsProcessed() << std::endl;
            std::cout << "   Packets blocked: " << wfpFilter->GetPacketsBlocked() << std::endl;
            std::cout << "   Packets allowed: " << wfpFilter->GetPacketsAllowed() << std::endl;
            
            // Stop filtering
            wfpFilter->StopFiltering();
            std::cout << "✅ Network filtering stopped" << std::endl;
        } else {
            std::cerr << "❌ Failed to start network filtering" << std::endl;
        }
    } else {
        std::cerr << "❌ Failed to initialize WFP filter" << std::endl;
    }
    
    // Cleanup
    delete wfpFilter;
    
    std::cout << "✅ WFP filter test completed" << std::endl;
    return 0;
}