// TEST DATA FIXTURE - CLEAN C++ PATTERNS
#include <iostream>
#include <memory>
#include <string>
#include <vector>

void safe_process_request(const std::string& data) {
    // Modern smart pointers avoiding raw new/delete
    auto safe_buffer = std::make_unique<std::vector<int>>(100);

    // Safe string operations
    std::string message = "Result: " + data;
    std::cout << message << std::endl;
}
