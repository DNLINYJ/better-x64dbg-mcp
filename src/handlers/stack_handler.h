#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::stack {
    nlohmann::json trace();
    nlohmann::json read(const std::string& address, size_t size);
    nlohmann::json pointers();
    nlohmann::json comment(const std::string& address);
    nlohmann::json callstack_thread(const std::string& handle);
    nlohmann::json return_address();
    nlohmann::json seh_chain();
}
