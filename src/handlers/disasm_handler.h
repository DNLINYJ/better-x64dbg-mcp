#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::disasm {
    nlohmann::json at(const std::string& address, int count);
    nlohmann::json function(const std::string& address, int max_instructions);
    nlohmann::json basic(const std::string& address);
    nlohmann::json assemble(const std::string& address, const std::string& instruction);
}
