#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::analysis {
    nlohmann::json function_bounds(const std::string& address);
    nlohmann::json xrefs_to(const std::string& address);
    nlohmann::json xrefs_from(const std::string& address);
    nlohmann::json basic_blocks(const std::string& address);
    nlohmann::json constants();
    nlohmann::json error_codes();
    nlohmann::json watch(unsigned int id);
    nlohmann::json structs();
    nlohmann::json source(const std::string& address);
    nlohmann::json va_to_file(const std::string& address);
    nlohmann::json file_to_va(const std::string& module, const std::string& offset);
    nlohmann::json mnemonic_brief(const std::string& mnemonic);
    nlohmann::json find_strings(const std::string& module);
}
