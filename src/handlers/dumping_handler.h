#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::dumping {
    nlohmann::json dump_module(const std::string& module, const std::string& file);
    nlohmann::json pe_header(const std::string& address);
    nlohmann::json sections(const std::string& module);
    nlohmann::json imports(const std::string& module);
    nlohmann::json exports(const std::string& module);
    nlohmann::json fix_iat(const std::string& oep);
    nlohmann::json relocations(const std::string& address);
    nlohmann::json export_patches(const std::string& filename);
    nlohmann::json entry_point(const std::string& module);
}
