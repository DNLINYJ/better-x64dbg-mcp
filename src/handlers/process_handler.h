#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::process {
    nlohmann::json details();
    nlohmann::json cmdline();
    nlohmann::json set_cmdline(const std::string& cmdline);
    nlohmann::json elevated();
    nlohmann::json dbversion();
}
