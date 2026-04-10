#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::debug {
    nlohmann::json state();
    nlohmann::json run();
    nlohmann::json pause();
    nlohmann::json force_pause();
    nlohmann::json step_into();
    nlohmann::json step_over();
    nlohmann::json step_out();
    nlohmann::json stop_debug();
    nlohmann::json restart_debug();
    nlohmann::json run_to_address(const std::string& address);
}
