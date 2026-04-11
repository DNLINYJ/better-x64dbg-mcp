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
    nlohmann::json last_crash();

    // Called from plugin callbacks to capture/clear launch-time session state.
    void capture_launch_target(const char* file_name);  // CBINITDEBUG
    void mark_attached();                               // CBATTACH
    void capture_launch_cwd();                          // CBCREATEPROCESS
    void clear_launch_state();                          // CBSTOPDEBUG
}
