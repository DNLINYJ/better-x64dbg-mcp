#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::tracing {
    nlohmann::json trace_into(const nlohmann::json& args);
    nlohmann::json trace_over(const nlohmann::json& args);
    nlohmann::json run_to_party(const std::string& party);
    nlohmann::json stop_trace();
    nlohmann::json record_hitcount(const std::string& address);
    nlohmann::json record_type(const std::string& address);
    nlohmann::json set_record_type(const std::string& address, int type);
    nlohmann::json animate(const std::string& command);
    nlohmann::json conditional_run(const nlohmann::json& args);
    nlohmann::json log_trace(const nlohmann::json& args);
}
