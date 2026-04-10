#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::threads {
    nlohmann::json list();
    nlohmann::json current();
    nlohmann::json get_by_id(uint32_t tid);
    nlohmann::json switch_thread(uint32_t tid);
    nlohmann::json suspend(uint32_t tid);
    nlohmann::json resume(uint32_t tid);
    nlohmann::json count();
    nlohmann::json teb(uint32_t tid);
    nlohmann::json name(uint32_t tid);
}
