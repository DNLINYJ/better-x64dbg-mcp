#include "handlers/annotation_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

namespace handlers::annotations {

nlohmann::json get_label(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    return {{"address", format_utils::format_address(address)}, {"label", bridge.get_label_at(address)}};
}

nlohmann::json set_label(const std::string& address_str, const std::string& text) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    if (!bridge.set_label_at(address, text)) throw std::runtime_error("Failed to set label");
    return {{"address", format_utils::format_address(address)}, {"label", text}};
}

nlohmann::json get_comment(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    return {{"address", format_utils::format_address(address)}, {"comment", bridge.get_comment_at(address)}};
}

nlohmann::json set_comment(const std::string& address_str, const std::string& text) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    if (!bridge.set_comment_at(address, text)) throw std::runtime_error("Failed to set comment");
    return {{"address", format_utils::format_address(address)}, {"comment", text}};
}

nlohmann::json set_bookmark(const std::string& address_str, bool set) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    if (!bridge.set_bookmark_at(address, set)) throw std::runtime_error("Failed to set bookmark");
    return {{"address", format_utils::format_address(address)}, {"bookmarked", set}};
}

} // namespace handlers::annotations
