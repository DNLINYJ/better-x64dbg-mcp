#include "handlers/tracing_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers::tracing {

nlohmann::json trace_into(const nlohmann::json& args) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    std::string cmd = "TraceIntoConditional";
    if (args.contains("condition") && !args["condition"].get<std::string>().empty()) cmd += " " + args["condition"].get<std::string>();
    if (args.contains("max_steps") && !args["max_steps"].get<std::string>().empty()) cmd += ", " + args["max_steps"].get<std::string>();
    if (args.contains("log_text") && !args["log_text"].get<std::string>().empty()) cmd += ", " + args["log_text"].get<std::string>();
    return {{"success", bridge.exec_command_async(cmd)}, {"command", cmd}, {"message", "Trace into started (async)"}};
}

nlohmann::json trace_over(const nlohmann::json& args) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    std::string cmd = "TraceOverConditional";
    if (args.contains("condition") && !args["condition"].get<std::string>().empty()) cmd += " " + args["condition"].get<std::string>();
    if (args.contains("max_steps") && !args["max_steps"].get<std::string>().empty()) cmd += ", " + args["max_steps"].get<std::string>();
    if (args.contains("log_text") && !args["log_text"].get<std::string>().empty()) cmd += ", " + args["log_text"].get<std::string>();
    return {{"success", bridge.exec_command_async(cmd)}, {"command", cmd}, {"message", "Trace over started (async)"}};
}

nlohmann::json run_to_party(const std::string& party) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto cmd = "RunToParty " + party;
    return {{"success", bridge.exec_command_async(cmd)}, {"command", cmd}, {"message", "Run to party started (async)"}};
}

nlohmann::json stop_trace() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    return {{"success", bridge.exec_command("StopRunTrace")}, {"message", "Trace stopped"}};
}

nlohmann::json record_hitcount(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    return {{"address", format_utils::format_address(address)}, {"hit_count", DbgFunctions()->GetTraceRecordHitCount(address)}};
}

nlohmann::json record_type(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    auto bt = DbgFunctions()->GetTraceRecordByteType(address);
    const char* names[] = {"InstructionBody","InstructionHeading","InstructionTailing","InstructionOverlapped",
        "DataByte","DataWord","DataDWord","DataQWord","DataFloat","DataDouble","DataLongDouble",
        "DataXMM","DataYMM","DataMMX","DataMixed","InstructionDataMixed"};
    auto type_str = (static_cast<int>(bt) < 16) ? names[static_cast<int>(bt)] : "Unknown";
    return {{"address", format_utils::format_address(address)}, {"type", type_str}, {"type_id", static_cast<int>(bt)}};
}

nlohmann::json set_record_type(const std::string& address_str, int type) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    return {{"success", DbgFunctions()->SetTraceRecordType(address, static_cast<TRACERECORDTYPE>(type))},
            {"address", format_utils::format_address(address)}, {"type", type}};
}

nlohmann::json animate(const std::string& command) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    return {{"success", DbgFunctions()->AnimateCommand(command.c_str())}, {"command", command}};
}

nlohmann::json conditional_run(const nlohmann::json& args) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto trace_type = args.value("type", "into");
    if (trace_type != "into" && trace_type != "over")
        throw std::runtime_error("Invalid trace type '" + trace_type + "', expected: into, over");
    std::string cmd = (trace_type == "over") ? "TraceOverConditional" : "TraceIntoConditional";
    if (args.contains("break_condition") && !args["break_condition"].get<std::string>().empty())
        cmd += " " + args["break_condition"].get<std::string>();
    return {{"success", bridge.exec_command_async(cmd)}, {"command", cmd}, {"type", trace_type}, {"message", "Conditional trace started (async)"}};
}

nlohmann::json log_trace(const nlohmann::json& args) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto file = args.value("file", "");
    if (file.empty()) throw std::runtime_error("Missing 'file' field");
    std::string cmd = "StartRunTrace " + file;
    if (args.contains("text") && !args["text"].get<std::string>().empty()) cmd += ", " + args["text"].get<std::string>();
    return {{"success", bridge.exec_command(cmd)}, {"command", cmd}, {"file", file}};
}

} // namespace handlers::tracing
