#include "handlers/register_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"

namespace handlers::registers {

nlohmann::json get_all() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto dump_result = bridge.get_register_dump();
    if (!dump_result.has_value()) throw std::runtime_error(dump_result.error());
    const auto& ctx = dump_result->regcontext;
    nlohmann::json regs;
#ifdef _WIN64
    regs["rax"] = format_utils::format_address(ctx.cax);
    regs["rcx"] = format_utils::format_address(ctx.ccx);
    regs["rdx"] = format_utils::format_address(ctx.cdx);
    regs["rbx"] = format_utils::format_address(ctx.cbx);
    regs["rsp"] = format_utils::format_address(ctx.csp);
    regs["rbp"] = format_utils::format_address(ctx.cbp);
    regs["rsi"] = format_utils::format_address(ctx.csi);
    regs["rdi"] = format_utils::format_address(ctx.cdi);
    regs["r8"]  = format_utils::format_address(ctx.r8);
    regs["r9"]  = format_utils::format_address(ctx.r9);
    regs["r10"] = format_utils::format_address(ctx.r10);
    regs["r11"] = format_utils::format_address(ctx.r11);
    regs["r12"] = format_utils::format_address(ctx.r12);
    regs["r13"] = format_utils::format_address(ctx.r13);
    regs["r14"] = format_utils::format_address(ctx.r14);
    regs["r15"] = format_utils::format_address(ctx.r15);
    regs["rip"] = format_utils::format_address(ctx.cip);
#else
    regs["eax"] = format_utils::format_address(ctx.cax);
    regs["ecx"] = format_utils::format_address(ctx.ccx);
    regs["edx"] = format_utils::format_address(ctx.cdx);
    regs["ebx"] = format_utils::format_address(ctx.cbx);
    regs["esp"] = format_utils::format_address(ctx.csp);
    regs["ebp"] = format_utils::format_address(ctx.cbp);
    regs["esi"] = format_utils::format_address(ctx.csi);
    regs["edi"] = format_utils::format_address(ctx.cdi);
    regs["eip"] = format_utils::format_address(ctx.cip);
#endif
    regs["eflags"] = format_utils::format_address(ctx.eflags);
    regs["cs"] = ctx.cs; regs["ds"] = ctx.ds; regs["es"] = ctx.es;
    regs["fs"] = ctx.fs; regs["gs"] = ctx.gs; regs["ss"] = ctx.ss;
    regs["dr0"] = format_utils::format_address(ctx.dr0);
    regs["dr1"] = format_utils::format_address(ctx.dr1);
    regs["dr2"] = format_utils::format_address(ctx.dr2);
    regs["dr3"] = format_utils::format_address(ctx.dr3);
    regs["dr6"] = format_utils::format_address(ctx.dr6);
    regs["dr7"] = format_utils::format_address(ctx.dr7);
    return regs;
}

nlohmann::json get_single(const std::string& name) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    if (!bridge.is_valid_expression(name)) throw std::runtime_error("Invalid register name: " + name);
    auto value = bridge.eval_expression(name);
    return {{"name", name}, {"value", format_utils::format_address(value)}};
}

nlohmann::json set_register(const std::string& name, const std::string& value) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    if (!bridge.exec_command("mov " + name + ", " + value))
        throw std::runtime_error("Failed to set register " + name);
    auto new_value = bridge.eval_expression(name);
    return {{"name", name}, {"value", format_utils::format_address(new_value)}};
}

nlohmann::json get_flags() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto dump_result = bridge.get_register_dump();
    if (!dump_result.has_value()) throw std::runtime_error(dump_result.error());
    const auto& flags = dump_result->flags;
    return {
        {"CF", flags.c}, {"PF", flags.p}, {"AF", flags.a}, {"ZF", flags.z},
        {"SF", flags.s}, {"TF", flags.t}, {"IF", flags.i}, {"DF", flags.d}, {"OF", flags.o},
        {"eflags", format_utils::format_address(dump_result->regcontext.eflags)}
    };
}

nlohmann::json get_avx512() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    REGDUMP_AVX512 avx512{};
    if (!DbgGetRegDumpEx(&avx512, sizeof(REGDUMP_AVX512)))
        throw std::runtime_error("Failed to get AVX-512 register dump");
    const auto& ctx = avx512.regcontext;
    nlohmann::json data;
#ifdef _WIN64
    data["rax"] = format_utils::format_address(ctx.cax);
    data["rcx"] = format_utils::format_address(ctx.ccx);
    data["rdx"] = format_utils::format_address(ctx.cdx);
    data["rbx"] = format_utils::format_address(ctx.cbx);
    data["rsp"] = format_utils::format_address(ctx.csp);
    data["rbp"] = format_utils::format_address(ctx.cbp);
    data["rsi"] = format_utils::format_address(ctx.csi);
    data["rdi"] = format_utils::format_address(ctx.cdi);
    data["rip"] = format_utils::format_address(ctx.cip);
#else
    data["eax"] = format_utils::format_address(ctx.cax);
    data["ecx"] = format_utils::format_address(ctx.ccx);
    data["edx"] = format_utils::format_address(ctx.cdx);
    data["ebx"] = format_utils::format_address(ctx.cbx);
    data["esp"] = format_utils::format_address(ctx.csp);
    data["ebp"] = format_utils::format_address(ctx.cbp);
    data["esi"] = format_utils::format_address(ctx.csi);
    data["edi"] = format_utils::format_address(ctx.cdi);
    data["eip"] = format_utils::format_address(ctx.cip);
#endif
    data["avx512_supported"] = true;
    data["eflags"] = format_utils::format_address(ctx.eflags);
    return data;
}

} // namespace handlers::registers
