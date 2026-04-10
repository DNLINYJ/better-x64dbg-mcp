# better-x64dbg-mcp

改进版 x64dbg MCP (Model Context Protocol) 插件，基于 [@bromoket](https://github.com/bromoket) 的 [x64dbg_mcp](https://github.com/bromoket/x64dbg_mcp) 重构。

原项目采用两层架构——TypeScript MCP 服务器通过 HTTP 与 C++ x64dbg 插件通信。本项目**将两层合并为单个 C++ DLL**，直接在 x64dbg 内实现 [MCP Streamable HTTP 传输协议](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http)。

## 核心改进

| | 原项目 | 本项目 |
|---|---|---|
| **层数** | 2 层 (TypeScript + C++) | 1 层 (纯 C++) |
| **部署依赖** | Node.js + npm + DLL | 仅 DLL |
| **传输协议** | stdio (JSON-RPC over stdin/stdout) | Streamable HTTP |
| **事件推送** | 不支持 | SSE (断点、异常、暂停、单步、进程、DLL 事件) |
| **端点数量** | 148 条 REST 路由 | 1 个 (`/mcp`) |
| **客户端配置** | `npx -y x64dbg-mcp-server` | `http://127.0.0.1:27042/mcp` |

## 功能

- **MCP Streamable HTTP** (2025-03-26 规范) — 单一 `/mcp` 端点，`POST`/`GET`/`DELETE`
- **21 个聚合工具** 覆盖调试控制、寄存器、内存、断点、反汇编、符号、栈、线程、模块、搜索、追踪、转储、异常、控制流、补丁、标注、内存映射、进程信息、句柄、分析、原始命令
- **实时事件推送** 通过 SSE — 9 个 x64dbg 回调 (断点命中、暂停、异常、单步完成、调试停止、进程创建/退出、DLL 加载/卸载)
- **零部署成本** — 将 `.dp64` 放入 x64dbg 的 `plugins/` 目录即可

## 快速开始

1. 在 Visual Studio 中构建 (x64 Debug/Release)，或命令行：
   ```
   msbuild better-x64dbg-mcp.vcxproj /p:Configuration=Release /p:Platform=x64
   ```
2. 将输出的 `.dp64` 复制到 x64dbg 的 `plugins/` 目录
3. 启动 x64dbg — MCP 服务器自动在 `127.0.0.1:27042` 上运行
4. 连接 MCP 客户端：
   ```bash
   # Claude Code
   claude mcp add --transport http x64dbg http://127.0.0.1:27042/mcp

   # 或在 .mcp.json 中配置
   {
     "mcpServers": {
       "x64dbg": { "type": "http", "url": "http://127.0.0.1:27042/mcp" }
     }
   }
   ```

## 构建要求

- Visual Studio 2022+，MSVC v145 工具集
- Windows SDK 10.0
- C++23 (x64) / C++20 (Win32)

所有依赖已内置：x64dbg Plugin SDK 和 nlohmann/json。

## 致谢

本项目基于 [@bromoket](https://github.com/bromoket) 的 [x64dbg_mcp](https://github.com/bromoket/x64dbg_mcp) 改造。Handler 逻辑、Bridge 执行器和 UI 对话框适配自原项目的 C++ 插件。MCP 协议层、事件系统和 Streamable HTTP 传输为全新实现。

## 许可证

MIT
