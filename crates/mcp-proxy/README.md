# MCP Proxy Tool

An MCP (Model Context Protocol) proxy library that enables connections to HTTP-based, STDIO-based, and named pipe-based MCP servers.

## Features

- **HTTP(S) Transport**: Proxy requests to remote HTTP-based MCP servers (like Microsoft Learn)
- **STDIO Transport**: Launch and communicate with executable MCP servers over stdin/stdout
- **Named Pipe Transport**: Connect to MCP servers over named pipes (Unix sockets + Windows named pipes)
- **JSON-RPC 2.0 Compatible**: Full support for MCP protocol specifications

## Supported MCP Methods

When connecting to the Microsoft Learn Docs MCP server:

- `tools/list` - List available documentation search tools
- `tools/call` - Execute documentation searches with the `microsoft_docs_search` tool:
  - `question` (required) - Your question or topic about Microsoft/Azure products, services, platforms, developer tools, frameworks, or APIs
  - Returns up to 10 high-quality content chunks from Microsoft Learn and official sources
  - Each result includes article title, URL, and content excerpt (max 500 tokens each)
- `resources/list` - List available documentation resources (if supported)
- `resources/read` - Read specific documentation content (if supported)

## Usage of the CLI

### Command Line Options

```
Usage: mcp-proxy [-u URL | -c CMD [-a ARGS] | -p PIPE] [-t SECS] [-v] [-h]

Options:
  -u, --url         URL of the remote HTTP-based MCP server to proxy requests to
  -c, --command     Command to execute for STDIO-based MCP server
  -a, --args        Arguments for the STDIO-based MCP server command
  -p, --pipe        Path to named pipe for named pipe-based MCP server
  -t, --timeout     Timeout in seconds for HTTP requests (ignored for STDIO and named pipe)
  -v, --verbose     Enable verbose output to stderr
  -h, --help        Display usage information
```

### HTTP Transport (Remote MCP Server)

Connect to a remote HTTP-based MCP server:

```bash
# Connect to Microsoft Learn MCP server
mcp-proxy -u https://learn.microsoft.com/api/mcp

# With verbose logging and custom timeout
mcp-proxy -u https://learn.microsoft.com/api/mcp -v -t 60
```

### STDIO Transport (Local Executable)

Launch and connect to a local executable MCP server:

```bash
# Connect to a Python MCP server
mcp-proxy -c "python3 mcp_server.py"

# Connect to a Node.js MCP server with arguments
mcp-proxy -c "node server.js --config config.json"

# With verbose logging
mcp-proxy -c "python3 mcp_server.py" -v
```

### Named Pipe Transport (Local Socket-based)

Connect to an MCP server over named pipes (cross-platform):

**Unix/Linux/macOS:**
```bash
# Connect to a Unix domain socket
mcp-proxy -p /tmp/mcp_server.sock

# Connect to a FIFO named pipe
mcp-proxy -p /var/run/mcp/server.pipe -v
```

**Windows:**
```cmd
# Connect to a Windows named pipe (short form)
mcp-proxy.exe -p mcp_server

# Connect to a Windows named pipe (full path)
mcp-proxy.exe -p \\.\pipe\mcp_server -v
```

**PowerShell Examples:**
```powershell
# List tools from Windows named pipe MCP server
'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | mcp-proxy.exe -p mcp_server

# Call tool with verbose logging
'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"example","arguments":{"text":"Hello Windows!"}}}' | mcp-proxy.exe -p \\.\pipe\mcp_server -v
```

### Basic Usage

```bash
# Use default Microsoft Learn MCP server
echo '{"method": "tools/list", "params": {}}' | mcp-proxy --url "https://learn.microsoft.com/api/mcp"

# Use custom MCP server with verbose logging
echo '{"method": "tools/list", "params": {}}' | mcp-proxy --url "https://your-server.com/mcp" --verbose

# Set custom timeout
mcp-proxy --timeout 60 --verbose

# Search Microsoft Learn documentation
echo '{"method": "tools/call", "params": {"name": "microsoft_docs_search", "arguments": {"question": "Azure Functions"}}}' | mcp-proxy
```

### MCP Protocol Communication Examples

#### HTTP Transport with Microsoft Learn
```bash
# Initialize connection
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | mcp-proxy -u https://learn.microsoft.com/api/mcp

# List available tools
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | mcp-proxy -u https://learn.microsoft.com/api/mcp

# Call a tool
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"microsoft_docs_search","arguments":{"question":"How to use Azure Functions?"}}}' | mcp-proxy -u https://learn.microsoft.com/api/mcp
```

#### STDIO Transport with Custom Server
```bash
# List tools from Python MCP server
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | mcp-proxy -c "python3 echo_server.py"

# Call tool via STDIO transport
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"Hello STDIO!"}}}' | mcp-proxy -c "python3 echo_server.py"
```

#### Named Pipe Transport with Socket Server
```bash
# List tools from named pipe MCP server
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | mcp-proxy -p /tmp/mcp_server.sock

# Call tool via named pipe transport
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pipe_echo","arguments":{"message":"Hello Named Pipe!"}}}' | mcp-proxy -p /tmp/mcp_server.sock -v
```

## Windows Named Pipe Support

### Windows Named Pipe Paths

Windows named pipes use a different path format than Unix:

- **Short form**: `pipename` (automatically converted to `\\.\pipe\pipename`)
- **Full form**: `\\.\pipe\pipename` (explicit Windows named pipe path)

### Windows Command Examples

**Command Prompt:**
```cmd
REM List tools from Windows named pipe MCP server
echo {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}} | mcp-proxy.exe -p mcp_server

REM Call tool with full pipe path
echo {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"example","arguments":{"text":"Hello Windows!"}}} | mcp-proxy.exe -p \\.\pipe\mcp_server -v
```

**PowerShell:**
```powershell
# List tools from Windows named pipe MCP server
'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | .\mcp-proxy.exe -p mcp_server

# Call tool with verbose logging
'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"example","arguments":{"text":"Hello Windows!"}}}' | mcp-proxy.exe -p \\.\pipe\mcp_server -v
```
