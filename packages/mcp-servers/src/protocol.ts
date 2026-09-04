// Minimal MCP-compatible transport: JSON-RPC 2.0, newline-delimited, over stdio.
// Faithful to the MCP stdio shape (initialize → tools/list → tools/call) so real
// MCP clients can swap in; `McpClient` below is the in-repo test harness and the
// pattern external agents follow. Tool IMPLEMENTATIONS live in registry.ts and are
// shared in-process by the API Copilot (no spawn cost per chat turn).
import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';

export type ToolDef = { name: string; description: string; inputSchema: Record<string, unknown> };
export type ToolHandler = (args: Record<string, unknown>) => unknown | Promise<unknown>;
export type ServerSpec = { version: string; tools: Record<string, { def: ToolDef; handler: ToolHandler }> };

type RpcReq = { jsonrpc: '2.0'; id: string | number; method: string; params?: Record<string, unknown> };

export async function serve(serverName: string, spec: ServerSpec): Promise<void> {
  process.stdout.write(`[mcp] ${serverName} v${spec.version} ready\n`);
  let buf = '';
  const send = (id: string | number, result: unknown): void => {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
  };
  const sendErr = (id: string | number | null, code: number, message: string): void => {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\n');
  };

  for await (const chunk of process.stdin) {
    buf += chunk.toString();
    const lines = buf.split('\n');
    buf = lines.pop() ?? '';
    for (const line of lines) {
      if (!line.trim()) continue;
      let req: RpcReq;
      try {
        req = JSON.parse(line);
      } catch {
        continue; // ignore non-JSON (log banners from runners)
      }
      if (req.jsonrpc !== '2.0' || req.id === undefined) continue; // notifications unsupported
      try {
        if (req.method === 'initialize') {
          send(req.id, { protocolVersion: '2024-11-05', serverInfo: { name: serverName, version: spec.version } });
        } else if (req.method === 'tools/list') {
          send(req.id, { tools: Object.values(spec.tools).map((t) => t.def) });
        } else if (req.method === 'tools/call') {
          const name = (req.params?.name ?? '') as string;
          const tool = spec.tools[name];
          if (!tool) return sendErr(req.id, -32602, `unknown tool: ${name}`);
          const out = await tool.handler((req.params?.arguments ?? {}) as Record<string, unknown>);
          send(req.id, { content: [{ type: 'text', text: JSON.stringify(out) }] });
        } else {
          sendErr(req.id, -32601, `unknown method: ${req.method}`);
        }
      } catch (e) {
        sendErr(req.id, -32000, (e as Error).message);
      }
    }
  }
}

export class McpClient {
  private proc: ChildProcess;
  private seq = 0;
  private pending = new Map<string | number, (v: unknown) => void>();
  private buf = '';

  constructor(command: string, args: string[], cwd: string) {
    this.proc = spawn(command, args, { cwd, stdio: ['pipe', 'pipe', 'inherit'] });
    this.proc.stdout!.on('data', (d: Buffer) => {
      this.buf += d.toString();
      const lines = this.buf.split('\n');
      this.buf = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.trim() || !line.startsWith('{')) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.id !== undefined && this.pending.has(msg.id)) {
            this.pending.get(msg.id)!(msg);
            this.pending.delete(msg.id);
          }
        } catch {
          /* banner/non-JSON */
        }
      }
    });
  }

  request(method: string, params: Record<string, unknown> = {}): Promise<{ result?: unknown; error?: { message: string } }> {
    const id: string = `${++this.seq}-${randomUUID().slice(0, 4)}`;
    return new Promise((resolve) => {
      this.pending.set(id, resolve as (v: unknown) => void);
      this.proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          resolve({ error: { message: 'timeout' } });
        }
      }, 10000);
    });
  }

  async listTools() {
    return this.request('tools/list');
  }
  async callTool(name: string, args: Record<string, unknown> = {}) {
    return this.request('tools/call', { name, arguments: args });
  }
  close() {
    this.proc.kill();
  }
}
