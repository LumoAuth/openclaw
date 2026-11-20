// A minimal OpenAI-compatible chat-completions server for end-to-end runs.
// The first request of a turn answers with one tool call; when the last
// message is a tool result, it answers with text that quotes the result, so
// the agent's reply shows what the Guard did.
//
// The tool calls come from the JSON file $TOOL_CALL_FILE, read on every
// request, else from $TOOL_CALL: one call {"name", "arguments"} or a list of
// calls, made one after the other in the same turn. Listens on 127.0.0.1:$PORT.
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';

const port = Number(process.env.PORT ?? 47321);
const log = process.env.LOG ?? '/tmp/e2e-mock-llm.log';

function scriptedCalls() {
  const file = process.env.TOOL_CALL_FILE;
  const raw = file && existsSync(file) ? readFileSync(file, 'utf8') : (process.env.TOOL_CALL ?? '{"name":"read","arguments":{"path":"notes.md"}}');
  const parsed = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed : [parsed];
}

function text(content) {
  return typeof content === 'string' ? content : JSON.stringify(content);
}

createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString('utf8');
  let body = {};
  try {
    body = JSON.parse(raw);
  } catch {}
  const offered = Array.isArray(body.tools) ? body.tools.map((t) => t?.function?.name ?? t?.name).filter(Boolean) : [];
  appendFileSync(log, `${new Date().toISOString()} ${req.method} ${req.url} ${raw.length} bytes; tools: ${offered.join(',')}\n`);
  if (req.method === 'GET' && req.url.startsWith('/v1/models')) {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ object: 'list', data: [{ id: 'mock-1', object: 'model' }] }));
    return;
  }
  const messages = Array.isArray(body.messages) ? body.messages : [];
  // Tool results since the user's last message: how far this turn has got.
  let start = messages.length;
  while (start > 0 && messages[start - 1].role !== 'user') start--;
  const results = messages.slice(start).filter((m) => m.role === 'tool');
  const calls = scriptedCalls();
  let message;
  let finish;
  if (results.length >= calls.length) {
    message = { role: 'assistant', content: results.map((r, i) => `TOOL RESULT[${i + 1}] >>> ${text(r.content)}`).join('\n') };
    finish = 'stop';
  } else {
    const call = calls[results.length];
    message = {
      role: 'assistant',
      content: null,
      tool_calls: [{ id: `call_${Date.now()}`, type: 'function', function: { name: call.name, arguments: JSON.stringify(call.arguments ?? {}) } }],
    };
    finish = 'tool_calls';
  }
  const usage = { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 };
  if (body.stream) {
    res.setHeader('Content-Type', 'text/event-stream');
    const base = { id: 'chatcmpl-e2e', object: 'chat.completion.chunk', created: Math.floor(Date.now() / 1000), model: body.model ?? 'mock-1' };
    const delta = message.tool_calls
      ? { role: 'assistant', tool_calls: message.tool_calls.map((t, index) => ({ index, ...t })) }
      : { role: 'assistant', content: message.content };
    res.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`);
    res.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: {}, finish_reason: finish }], usage })}\n\n`);
    res.end('data: [DONE]\n\n');
    return;
  }
  res.setHeader('Content-Type', 'application/json');
  res.end(
    JSON.stringify({
      id: 'chatcmpl-e2e',
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: body.model ?? 'mock-1',
      choices: [{ index: 0, message, finish_reason: finish }],
      usage,
    }),
  );
}).listen(port, '127.0.0.1', () => console.log(`mock model on http://127.0.0.1:${port}/v1`));
