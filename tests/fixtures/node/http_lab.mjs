import http from 'node:http';
import readline from 'node:readline';

const initialState = () => ({ sessionMode: '', delivered: 0, ledger: [] });
let state = initialState();
let events = [];
let server;

function snapshotState() {
  return { sessionMode: state.sessionMode, delivered: state.delivered, ledger: [...state.ledger] };
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let data = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => { data += chunk; });
    request.on('end', () => resolve(data ? JSON.parse(data) : {}));
    request.on('error', reject);
  });
}

server = http.createServer(async (request, response) => {
  try {
    const body = await readBody(request);
    if (request.method !== 'POST') {
      response.writeHead(405); response.end(); return;
    }
    if (request.url === '/session') {
      const accepted = body.mode === 'admin' || body.mode === 'review';
      if (accepted) state.sessionMode = String(body.mode);
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ accepted, mode: state.sessionMode }));
      return;
    }
    if (request.url === '/v1/import') {
      const accepted = state.sessionMode === 'review' && body.proof === 'RSVE-CANARY';
      if (accepted) {
        state.delivered += 1;
        state.ledger.push('controlled.local.sink');
      }
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ accepted, delivered: state.delivered }));
      return;
    }
    response.writeHead(404); response.end();
  } catch (error) {
    response.writeHead(400); response.end(JSON.stringify({ error: String(error) }));
  }
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;

function emit(operation, entry, request, before, after, observation, guardResult, context) {
  const index = events.length;
  events.push({ operation, entry_point: entry, component: operation === 'state.mutation' ? 'controlled.local.sink' : 'http.app', request, before, after, observation, guard_result: guardResult, parent_index: index ? index - 1 : null, trace_id: context.traceId, run_id: context.runId, timestamp_ns: Number(process.hrtime.bigint()) });
}

function call(path, body) {
  return new Promise((resolve, reject) => {
    const request = http.request({ hostname: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json' } }, (response) => {
      let data = '';
      response.on('data', (chunk) => { data += chunk; });
      response.on('end', () => resolve(JSON.parse(data || '{}')));
    });
    request.on('error', reject);
    request.end(JSON.stringify(body));
  });
}

async function invoke(entry, request, runId) {
  events = [];
  const context = { traceId: `http-${runId}`, runId };
  const before = snapshotState();
  emit('entry.invocation', entry, request, before, before, { phase: 'start', transport: 'loopback-http' }, null, context);
  const result = await call(entry === 'http.session' ? '/session' : '/v1/import', request);
  const guardResult = Boolean(result.accepted);
  const after = snapshotState();
  emit('guard.decision', entry, request, before, after, { accepted: guardResult, transport: 'loopback-http' }, guardResult, context);
  if (entry === 'http.import' && guardResult) emit('state.mutation', entry, request, before, after, { sink: 'controlled.local.sink', canary: true, transport: 'loopback-http' }, true, context);
  emit('entry.outcome', entry, request, before, after, { phase: 'end', delivered: after.delivered, transport: 'loopback-http' }, guardResult, context);
  return { events, state: after, outcome: { accepted: guardResult, delivered: after.delivered } };
}

async function handle(request) {
  if (request.command === 'discover') return { entries: [{ name: 'http.session', declared: true, capabilities: ['http', 'stateful_command'] }, { name: 'http.import', declared: true, capabilities: ['http', 'stateful_command'] }] };
  if (request.command === 'snapshot') return { snapshot: { state: snapshotState(), version: 1 } };
  if (request.command === 'restore') { state = JSON.parse(JSON.stringify(request.snapshot.state)); return { snapshot: { state: snapshotState(), version: 1 } }; }
  if (request.command === 'invoke') return invoke(request.entry, request.request ?? {}, request.run_id);
  if (request.command === 'shutdown') { await new Promise((resolve) => server.close(resolve)); return { stopped: true }; }
  throw new Error(`unsupported command: ${request.command}`);
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of input) {
  if (!line.trim()) continue;
  const request = JSON.parse(line);
  try {
    process.stdout.write(`${JSON.stringify({ request_id: request.request_id, ...(await handle(request))})}\n`);
    if (request.command === 'shutdown') break;
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ request_id: request.request_id, error: String(error) })}\n`);
  }
}
