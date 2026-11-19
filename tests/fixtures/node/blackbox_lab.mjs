import { channel } from 'node:diagnostics_channel';
import { AsyncLocalStorage } from 'node:async_hooks';
import readline from 'node:readline';

const initialState = () => ({ delivered: 0, sinkValues: [] });
let state = initialState();
let events = [];
const contextStorage = new AsyncLocalStorage();
const entryEvents = channel('rsve.blackbox.entry');
const operationEvents = channel('rsve.blackbox.operation');
entryEvents.subscribe((event) => events.push(event));
operationEvents.subscribe((event) => events.push(event));

function snapshotState() {
  return { delivered: state.delivered, sinkValues: [...state.sinkValues] };
}

function emit(channelRef, event) {
  const context = contextStorage.getStore() ?? {};
  const parentIndex = context.parentIndex ?? null;
  const index = events.length;
  channelRef.publish({ ...event, parent_index: parentIndex, trace_id: context.traceId ?? 'unknown', run_id: context.runId ?? 'unknown', timestamp_ns: Number(process.hrtime.bigint()) });
  context.parentIndex = index;
}

async function submit(request, runId) {
  events = [];
  return contextStorage.run({ traceId: `blackbox-${runId}`, runId, parentIndex: null }, async () => {
    const before = snapshotState();
    emit(entryEvents, { operation: 'entry.invocation', entry_point: 'submit', component: 'controlled.entry', request, before, after: before, observation: { phase: 'start' }, guard_result: null, input_representation: 'json.request', output_representation: 'controlled.outcome' });
    const accepted = request.role === 'admin' || request.token === 'RSVE-CANARY';
    emit(operationEvents, { operation: 'guard.decision', entry_point: 'submit', component: 'controlled.guard', request, before, after: before, observation: { accepted }, guard_result: accepted, input_representation: 'json.request', output_representation: 'guard.decision' });
    if (!accepted) return { events, state: snapshotState(), outcome: { accepted: false } };
    state.delivered += 1;
    state.sinkValues.push(request.token ?? '');
    const after = snapshotState();
    emit(operationEvents, { operation: 'state.mutation', entry_point: 'submit', component: 'controlled.local.sink', request, before, after, observation: { sink: 'controlled.local.sink', canary: request.token === 'RSVE-CANARY' }, guard_result: true, input_representation: 'json.request', output_representation: 'controlled.sink' });
    emit(entryEvents, { operation: 'entry.outcome', entry_point: 'submit', component: 'controlled.entry', request, before, after, observation: { phase: 'end', delivered: after.delivered }, guard_result: true, input_representation: 'controlled.sink', output_representation: 'json.outcome' });
    return { events, state: after, outcome: { accepted: true, delivered: after.delivered } };
  });
}

async function handle(request) {
  if (request.command === 'discover') return { entries: [{ name: 'submit', declared: true, capabilities: ['stateful_command'] }] };
  if (request.command === 'snapshot') return { snapshot: { state: snapshotState(), version: 1 } };
  if (request.command === 'restore') { state = JSON.parse(JSON.stringify(request.snapshot.state)); return { snapshot: { state: snapshotState(), version: 1 } }; }
  if (request.command === 'invoke') return submit(request.request ?? {}, request.run_id);
  if (request.command === 'shutdown') return { stopped: true };
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
