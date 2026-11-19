import { channel } from 'node:diagnostics_channel';
import readline from 'node:readline';

const initialState = () => ({ pending: false, delivered: 0, ledger: [] });
let state = initialState();
let events = [];
const entryEvents = channel('rsve.variant.entry');
const operationEvents = channel('rsve.variant.operation');
entryEvents.subscribe((event) => events.push(event));
operationEvents.subscribe((event) => events.push(event));

function snapshotState() {
  return { pending: state.pending, delivered: state.delivered, ledger: [...state.ledger] };
}

function emit(channelRef, event, context) {
  const index = events.length;
  channelRef.publish({ ...event, parent_index: context.parentIndex, trace_id: context.traceId, run_id: context.runId, timestamp_ns: Number(process.hrtime.bigint()) });
  context.parentIndex = index;
}

function accepted(request) {
  if (request.variant === 'decode') return decodeURIComponent(request.value ?? '') === 'RSVE-CANARY';
  if (request.variant === 'coerce') return String(request.role) === 'admin';
  if (request.variant === 'duplicate') return Object.fromEntries(request.fields ?? []).role === 'admin';
  if (request.variant === 'sequence' && request.action === 'prepare') return request.mode === 'review';
  if (request.variant === 'sequence' && request.action === 'commit') return state.pending;
  return false;
}

async function invoke(request, runId) {
  const context = { traceId: `variant-${runId}`, runId, parentIndex: null };
  const before = snapshotState();
  emit(entryEvents, { operation: 'entry.invocation', entry_point: request.action ?? 'submit', component: 'variant.entry', request, before, after: before, observation: { phase: 'start', variant: request.variant }, guard_result: null, input_representation: 'json.request', output_representation: 'variant.outcome' }, context);
  const ok = accepted(request);
  emit(operationEvents, { operation: 'guard.decision', entry_point: request.action ?? 'submit', component: 'variant.guard', request, before, after: before, observation: { accepted: ok, variant: request.variant }, guard_result: ok, input_representation: 'json.request', output_representation: 'guard.decision' }, context);
  if (!ok) return { events, state: snapshotState(), outcome: { accepted: false, variant: request.variant } };
  if (request.variant === 'sequence' && request.action === 'prepare') {
    state.pending = true;
    state.ledger.push('prepared');
  } else {
    state.pending = false;
    state.delivered += 1;
    state.ledger.push(request.variant);
    const after = snapshotState();
    emit(operationEvents, { operation: 'state.mutation', entry_point: request.action ?? 'submit', component: 'controlled.local.sink', request, before, after, observation: { sink: 'controlled.local.sink', canary: true, variant: request.variant }, guard_result: true, input_representation: 'json.request', output_representation: 'controlled.sink' }, context);
  }
  const after = snapshotState();
  emit(entryEvents, { operation: 'entry.outcome', entry_point: request.action ?? 'submit', component: 'variant.entry', request, before, after, observation: { phase: 'end', delivered: after.delivered, variant: request.variant }, guard_result: true, input_representation: 'variant.state', output_representation: 'json.outcome' }, context);
  return { events, state: after, outcome: { accepted: true, delivered: after.delivered, variant: request.variant } };
}

async function handle(request) {
  if (request.command === 'discover') return { entries: [{ name: 'submit', declared: true }, { name: 'prepare', declared: true }, { name: 'commit', declared: true }] };
  if (request.command === 'snapshot') return { snapshot: { state: snapshotState(), version: 1 } };
  if (request.command === 'restore') { state = JSON.parse(JSON.stringify(request.snapshot.state)); return { snapshot: { state: snapshotState(), version: 1 } }; }
  if (request.command === 'invoke') { events = []; return invoke(request.request ?? {}, request.run_id); }
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
