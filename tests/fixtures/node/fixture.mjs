import { channel } from 'node:diagnostics_channel';
import { AsyncLocalStorage } from 'node:async_hooks';
import readline from 'node:readline';

const initialState = () => ({ count: 0, history: [] });
let state = initialState();
let invocationCount = 0;
let events = [];
const contextStorage = new AsyncLocalStorage();
const entryEvents = channel('rsve.fixture.entry');
const operationEvents = channel('rsve.fixture.operation');

entryEvents.subscribe((event) => events.push(event));
operationEvents.subscribe((event) => events.push(event));

function snapshotState() {
  return { count: state.count, history: [...state.history] };
}

function emit(channelRef, event) {
  const context = contextStorage.getStore() ?? {};
  const parentIndex = context.parentIndex ?? null;
  const index = events.length;
  channelRef.publish({
    ...event,
    trace_id: context.traceId ?? 'unknown',
    run_id: context.runId ?? 'unknown',
    parent_index: parentIndex,
    timestamp_ns: Number(process.hrtime.bigint()),
  });
  context.parentIndex = index;
}

function guard(entry, request) {
  if (entry === 'increment' || entry === 'async_increment') {
    return Number.isInteger(request.amount) && request.amount > 0 && request.amount <= 10;
  }
  return entry === 'read' || entry === 'dynamic_debug';
}

function mutate(entry, request) {
  const before = snapshotState();
  if (entry === 'increment' || entry === 'async_increment') {
    state.count += request.amount;
    state.history.push({ entry, amount: request.amount });
  }
  const after = snapshotState();
  emit(operationEvents, {
    operation: 'state.mutation',
    entry_point: entry,
    component: 'fixture.state',
    request,
    before,
    after,
    observation: { count: after.count },
    guard_result: true,
    input_representation: 'json.request',
    output_representation: 'fixture.state',
  });
}

async function invoke(entry, request, runId) {
  events = [];
  invocationCount += 1;
  const traceId = `fixture-${runId}`;
  return contextStorage.run({ traceId, runId, parentIndex: null }, async () => {
    const before = snapshotState();
    emit(entryEvents, {
      operation: 'entry.invocation',
      entry_point: entry,
      component: 'fixture.entry',
      request,
      before,
      after: before,
      observation: { phase: 'start' },
      guard_result: null,
      input_representation: 'json.request',
      output_representation: 'fixture.state',
    });
    const accepted = guard(entry, request);
    emit(operationEvents, {
      operation: 'guard.decision',
      entry_point: entry,
      component: 'fixture.guard',
      request,
      before,
      after: before,
      observation: { accepted },
      guard_result: accepted,
      input_representation: 'json.request',
      output_representation: 'guard.decision',
    });
    if (!accepted) {
      return { events, state: snapshotState(), outcome: { accepted: false, reason: 'guard_rejected' } };
    }
    if (entry === 'async_increment') {
      emit(operationEvents, {
        operation: 'async.schedule',
        entry_point: entry,
        component: 'fixture.scheduler',
        request,
        before,
        after: before,
        observation: { scheduler: 'setTimeout', delay_ms: 0 },
        guard_result: true,
        input_representation: 'json.request',
        output_representation: 'async.continuation',
      });
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    mutate(entry, request);
    const after = snapshotState();
    emit(entryEvents, {
      operation: 'entry.outcome',
      entry_point: entry,
      component: 'fixture.entry',
      request,
      before,
      after,
      observation: { phase: 'end', count: after.count },
      guard_result: true,
      input_representation: 'fixture.state',
      output_representation: 'json.outcome',
    });
    return {
      events,
      state: after,
      outcome: { accepted: true, count: after.count, ...(request.flaky ? { sample: invocationCount % 2 } : {}) },
    };
  });
}

async function handle(request) {
  if (request.command === 'discover') {
    return {
      entries: [
        { name: 'increment', declared: true, capabilities: ['stateful_command'] },
        { name: 'async_increment', declared: true, capabilities: ['stateful_command', 'async_function'] },
        { name: 'read', declared: true, capabilities: ['stateful_command'] },
        { name: 'dynamic_debug', declared: false, capabilities: ['module_function'] },
      ],
    };
  }
  if (request.command === 'snapshot') {
    return { snapshot: { state: snapshotState(), version: 1 } };
  }
  if (request.command === 'restore') {
    state = JSON.parse(JSON.stringify(request.snapshot.state));
    return { snapshot: { state: snapshotState(), version: 1 } };
  }
  if (request.command === 'invoke') {
    return await invoke(request.entry, request.request ?? {}, request.run_id);
  }
  if (request.command === 'shutdown') {
    return { stopped: true };
  }
  throw new Error(`unsupported command: ${request.command}`);
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of input) {
  if (!line.trim()) continue;
  const request = JSON.parse(line);
  try {
    const response = await handle(request);
    process.stdout.write(`${JSON.stringify({ request_id: request.request_id, ...response })}\n`);
    if (request.command === 'shutdown') break;
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ request_id: request.request_id, error: String(error) })}\n`);
  }
}
