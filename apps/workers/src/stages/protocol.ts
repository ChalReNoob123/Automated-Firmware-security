// Protocol state-machine fuzzing (spec: Autonomous Discovery Engine §6).
// Mutates TRANSITIONS, not payloads: out-of-order events, skipped states,
// repeated and invalid events. The oracle is DIFFERENTIAL — a strict reference
// machine (the spec) runs beside the target, and any accept/reject or state
// divergence is a logic finding (auth bypass, illegal transition, deadlock).
// Deterministic per seed, so every finding replays from its event trace.
export type ProtoState = string;
export type ProtoEvent = string;
export type Transition = { from: ProtoState; event: ProtoEvent; to: ProtoState };
export type Machine = { initial: ProtoState; transitions: Transition[]; privileged: ProtoState[] };

export type StepResult = { accepted: boolean; next: ProtoState };
export type Target = (state: ProtoState, event: ProtoEvent) => StepResult;

export function strictTarget(machine: Machine): Target {
  return (state, event) => {
    const t = machine.transitions.find((x) => x.from === state && x.event === event);
    return t ? { accepted: true, next: t.to } : { accepted: false, next: state };
  };
}

function mulberry(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export type ProtoFinding = {
  type: 'auth-bypass' | 'illegal-accept' | 'state-divergence' | 'deadlock';
  trace: ProtoEvent[];
  detail: string;
};

export type ProtoResult = {
  execs: number;
  pairsHit: string[];
  findings: ProtoFinding[];
};

// Sample machines: keep small but structurally honest (pairing/auth gates present).
export const BLE_GATT: Machine = {
  initial: 'idle',
  privileged: ['authenticated'],
  transitions: [
    { from: 'idle', event: 'advertise', to: 'advertising' },
    { from: 'advertising', event: 'connect', to: 'connected' },
    { from: 'connected', event: 'pair', to: 'pairing' },
    { from: 'pairing', event: 'pair_ok', to: 'authenticated' },
    { from: 'pairing', event: 'pair_fail', to: 'connected' },
    { from: 'authenticated', event: 'gatt_read', to: 'authenticated' },
    { from: 'authenticated', event: 'gatt_write', to: 'authenticated' },
    { from: 'connected', event: 'disconnect', to: 'idle' },
    { from: 'authenticated', event: 'disconnect', to: 'idle' },
  ],
};

export const MQTT: Machine = {
  initial: 'idle',
  privileged: ['subscribed'],
  transitions: [
    { from: 'idle', event: 'connect', to: 'connected' },
    { from: 'connected', event: 'auth', to: 'session' },
    { from: 'connected', event: 'auth_fail', to: 'idle' },
    { from: 'session', event: 'subscribe', to: 'subscribed' },
    { from: 'subscribed', event: 'publish', to: 'subscribed' },
    { from: 'subscribed', event: 'unsubscribe', to: 'session' },
    { from: 'session', event: 'disconnect', to: 'idle' },
  ],
};

export const MODBUS: Machine = {
  initial: 'idle',
  privileged: ['write_enabled'],
  transitions: [
    { from: 'idle', event: 'tcp_open', to: 'connected' },
    { from: 'connected', event: 'read_regs', to: 'connected' },
    { from: 'connected', event: 'unlock', to: 'write_enabled' },
    { from: 'write_enabled', event: 'write_reg', to: 'write_enabled' },
    { from: 'write_enabled', event: 'lock', to: 'connected' },
    { from: 'connected', event: 'tcp_close', to: 'idle' },
  ],
};

// Demo target with the classic flaw: GATT writes accepted pre-pairing.
export function buggyGattTarget(machine: Machine): Target {
  const strict = strictTarget(machine);
  return (state, event) => {
    if ((state === 'connected' || state === 'pairing') && event === 'gatt_write')
      return { accepted: true, next: 'authenticated' };
    return strict(state, event);
  };
}

export function fuzzProtocol(
  machine: Machine,
  target: Target,
  opts: { iterations?: number; seed?: number; maxTrace?: number } = {}
): ProtoResult {
  const iterations = Math.min(Math.max(opts.iterations ?? 2000, 1), 50_000);
  const maxTrace = Math.min(Math.max(opts.maxTrace ?? 12, 2), 64);
  const rng = mulberry(opts.seed ?? 0x90C0);
  const reference = strictTarget(machine);
  const events = [...new Set(machine.transitions.map((t) => t.event))];
  const hit = new Set<string>();
  const findings: ProtoFinding[] = [];
  const seen = new Set<string>();

  const record = (f: ProtoFinding) => {
    const key = `${f.type}:${f.trace.join(',')}`;
    if (!seen.has(key)) {
      seen.add(key);
      findings.push(f);
    }
  };

  for (let i = 0; i < iterations; i++) {
    const len = 2 + Math.floor(rng() * (maxTrace - 1));
    const trace: ProtoEvent[] = Array.from({ length: len }, () => events[Math.floor(rng() * events.length)]);
    let rs = machine.initial;
    let ts = machine.initial;
    for (const ev of trace) {
      const r = reference(rs, ev);
      const t = target(ts, ev);
      hit.add(`${rs}:${ev}`);
      rs = r.next;
      ts = t.next;
      if (t.accepted && !r.accepted) {
        const priv = machine.privileged.includes(ts);
        record({
          type: priv ? 'auth-bypass' : 'illegal-accept',
          trace: [...trace],
          detail: priv
            ? `event '${ev}' accepted into privileged '${ts}' without the auth path`
            : `event '${ev}' accepted where the reference rejects (state '${rs}')`,
        });
        break;
      }
      if (r.accepted && t.accepted && rs !== ts) {
        record({ type: 'state-divergence', trace: [...trace], detail: `same accepts, different states (ref '${rs}' vs target '${ts}')` });
        break;
      }
    }
    if (machine.transitions.every((t) => t.from !== ts) && ts !== machine.initial && !machine.privileged.includes(ts)) {
      // terminal non-initial state with no outgoing edge and no finding yet this trace
      record({ type: 'deadlock', trace: [...trace], detail: `stuck in '${ts}' with no outgoing transition` });
    }
  }
  return { execs: iterations, pairsHit: [...hit].sort(), findings };
}
