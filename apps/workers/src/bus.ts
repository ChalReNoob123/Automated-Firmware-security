// Event bus abstraction — spec calls for Kafka/NATS linking ingestion → analysis → correlation.
// Ships with an in-process bus; swap `publish` for a NATS/Kafka publisher in prod without
// touching stage code (same event envelope).
export type BusEvent = {
  type: 'stage.started' | 'stage.done' | 'stage.failed' | 'sbom.ready' | 'handoff.discovery' | 'pipeline.metrics';
  firmwareId: string;
  runId: string;
  stage?: string;
  at: string;
  data?: unknown;
};

type Handler = (e: BusEvent) => void;
const handlers = new Map<string, Handler[]>();

export function subscribe(type: BusEvent['type'] | '*', h: Handler): () => void {
  const list = handlers.get(type) ?? [];
  list.push(h);
  handlers.set(type, list);
  return () => handlers.set(type, (handlers.get(type) ?? []).filter((f) => f !== h));
}

export function publish(e: Omit<BusEvent, 'at'>): BusEvent {
  const full: BusEvent = { ...e, at: new Date().toISOString() };
  for (const key of [e.type, '*'] as const) {
    for (const h of handlers.get(key) ?? []) {
      try {
        h(full);
      } catch {
        // bus must never break a stage
      }
    }
  }
  return full;
}
