import { Router } from 'express';
import { spawn } from 'node:child_process';
import { requireAuth } from '../middleware/rbac.js';

const router = Router();

// Native USB enumeration (spec §3 onboarding). Browsers cannot enumerate
// connected devices — WebUSB only surfaces devices the user explicitly granted
// in the picker, which is why a plugged-in phone/hub/HID device was invisible to
// the web page. This API process runs on the same host, so it can ask Windows
// directly: read-only WMI/PnP queries, no driver or device-store mutation, and
// the response carries only names/manufacturers/IDs. Presence in this list is
// NOT ownership — attestation (POST /v1/attestations) stays the legal gate.
//
// Cache 15s: the probe spawns PowerShell (~1-4s) and the UI polls on an
// interval; without the cache a few tabs would pin CPU through repeated spawns
// (same DoS-amplification lesson as the capabilities native probe).

type SysDevice = {
  id: string; // PnP instance id — stable per boot, composites get &mi_NN suffixes
  vid: string | null; // lowercase hex, e.g. '0x1a86' (null for non-USB-bus rows)
  pid: string | null;
  name: string;
  manufacturer: string | null;
  serial: string | null; // PnP id tail — real serial for most devices, a port path for hubs
  status: string | null; // Windows device status, e.g. 'OK'
  problem: number | null; // ConfigManager error code, 0/undefined = healthy
};

let cache: { rows: SysDevice[]; source: string; at: number; note?: string } | null = null;
const TTL_MS = 15_000;

const runPs = (script: string, timeoutMs = 9000): Promise<string> =>
  new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true });
    let out = '';
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (c: string) => (out += c));
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('probe timeout'));
    }, timeoutMs);
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0 && out.trim()) resolve(out);
      else reject(new Error(`probe exit ${code ?? 'unknown'}`));
    });
  });

// Primary: Win32_PnPEntity gives Name + Manufacturer + status. Limited to the
// USB\ bus — hubs, MTP phones, HID gear all enumerate there, which is exactly
// what the picker hides.
const CIM_SCRIPT =
  `[Console]::OutputEncoding=[Text.Encoding]::UTF8;` +
  `@(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'USB\\*' } |` +
  ` Sort-Object PNPDeviceID | Select-Object -First 60` +
  ` @{n='id';e={$_.PNPDeviceID}}, @{n='name';e={$_.Name}}, @{n='manufacturer';e={$_.Manufacturer}},` +
  ` @{n='status';e={$_.Status}}, @{n='problem';e={$_.ConfigManagerErrorCode}}) | ConvertTo-Json -Compress`;

// Fallback: Get-PnpDevice is faster but lacks Manufacturer/ConfigManagerErrorCode.
const PNP_SCRIPT =
  `[Console]::OutputEncoding=[Text.Encoding]::UTF8;` +
  `@(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\\*' } |` +
  ` Sort-Object InstanceId | Select-Object -First 60` +
  ` @{n='id';e={$_.InstanceId}}, @{n='name';e={$_.FriendlyName}}, @{n='status';e={$_.Status}}) | ConvertTo-Json -Compress`;

const parse = (raw: string): SysDevice[] => {
  let j: unknown;
  try {
    j = JSON.parse(raw);
  } catch {
    return [];
  }
  const arr = Array.isArray(j) ? j : j && typeof j === 'object' ? [j] : [];
  return (arr as Array<Record<string, unknown>>).flatMap((r) => {
    const id = String(r.id ?? '');
    if (!id) return [];
    const vid = /VID_([0-9A-Fa-f]{4})/.exec(id);
    const pid = /PID_([0-9A-Fa-f]{4})/.exec(id);
    const tail = id.split('\\').slice(2).join('\\');
    return [
      {
        id,
        vid: vid ? '0x' + vid[1].toLowerCase() : null,
        pid: pid ? '0x' + pid[1].toLowerCase() : null,
        name: String(r.name ?? '').trim() || '(unnamed device)',
        manufacturer: r.manufacturer ? String(r.manufacturer).trim() || null : null,
        serial: tail || null,
        status: r.status ? String(r.status) : null,
        problem: typeof r.problem === 'number' ? r.problem : null,
      },
    ];
  });
};

// GET /v1/system/usb-devices — devices Windows currently enumerates on the USB
// bus of this host. Auth-scoped (it reveals the operator's local hardware);
// read-only; cached. Non-Windows hosts get an honest note, not a fake list.
router.get('/usb-devices', requireAuth, async (_req, res) => {
  if (cache && Date.now() - cache.at <= TTL_MS) {
    return res.json({ ok: true, source: cache.source, cached: true, ttlMs: TTL_MS, devices: cache.rows, note: cache.note });
  }
  let rows: SysDevice[] = [];
  let source = 'none';
  let note: string | undefined;
  if (process.platform === 'win32') {
    try {
      rows = parse(await runPs(CIM_SCRIPT));
      source = 'win32-cim';
    } catch {
      try {
        rows = parse(await runPs(PNP_SCRIPT));
        source = 'win32-pnp';
      } catch {
        note = 'Windows device probe failed on this host — register the target manually below.';
      }
    }
  } else {
    note = 'Native USB detection is Windows-only in this build — register via manual registration.';
  }
  cache = { rows, source, at: Date.now(), note };
  res.json({ ok: true, source, cached: false, ttlMs: TTL_MS, devices: rows, note });
});

export default router;
