'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card, Badge, Empty, glassGlow } from '../components/ui';
import { apiFetch, getAccess } from '../lib/auth';
import { fmtUtcTime } from '../lib/time';

// Android-Studio-style device lab: virtual profiles, animated boot, interactive
// home screen, streaming logcat, working ADB shell, local snapshots, and a
// one-click bridge that boots a backend twin for the profile's architecture.

type Profile = { id: string; name: string; arch: 'arm' | 'aarch64' | 'mipsel'; soc: string; android: string; ram: string };
const PROFILES: Profile[] = [
  { id: 'pixel', name: 'Pixel 8 Pro', arch: 'aarch64', soc: 'Tensor G3', android: '14 (API 34)', ram: '12 GB' },
  { id: 'gateway', name: 'IoT Gateway GW-200', arch: 'arm', soc: 'Cortex-A53', android: '13 Go (API 33)', ram: '2 GB' },
  { id: 'cam', name: 'Smart Cam C1', arch: 'mipsel', soc: 'Ingenic T31', android: '11 (API 30)', ram: '512 MB' },
];

const BOOT_LINES = [
  'bootloader: verifying vbmeta… OK',
  'bootloader: anti-rollback counter 7… OK',
  'kernel: Linux version 5.15-forge',
  'init: starting first stage…',
  'zygote64: preloading 4,102 classes…',
  'SystemServer: package manager ready',
  'SurfaceFlinger: composer ready',
  'launcher: home',
];

const LOG_TAGS = ['ActivityManager', 'kernel', 'wpa_supplicant', 'adbd', 'SurfaceFlinger', 'libc', 'netd', 'storaged'];
const LOG_MSGS = [
  'I: Start proc com.android.launcher',
  'D: Alloc concurrent copying GC freed 12KB',
  'I: wlp0: connected to LabNet (signal -52 dBm)',
  'W: Battery saver: CPU throttled to 1.2GHz',
  'D: adbd: auth confirmed (rsa key)',
  'I: Displayed com.android.settings/.Settings in +312ms',
  'E: libc: denied { open } scontext=u:r:untrusted_app',
  'D: netd: route updated via rmnet_data0',
  'I: storaged: lifetime estimate 9.2 years',
  'W: SurfaceFlinger: missed vsync (34ms)',
];
const LV_COLOR: Record<string, string> = { I: '#6ee7b7', D: '#94a3b8', W: '#fcd34d', E: '#fca5a5' };

const djb2 = (s: string) => {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(16).padStart(8, '0');
};

type Snap = { id: string; at: string; hash: string; state: string };

export default function AndroidLab() {
  const [profile, setProfile] = useState<Profile>(PROFILES[0]);
  const [power, setPower] = useState<'off' | 'booting' | 'on'>('off');
  const [bootIdx, setBootIdx] = useState(0);
  const [app, setApp] = useState<string | null>(null);
  const [tab, setTab] = useState<'screen' | 'log' | 'adb' | 'snaps'>('screen');
  const [logs, setLogs] = useState<string[]>([]);
  const [logRun, setLogRun] = useState(true);
  const [tagFilter, setTagFilter] = useState('');
  const [shellHist, setShellHist] = useState<string[]>(['Android Debug Bridge — type `help`.']);
  const [shellIn, setShellIn] = useState('');
  const [packages, setPackages] = useState(['com.android.settings', 'com.android.browser', 'com.android.files', 'com.vendor.ota']);
  const [snaps, setSnaps] = useState<Snap[]>([]);
  const [twin, setTwin] = useState('');
  const [err, setErr] = useState('');
  const logRef = useRef<HTMLDivElement>(null);
  const shellRef = useRef<HTMLDivElement>(null);
  // Clock starts null so server and client render the same placeholder —
  // a live Date in render would diverge across the hydration boundary.
  const [now, setNow] = useState<Date | null>(null);

  useEffect(() => {
    setNow(new Date());
    const t = setInterval(() => setNow(new Date()), 30000);
    return () => clearInterval(t);
  }, []);

  // boot sequence
  useEffect(() => {
    if (power !== 'booting') return;
    if (bootIdx >= BOOT_LINES.length) {
      const t = setTimeout(() => setPower('on'), 500);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setBootIdx((i) => i + 1), 620);
    return () => clearTimeout(t);
  }, [power, bootIdx]);

  // logcat stream
  useEffect(() => {
    if (power !== 'on' || !logRun) return;
    const t = setInterval(() => {
      setLogs((l) => {
        const line = `${new Date().toTimeString().slice(0, 8)} ${LOG_TAGS[Math.floor(Math.random() * LOG_TAGS.length)]}: ${LOG_MSGS[Math.floor(Math.random() * LOG_MSGS.length)]}`;
        return [...l.slice(-299), line];
      });
    }, 750);
    return () => clearInterval(t);
  }, [power, logRun]);

  useEffect(() => {
    logRef.current?.scrollTo({ top: 99999 });
  }, [logs.length]);
  useEffect(() => {
    shellRef.current?.scrollTo({ top: 99999 });
  }, [shellHist.length]);

  const powerOn = () => {
    setBootIdx(0);
    setApp(null);
    setPower('booting');
  };

  const adb = (raw: string) => {
    const [cmd, ...rest] = raw.trim().split(/\s+/);
    const arg = rest.join(' ');
    const out: string[] = [`shell@${profile.id} $ ${raw}`];
    switch (cmd) {
      case 'help':
        out.push('getprop | pm list packages | dumpsys battery | ls /system | cat /proc/cpuinfo | install <pkg> | uninstall <pkg> | reboot | whoami');
        break;
      case 'whoami':
      case 'id':
        out.push('uid=2000(shell) gid=2000(shell) groups=2000(shell),adb');
        break;
      case 'getprop':
        out.push(
          `[ro.product.model]: [${profile.name}]`,
          `[ro.build.version.release]: [${profile.android}]`,
          '[ro.secure]: [1]',
          '[ro.debuggable]: [0]',
          `[ro.hardware]: [${profile.soc}]`
        );
        break;
      case 'pm':
        if (rest[0] === 'list' && rest[1] === 'packages') packages.forEach((p) => out.push(`package:${p}`));
        else out.push('usage: pm list packages');
        break;
      case 'dumpsys':
        out.push(arg === 'battery' ? 'level: 87\nstatus: Discharging\nhealth: Good' : `dumpsys ${arg || '?'}: 3 services, 0 errors`);
        break;
      case 'ls':
        out.push(arg === '/system' || !arg ? 'bin  etc  fonts  lib  priv-app  usr' : `ls: ${arg}: No such file or directory`);
        break;
      case 'cat':
        out.push(arg === '/proc/cpuinfo' ? `Processor: ${profile.soc}\nFeatures: neon tls` : `cat: ${arg || ''}: No such file`);
        break;
      case 'install':
        if (!arg) out.push('usage: install <package>');
        else if (packages.includes(arg)) out.push(`Failure [INSTALL_FAILED_ALREADY_EXISTS]`);
        else {
          setPackages((p) => [...p, arg]);
          out.push(`Success — ${arg} staged for next boot`);
        }
        break;
      case 'uninstall':
        if (!packages.includes(arg)) out.push(`Failure [DELETE_FAILED_INTERNAL_ERROR]`);
        else {
          setPackages((p) => p.filter((x) => x !== arg));
          out.push('Success');
        }
        break;
      case 'reboot':
        out.push('rebooting…');
        setPower('off');
        setTimeout(powerOn, 900);
        break;
      case '':
        break;
      default:
        out.push(`${cmd}: command not found (try help)`);
    }
    setShellHist((h) => [...h.slice(-199), ...out]);
  };

  const snapshot = () => {
    const state = JSON.stringify({ profile: profile.id, app, packages });
    const s: Snap = { id: `lab_${Date.now().toString(36)}`, at: new Date().toISOString(), hash: djb2(state), state };
    setSnaps((l) => [s, ...l]);
  };
  const restore = (s: Snap) => {
    const st = JSON.parse(s.state) as { profile: string; app: string | null; packages: string[] };
    const p = PROFILES.find((x) => x.id === st.profile);
    if (p) setProfile(p);
    setApp(st.app);
    setPackages(st.packages);
    if (power === 'off') powerOn();
  };

  const linkTwin = async () => {
    setErr('');
    setTwin('');
    try {
      const tok = await getAccess();
      if (!tok) throw new Error('sign in at /login first');
      const att = localStorage.getItem('sf_att') ?? '';
      if (!att) throw new Error('attest a device at /devices first');
      // Honest memory: the bridge used to send a flat 512MB for a 12GB profile.
      const gb = parseFloat(profile.ram) || 0.5;
      const memoryMb = Math.min(8192, Math.max(64, Math.round(profile.ram.includes('GB') ? gb * 1024 : gb)));
      const r = await apiFetch('/v1/emulator/sessions', {
        method: 'POST',
        headers: { 'x-attestation-id': att },
        body: JSON.stringify({ arch: profile.arch, memoryMb }),
      });
      const j = await r.json();
      if (!r.ok) throw new Error((j as { error?: string }).error ?? `HTTP ${r.status}`);
      const id = (j as { id: string }).id;
      // Round 33: without this the twin was orphaned — /emulator reloads from
      // sf_last_session, which only the attack runner used to write, so the old
      // "mirrored in /emulator" message pointed at a session the page never saw.
      localStorage.setItem('sf_last_session', id);
      setTwin(`twin ${id} · ${profile.arch} · ${memoryMb}MB`);
    } catch (e) {
      setErr('Twin bridge: ' + (e as Error).message);
    }
  };

  const time = now ? `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}` : '--:--';
  const shownLogs = tagFilter ? logs.filter((l) => l.toLowerCase().includes(tagFilter.toLowerCase())) : logs;

  return (
    <Card>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 16 }}>
        {PROFILES.map((p) => (
          <button key={p.id} className={p.id === profile.id ? 'sf-btn sf-btn-accent' : 'sf-btn'} onClick={() => { setProfile(p); setPower('off'); setApp(null); }}>
            {p.name}
          </button>
        ))}
        <span style={{ color: '#64748b', fontSize: 12, marginLeft: 'auto' }}>{profile.soc} · {profile.android} · {profile.ram}</span>
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        {(['screen', 'log', 'adb', 'snaps'] as const).map((t) => (
          <button key={t} className={tab === t ? 'sf-btn sf-btn-accent' : 'sf-btn'} onClick={() => setTab(t)}>
            {t === 'screen' ? 'Screen' : t === 'log' ? 'Logcat' : t === 'adb' ? 'ADB Shell' : `Snapshots (${snaps.length})`}
          </button>
        ))}
      </div>

      {tab === 'screen' && (
        <div style={{ display: 'flex', gap: 26, flexWrap: 'wrap', alignItems: 'flex-start' }}>
          {/* handset frame */}
          <div style={{ width: 300, height: 610, borderRadius: 38, border: '1px solid rgba(255,255,255,0.18)', background: '#000', padding: 12, boxShadow: '0 0 60px rgba(34,211,238,0.12)', position: 'relative' }}>
            <div style={{ position: 'absolute', top: 22, left: '50%', marginLeft: -50, width: 100, height: 22, borderRadius: 12, background: '#000', border: '1px solid rgba(255,255,255,0.1)', zIndex: 3 }} />
            <div style={{ width: '100%', height: '100%', borderRadius: 28, overflow: 'hidden', background: 'linear-gradient(160deg, #0b1226, #1b1040)', position: 'relative', display: 'flex', flexDirection: 'column' }}>
              {power === 'off' && (
                <button onClick={powerOn} style={{ margin: 'auto', background: 'none', border: '1px solid rgba(34,211,238,0.5)', color: '#22d3ee', borderRadius: '50%', width: 74, height: 74, fontSize: 11, cursor: 'pointer' }}>
                  POWER
                </button>
              )}
              {power === 'booting' && (
                <div style={{ margin: 'auto 24px', fontSize: 12, fontFamily: 'monospace' }}>
                  <div style={{ color: '#22d3ee', marginBottom: 10, letterSpacing: 3 }}>SENTINELFORGE</div>
                  {BOOT_LINES.slice(0, bootIdx).map((l) => (
                    <div key={l} style={{ color: '#64748b', marginBottom: 3 }}>{l}</div>
                  ))}
                  <div style={{ height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.1)', marginTop: 12 }}>
                    <div style={{ height: '100%', width: `${(bootIdx / BOOT_LINES.length) * 100}%`, borderRadius: 2, background: 'linear-gradient(90deg,#22d3ee,#a855f7)', transition: 'width .5s' }} />
                  </div>
                </div>
              )}
              {power === 'on' && (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 18px 4px', fontSize: 11, color: '#cbd5e1' }}>
                    <span>{time}</span>
                    <span>5G ▂▄▆ 87%</span>
                  </div>
                  <AnimatePresence mode="wait">
                    {app === null ? (
                      <motion.div key="home" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, padding: 20 }}>
                        {[['Settings', '⚙', '#38bdf8'], ['Browser', '◉', '#a855f7'], ['Files', '▤', '#f59e0b'], ['Terminal', '❯', '#34d399']].map(([label, glyph, color]) => (
                          <button key={label} onClick={() => setApp(label)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#e2e8f0', fontSize: 10 }}>
                            <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 46, height: 46, margin: '0 auto 5px', borderRadius: 13, background: `${color}22`, border: `1px solid ${color}55`, color, fontSize: 20 }}>{glyph}</span>
                            {label}
                          </button>
                        ))}
                      </motion.div>
                    ) : (
                      <motion.div key={app} initial={{ opacity: 0, x: 30 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} style={{ padding: 16, fontSize: 12, color: '#cbd5e1', flex: 1 }}>
                        <button onClick={() => setApp(null)} style={{ background: 'none', border: 'none', color: '#22d3ee', cursor: 'pointer', fontSize: 13, marginBottom: 10 }}>‹ Home</button>
                        {app === 'Settings' && (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                            {[['Model', profile.name], ['Android', profile.android], ['SoC', profile.soc], ['Secure boot', 'enforced ✓'], ['Play Protect', 'certified']].map(([k, v]) => (
                              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.07)', paddingBottom: 6 }}>
                                <span style={{ color: '#64748b' }}>{k}</span>
                                <span>{v}</span>
                              </div>
                            ))}
                          </div>
                        )}
                        {app === 'Browser' && <div style={{ background: '#7f1d1d', borderRadius: 10, padding: 12 }}>⚠ sequel.lab says: this update server uses plain HTTP. Flag it in /attacks.</div>}
                        {app === 'Files' && <div style={{ fontFamily: 'monospace' }}>/system — bin etc lib<br />/vendor — ota_{profile.arch}.zip (2.1 MB)<br />/sdcard — 0 files</div>}
                        {app === 'Terminal' && <div style={{ fontFamily: 'monospace' }}>shell@{profile.id} $ <span style={{ color: '#22d3ee' }}>full shell lives in the ADB tab →</span></div>}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </>
              )}
            </div>
          </div>

          {/* side controls */}
          <div style={{ flex: '1 1 260px', display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', gap: 8 }}>
              <Badge tone={power === 'on' ? 'green' : power === 'booting' ? 'amber' : 'gray'}>{power.toUpperCase()}</Badge>
              {power === 'on' ? <button className="sf-btn" onClick={() => setPower('off')}>Power off</button> : power === 'off' ? <button className="sf-btn sf-btn-accent" onClick={powerOn}>Power on</button> : null}
            </div>
            <p style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.6 }}>
              A working virtual bench: boot it, poke the apps, watch logcat, drive ADB — then bridge
              the same profile to a real backend twin for fuzzing and attack runs.
            </p>
            <div>
              <button className="sf-btn" onClick={linkTwin}>Bridge to backend twin ({profile.arch})</button>
              {twin && (
                <p style={{ color: '#6ee7b7', fontSize: 13 }}>
                  {twin} ·{' '}
                  <a href="/emulator" style={{ color: '#a5f3fc' }}>
                    open /emulator
                  </a>
                </p>
              )}
              {err && <p style={{ color: '#f87171', fontSize: 13 }}>{err}</p>}
            </div>
          </div>
        </div>
      )}

      {tab === 'log' && (
        <div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
            <input className="sf-input" placeholder="filter by tag/message" value={tagFilter} onChange={(e) => setTagFilter(e.target.value)} style={{ flex: 1 }} />
            <button className="sf-btn" onClick={() => setLogRun((v) => !v)}>{logRun ? 'Pause' : 'Resume'}</button>
            <button className="sf-btn" onClick={() => setLogs([])}>Clear</button>
          </div>
          <div className="uv-term">
            <div className="uv-term-bar">
              <span className="uv-dot uv-dot-r" /><span className="uv-dot uv-dot-y" /><span className="uv-dot uv-dot-g" />
              <span style={{ marginLeft: 6 }}>LOGCAT — {profile.id}</span>
            </div>
            <div ref={logRef} className="sf-console" style={{ height: 380 }}>
            {power !== 'on' ? (
              <span style={{ color: '#64748b' }}>— device offline, power it on from the Screen tab —</span>
            ) : (
              shownLogs.map((l, i) => {
                const lv = l.slice(9, 10);
                return (
                  <div key={i}>
                    <span style={{ color: '#64748b' }}>{l.slice(0, 8)} </span>
                    <b style={{ color: LV_COLOR[lv] ?? '#94a3b8' }}>{lv}</b>
                    <span style={{ color: '#cbd5e1' }}>{l.slice(10)}</span>
                  </div>
                );
              })
            )}
          </div>
          </div>
        </div>
      )}

      {tab === 'adb' && (
        <div>
          <div className="uv-term">
            <div className="uv-term-bar">
              <span className="uv-dot uv-dot-r" /><span className="uv-dot uv-dot-y" /><span className="uv-dot uv-dot-g" />
              <span style={{ marginLeft: 6 }}>ADB SHELL — {profile.id}</span>
            </div>
            <div ref={shellRef} className="sf-console" style={{ height: 380, color: '#e2e8f0' }}>
              {shellHist.map((l, i) => (
                <div key={i} style={{ color: l.startsWith('shell@') ? '#22d3ee' : undefined }}>{l}</div>
              ))}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <input
              className="sf-input"
              placeholder="adb: help | getprop | pm list packages | install com.evil.ota …"
              value={shellIn}
              onChange={(e) => setShellIn(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  adb(shellIn);
                  setShellIn('');
                }
              }}
              style={{ flex: 1, fontFamily: 'monospace' }}
            />
            <button className="sf-btn sf-btn-accent" onClick={() => { adb(shellIn); setShellIn(''); }}>Run</button>
          </div>
        </div>
      )}

      {tab === 'snaps' && (
        <div>
          <button className="sf-btn sf-btn-accent" onClick={snapshot}>Capture snapshot</button>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 12 }}>
            {snaps.map((s) => (
              <div key={s.id} className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 10, padding: '10px 14px', fontSize: 13, display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <code style={{ color: '#a5f3fc' }}>{s.id}</code>
                <span style={{ color: '#64748b' }}>{fmtUtcTime(s.at)}</span>
                <code>state:{s.hash}</code>
                <button className="sf-btn" style={{ marginLeft: 'auto', padding: '5px 12px' }} onClick={() => restore(s)}>Restore</button>
              </div>
            ))}
            {snaps.length === 0 && <div style={{ marginTop: 8 }}><Empty title="No snapshots" hint="Capture before installing anything suspicious." /></div>}
          </div>
        </div>
      )}
    </Card>
  );
}
