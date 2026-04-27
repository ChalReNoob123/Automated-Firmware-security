import { useState, useEffect, useCallback, useRef } from "react";
import { Server, Play, RotateCcw, Terminal, Cpu, Shield, AlertTriangle, CheckCircle, Lock, Fingerprint, Award, Activity, Key, HardDrive } from "lucide-react";
import { DIGITAL_SIGNATURE_TEMPLATES, calculateFileTrustScore, ALL_COMPLIANCE_FRAMEWORKS, type DigitalSignature } from "../data/governmentStandards";

type VMState = "poweroff" | "running" | "paused" | "snapshotting" | "restoring" | "analyzing" | "compromised";

type VirtualMachine = {
  id: string;
  name: string;
  osType: "Windows 11 Enterprise" | "Ubuntu 22.04 LTS" | "Windows Server 2022 DC" | "Red Hat Enterprise Linux 9";
  state: VMState;
  cpu: number;
  memory: number;
  diskSize: number;
  snapshotCount: number;
  currentSnapshot: string;
  uptime: number;
  guestAdditions: boolean;
  vtX: boolean;
  nestedPaging: boolean;
  ioApic: boolean;
  efi: boolean;
  secureBoot: boolean;
  tpmVersion: string;
  sampleFile: string;
  analysisProgress: number;
};

type ForensicLog = {
  id: string;
  timestamp: number;
  vmId: string;
  category: "hypervisor" | "guest_kernel" | "network" | "filesystem" | "registry" | "memory" | "syscall" | "cert_validation";
  severity: "info" | "warning" | "critical";
  event: string;
  details: string;
  mitreTechnique?: string;
  governmentStandard?: string;
  signatureValid?: boolean;
};

type AnalysisResult = {
  vmId: string;
  sampleName: string;
  detonationTime: number;
  behavioralScore: number;
  fileReputation: "clean" | "suspicious" | "malicious" | "unknown";
  signaturesDetected: string[];
  certificateStatus: "valid" | "invalid" | "untrusted" | "expired" | "revoked" | "none";
  complianceViolations: string[];
  forensicArtifacts: string[];
  yaraMatches: string[];
  iocsExtracted: string[];
};

export default function AdvancedVirtualBox() {
  const [vms, setVms] = useState<VirtualMachine[]>([
    { id: "vm-001", name: "Win11-Enterprise-Analysis", osType: "Windows 11 Enterprise", state: "running", cpu: 4, memory: 8192, diskSize: 100, snapshotCount: 5, currentSnapshot: "Baseline-Clean-2024-01", uptime: 3600, guestAdditions: true, vtX: true, nestedPaging: true, ioApic: true, efi: true, secureBoot: true, tpmVersion: "2.0", sampleFile: "invoice_2024.xlsm", analysisProgress: 0 },
    { id: "vm-002", name: "Ubuntu-Forensics-Station", osType: "Ubuntu 22.04 LTS", state: "poweroff", cpu: 2, memory: 4096, diskSize: 60, snapshotCount: 3, currentSnapshot: "Clean-Ubuntu-22.04", uptime: 0, guestAdditions: true, vtX: true, nestedPaging: true, ioApic: true, efi: true, secureBoot: false, tpmVersion: "none", sampleFile: "", analysisProgress: 0 },
    { id: "vm-003", name: "Server2022-DC-Lab", osType: "Windows Server 2022 DC", state: "running", cpu: 4, memory: 16384, diskSize: 200, snapshotCount: 8, currentSnapshot: "AD-Controller-Baseline", uptime: 7200, guestAdditions: true, vtX: true, nestedPaging: true, ioApic: true, efi: true, secureBoot: true, tpmVersion: "2.0", sampleFile: "sysupdate_patch.exe", analysisProgress: 0 },
  ]);

  const [selectedVmId, setSelectedVmId] = useState<string>("vm-001");
  const [logs, setLogs] = useState<ForensicLog[]>([]);
  const [signatures] = useState<DigitalSignature[]>(DIGITAL_SIGNATURE_TEMPLATES);
  const [selectedSigId, setSelectedSigId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"vm_control" | "forensics" | "certificates" | "compliance">("vm_control");
  const [detonating, setDetonating] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<AnalysisResult | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logEndRef.current) logEndRef.current.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const addLog = useCallback((vmId: string, category: ForensicLog["category"], severity: ForensicLog["severity"], event: string, details: string, mitre?: string, standard?: string) => {
    const log: ForensicLog = {
      id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 5)}`,
      timestamp: Date.now(),
      vmId,
      category,
      severity,
      event,
      details,
      mitreTechnique: mitre,
      governmentStandard: standard,
    };
    setLogs(prev => [...prev.slice(-100), log]);
  }, []);

  const detonateSample = useCallback((vmId: string, sampleName: string) => {
    if (detonating) return;
    setDetonating(true);
    setProgress(0);
    setResults(null);

    addLog(vmId, "hypervisor", "info", "VM_STATE_CHANGE", "Transitioning VM to analysis state", "", "FIPS-140-2");
    
    let step = 0;
    const interval = setInterval(() => {
      step += 5;
      setProgress(step);

      if (step === 10) {
        addLog(vmId, "hypervisor", "info", "SNAPSHOT_REVERT", "Reverting to pristine snapshot for clean analysis environment", "", "NIST-800-53");
        addLog(vmId, "cert_validation", "info", "CODE_SIGNATURE_CHECK", "Validating Authenticode signature before execution", "T1204", "FIPS-140-2");
      }
      if (step === 20) {
        addLog(vmId, "guest_kernel", "warning", "DRIVER_LOAD", "Hypervisor agent driver loaded into guest kernel", "T1062", "Common Criteria");
        addLog(vmId, "syscall", "info", "EXECVE", `Sample ${sampleName} executed via CreateProcessW`, "T1204", "NIST-800-53");
      }
      if (step === 30) {
        addLog(vmId, "memory", "critical", "ALLOCATE_RWX", "NtAllocateVirtualMemory with PAGE_EXECUTE_READWRITE detected", "T1055", "FedRAMP-High");
        addLog(vmId, "syscall", "critical", "PROCESS_INJECTION", "WriteProcessMemory targeting svchost.exe", "T1055.012", "NIST-800-53");
      }
      if (step === 40) {
        addLog(vmId, "registry", "warning", "REG_SET_VALUE", "Persistence established via HKLM\\Run key modification", "T1547.001", "NIST-800-53");
        addLog(vmId, "network", "critical", "OUTBOUND_CONNECTION", "TCP SYN to 185.220.101.47:4444 (Tor Exit Node)", "T1090.003", "FedRAMP-High");
      }
      if (step === 50) {
        addLog(vmId, "filesystem", "warning", "MASS_FILE_ACCESS", "Bulk enumeration of C:\\Users\\*\\Documents", "T1083", "Common Criteria");
        addLog(vmId, "cert_validation", "critical", "CERT_REVOCATION", "Self-signed certificate detected in TLS handshake", "T1573", "FIPS-140-2");
      }
      if (step === 60) {
        addLog(vmId, "memory", "critical", "LSASS_ACCESS", "OpenProcess on LSASS.exe with PROCESS_VM_READ", "T1003.001", "NIST-800-53");
        addLog(vmId, "syscall", "critical", "CREDENTIAL_DUMP", "MiniDumpWriteDump API invoked on LSASS process", "T1003.001", "FedRAMP-High");
      }
      if (step === 70) {
        addLog(vmId, "filesystem", "critical", "VSS_DELETE", "vssadmin.exe delete shadows /all executed", "T1490", "NIST-800-53");
        addLog(vmId, "filesystem", "critical", "FILE_ENCRYPTION", "Mass file modification with .lockbit extension", "T1486", "Common Criteria");
      }
      if (step === 80) {
        addLog(vmId, "network", "critical", "DATA_EXFILTRATION", "Encrypted data stream detected to C2 server", "T1041", "FedRAMP-High");
        addLog(vmId, "hypervisor", "warning", "GUEST_CRASH", "Guest OS instability detected - potential rootkit", "T1014", "Common Criteria");
      }
      if (step === 90) {
        addLog(vmId, "hypervisor", "info", "MEMORY_DUMP", "Complete physical memory dump captured (16GB)", "", "NIST-800-53");
        addLog(vmId, "hypervisor", "info", "DISK_SNAPSHOT", "Forensic disk snapshot created for evidence", "", "FedRAMP-High");
      }
      if (step === 100) {
        clearInterval(interval);
        setDetonating(false);
        addLog(vmId, "hypervisor", "info", "ANALYSIS_COMPLETE", "Dynamic analysis concluded - VM quarantined", "", "FIPS-140-2");
        
        const res: AnalysisResult = {
          vmId,
          sampleName,
          detonationTime: Date.now(),
          behavioralScore: 98,
          fileReputation: "malicious",
          signaturesDetected: ["Ransomware.LockBit", "CredentialDumper.Mimikatz", "C2.CobaltStrike"],
          certificateStatus: "revoked",
          complianceViolations: ["FIPS-140-2-C1", "NIST-800-53-SI-4", "FedRAMP-SC-7"],
          forensicArtifacts: ["C2_config.bin", "encrypted_files.lst", "memory_dump.raw", "registry_hive.system"],
          yaraMatches: ["Ransomware_LockBit_Indicators", "Credential_Dumper_Generic"],
          iocsExtracted: ["185.220.101.47", "lockbit-ransomware.onion", "SHA256:deadbeef..."],
        };
        setResults(res);
        setVms(prev => prev.map(v => v.id === vmId ? { ...v, state: "compromised", analysisProgress: 100 } : v));
      }
    }, 400);
  }, [detonating, addLog]);

  const selectedVm = vms.find(v => v.id === selectedVmId)!;
  const selectedSig = signatures.find(s => s.filePath === selectedSigId);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Server className="h-5 w-5 text-amber-500" />
            Advanced VirtualBox Enterprise Hypervisor
          </h2>
          <p className="text-sm text-slate-400">
            Government-grade bare-metal virtualization with FIPS 140-2 validation, Common Criteria EAL4+ compliance, and forensic-grade analysis.
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          {ALL_COMPLIANCE_FRAMEWORKS.map(fw => (
            <span key={fw.id} className="flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-300">
              <Award className="h-3 w-3" /> {fw.id.toUpperCase()} {fw.complianceScore}%
            </span>
          ))}
        </div>
      </div>

      {/* VM Grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {vms.map(vm => (
          <button
            key={vm.id}
            type="button"
            onClick={() => setSelectedVmId(vm.id)}
            className={`rounded-2xl border p-4 text-left transition-all ${selectedVmId === vm.id ? "border-amber-400/40 bg-amber-500/10 ring-1 ring-amber-400/30" : "border-white/10 bg-white/5 hover:border-white/20"}`}
          >
            <div className="flex items-start justify-between mb-2">
              <Server className={`h-5 w-5 ${vm.state === "running" ? "text-emerald-400 animate-pulse" : vm.state === "compromised" ? "text-rose-400" : "text-slate-500"}`} />
              <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase ${vm.state === "running" ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300" : vm.state === "compromised" ? "border-rose-500/30 bg-rose-500/10 text-rose-300" : "border-slate-500/30 bg-slate-500/10 text-slate-400"}`}>
                {vm.state}
              </span>
            </div>
            <p className="text-sm font-bold text-white truncate">{vm.name}</p>
            <p className="text-xs text-slate-400">{vm.osType}</p>
            <div className="mt-3 grid grid-cols-2 gap-2 text-[10px] text-slate-500">
              <span>{vm.cpu} vCPU</span>
              <span>{vm.memory} MB RAM</span>
              <span>{vm.diskSize} GB Disk</span>
              <span>{vm.snapshotCount} Snapshots</span>
            </div>
            {vm.sampleFile && (
              <p className="mt-2 text-[10px] text-amber-300 truncate">Sample: {vm.sampleFile}</p>
            )}
          </button>
        ))}
      </div>

      {/* Control Panel */}
      <div className="rounded-3xl border border-white/10 bg-white/5 p-5">
        <div className="flex flex-col gap-4 md:flex-row md:items-center">
          <input
            type="text"
            placeholder="Enter file hash, malware family, or upload sample..."
            className="flex-1 rounded-2xl border border-white/10 bg-black/30 px-4 py-3 text-sm text-white placeholder-slate-500 outline-none focus:border-amber-500/50"
          />
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => detonateSample(selectedVmId, selectedVm.sampleFile || "suspicious.bin")}
              disabled={detonating || selectedVm.state === "compromised"}
              className="flex items-center gap-2 rounded-2xl border border-amber-400/30 bg-amber-500/10 px-5 py-3 text-sm font-semibold text-amber-200 hover:bg-amber-500/20 disabled:opacity-50"
            >
              <Play className="h-4 w-4" /> Detonate &amp; Analyze
            </button>
            <button
              type="button"
              onClick={() => setVms(prev => prev.map(v => v.id === selectedVmId ? { ...v, state: "poweroff", sampleFile: "", analysisProgress: 0 } : v))}
              disabled={detonating}
              className="flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-300 hover:bg-white/10 disabled:opacity-50"
            >
              <RotateCcw className="h-4 w-4" /> Revert Snapshot
            </button>
          </div>
        </div>

        {detonating && (
          <div className="mt-4">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span className="flex items-center gap-2 font-mono">
                <Activity className="h-3 w-3 text-amber-500 animate-pulse" /> 
                FIPS 140-2 Validated Analysis in Progress...
              </span>
              <span>{progress}%</span>
            </div>
            <div className="h-2 rounded-full bg-white/5 overflow-hidden">
              <div className="h-full rounded-full bg-gradient-to-r from-amber-500 via-orange-500 to-rose-500 transition-all" style={{ width: `${progress}%` }} />
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-white/10 pb-2 overflow-x-auto">
        {[
          { id: "vm_control", label: "VM Control & Hardware", icon: Cpu },
          { id: "forensics", label: "Forensic Analysis Logs", icon: Terminal },
          { id: "certificates", label: "Digital Signatures & PKI", icon: Fingerprint },
          { id: "compliance", label: "Government Compliance", icon: Shield },
        ].map(t => (
          <button
            key={t.id}
            type="button"
            onClick={() => setActiveTab(t.id as typeof activeTab)}
            className={`flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-medium whitespace-nowrap transition ${activeTab === t.id ? "bg-white/10 text-white" : "text-slate-400 hover:text-slate-200"}`}
          >
            <t.icon className="h-4 w-4" /> {t.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="grid gap-6 lg:grid-cols-12">
        {activeTab === "vm_control" && (
          <>
            <div className="lg:col-span-4 rounded-3xl border border-white/10 bg-white/5 p-5">
              <h3 className="text-sm font-bold text-white mb-4">Virtual Hardware Configuration</h3>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between border-b border-white/5 pb-2">
                  <span className="text-slate-400">Virtualization Engine</span>
                  <span className="text-emerald-400 font-semibold">VT-x/AMD-V Enabled</span>
                </div>
                <div className="flex justify-between border-b border-white/5 pb-2">
                  <span className="text-slate-400">Nested Paging</span>
                  <span className="text-emerald-400">{selectedVm.nestedPaging ? "Enabled" : "Disabled"}</span>
                </div>
                <div className="flex justify-between border-b border-white/5 pb-2">
                  <span className="text-slate-400">I/O APIC</span>
                  <span className="text-emerald-400">{selectedVm.ioApic ? "Enabled" : "Disabled"}</span>
                </div>
                <div className="flex justify-between border-b border-white/5 pb-2">
                  <span className="text-slate-400">EFI Boot</span>
                  <span className="text-emerald-400">{selectedVm.efi ? "Enabled" : "Disabled"}</span>
                </div>
                <div className="flex justify-between border-b border-white/5 pb-2">
                  <span className="text-slate-400">Secure Boot</span>
                  <span className={selectedVm.secureBoot ? "text-emerald-400" : "text-rose-400"}>
                    {selectedVm.secureBoot ? "Enabled" : "Disabled"}
                  </span>
                </div>
                <div className="flex justify-between border-b border-white/5 pb-2">
                  <span className="text-slate-400">TPM Version</span>
                  <span className="text-sky-400 font-mono">{selectedVm.tpmVersion}</span>
                </div>
                <div className="flex justify-between border-b border-white/5 pb-2">
                  <span className="text-slate-400">Guest Additions</span>
                  <span className={selectedVm.guestAdditions ? "text-emerald-400" : "text-rose-400"}>
                    {selectedVm.guestAdditions ? "Installed" : "Not Installed"}
                  </span>
                </div>
              </div>

              <div className="mt-6 rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-4">
                <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm mb-2">
                  <Shield className="h-4 w-4" /> Hardware-Assisted Isolation
                </div>
                <p className="text-xs text-slate-400">
                  Ring -1 hypervisor isolation active. Guest OS cannot escape to host. 
                  Memory boundaries enforced by CPU hardware (EPT/NPT).
                </p>
              </div>
            </div>

            <div className="lg:col-span-8 rounded-3xl border border-white/10 bg-white/5 p-5">
              <h3 className="text-sm font-bold text-white mb-4">Analysis Results &amp; Government Standards</h3>
              {results ? (
                <div className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-3">
                    <div className="rounded-2xl border border-rose-500/20 bg-rose-500/5 p-4 text-center">
                      <p className="text-3xl font-black text-rose-500">{results.behavioralScore}/100</p>
                      <p className="text-xs text-slate-400 mt-1">Behavioral Threat Score</p>
                    </div>
                    <div className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-4 text-center">
                      <p className="text-lg font-bold text-amber-400 capitalize">{results.fileReputation}</p>
                      <p className="text-xs text-slate-400 mt-1">File Reputation</p>
                    </div>
                    <div className="rounded-2xl border border-sky-500/20 bg-sky-500/5 p-4 text-center">
                      <p className="text-lg font-bold text-sky-400">{results.certificateStatus}</p>
                      <p className="text-xs text-slate-400 mt-1">Certificate Status</p>
                    </div>
                  </div>

                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <h4 className="text-xs font-bold text-rose-400 uppercase tracking-widest mb-2">Detected Malware Signatures</h4>
                    <div className="flex flex-wrap gap-2">
                      {results.signaturesDetected.map(sig => (
                        <span key={sig} className="rounded-lg border border-rose-500/20 bg-rose-500/10 px-3 py-1 text-sm font-mono text-rose-300">{sig}</span>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <h4 className="text-xs font-bold text-amber-400 uppercase tracking-widest mb-2">Compliance Violations</h4>
                    <ul className="space-y-1 text-sm text-slate-300">
                      {results.complianceViolations.map(v => (
                        <li key={v} className="flex items-center gap-2">
                          <AlertTriangle className="h-3 w-3 text-amber-500" /> {v}
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-widest mb-2">Extracted IOCs</h4>
                    <div className="flex flex-wrap gap-2 font-mono text-xs">
                      {results.iocsExtracted.map(ioc => (
                        <span key={ioc} className="rounded bg-black/30 px-2 py-1 text-emerald-300">{ioc}</span>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-64 text-slate-500">
                  <HardDrive className="h-12 w-12 text-slate-600 mb-2" />
                  <p>No analysis results yet. Detonate a sample to begin forensic analysis.</p>
                </div>
              )}
            </div>
          </>
        )}

        {activeTab === "forensics" && (
          <>
            <div className="lg:col-span-5 rounded-3xl border border-white/10 bg-black/40 p-5 h-[600px] flex flex-col">
              <div className="flex items-center justify-between mb-3 border-b border-white/10 pb-2">
                <div className="flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-amber-400" />
                  <h3 className="text-sm font-bold text-white font-mono">Hypervisor Forensic Trace</h3>
                </div>
                <span className="text-[10px] text-slate-500 font-mono">FIPS 140-2 Validated Logging</span>
              </div>
              <div className="flex-1 overflow-y-auto font-mono text-xs space-y-1 pr-1 custom-scrollbar">
                {logs.map(log => (
                  <div key={log.id} className="flex items-start gap-2 p-2 rounded hover:bg-white/5">
                    <span className="text-slate-500 shrink-0">{new Date(log.timestamp).toLocaleTimeString()}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 ${
                      log.category === "hypervisor" ? "bg-purple-500/10 text-purple-300 border border-purple-500/20" :
                      log.category === "cert_validation" ? "bg-amber-500/10 text-amber-300 border border-amber-500/20" :
                      "bg-slate-500/10 text-slate-300 border border-slate-500/20"
                    }`}>{log.category}</span>
                    <div className="flex-1 min-w-0">
                      <span className={`font-bold ${log.severity === "critical" ? "text-rose-400" : log.severity === "warning" ? "text-amber-300" : "text-slate-300"}`}>
                        {log.event}
                      </span>
                      <p className="text-slate-500 truncate">{log.details}</p>
                      {log.mitreTechnique && (
                        <span className="text-[10px] text-rose-400 font-mono">MITRE: {log.mitreTechnique}</span>
                      )}
                    </div>
                  </div>
                ))}
                <div ref={logEndRef} />
              </div>
            </div>

            <div className="lg:col-span-7 rounded-3xl border border-white/10 bg-white/5 p-5 h-[600px] overflow-y-auto custom-scrollbar">
              <h3 className="text-sm font-bold text-white mb-4">Detailed Forensic Analysis</h3>
              
              <div className="space-y-4">
                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <h4 className="text-xs font-bold text-sky-400 uppercase tracking-widest mb-3">Memory Forensics (Volatility 3)</h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between border-b border-white/5 pb-1">
                      <span className="text-slate-500">Process Hollowing Detected</span>
                      <span className="text-rose-400">PID 4821 → PID 912 (svchost.exe)</span>
                    </div>
                    <div className="flex justify-between border-b border-white/5 pb-1">
                      <span className="text-slate-500">Memory Sections (VAD)</span>
                      <span className="text-amber-400">0x0045A000-0x0045F000 (RWX)</span>
                    </div>
                    <div className="flex justify-between border-b border-white/5 pb-1">
                      <span className="text-slate-500">Injected Shellcode Hash</span>
                      <span className="text-slate-300">SHA256: a3b8c9d4...</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Extracted Strings</span>
                      <span className="text-emerald-400">C2: 185.220.101.47:4444</span>
                    </div>
                  </div>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <h4 className="text-xs font-bold text-amber-400 uppercase tracking-widest mb-3">Disk Forensics (Sleuth Kit)</h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between border-b border-white/5 pb-1">
                      <span className="text-slate-500">Deleted Files Recovered</span>
                      <span className="text-rose-400">C:\\Windows\\Temp\\tmp8421.bat</span>
                    </div>
                    <div className="flex justify-between border-b border-white/5 pb-1">
                      <span className="text-slate-500">MFT Record Analysis</span>
                      <span className="text-amber-400">$LogFile shows mass file access</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Timeline Analysis</span>
                      <span className="text-emerald-400">14:32:18 - First encryption</span>
                    </div>
                  </div>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                  <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-widest mb-3">Network Forensics (Wireshark/tshark)</h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between border-b border-white/5 pb-1">
                      <span className="text-slate-500">C2 Protocol</span>
                      <span className="text-rose-400">HTTPS over 4444 (Non-standard)</span>
                    </div>
                    <div className="flex justify-between border-b border-white/5 pb-1">
                      <span className="text-slate-500">TLS Fingerprint (JA3)</span>
                      <span className="text-amber-400">51c64c77e60f3980eea90869b68d58d8</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Data Exfiltrated</span>
                      <span className="text-emerald-400">2.4 GB encrypted to Tor exit</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {activeTab === "certificates" && (
          <>
            <div className="lg:col-span-5 rounded-3xl border border-white/10 bg-white/5 p-5 h-[600px] flex flex-col">
              <h3 className="text-sm font-bold text-white mb-4">Digital Signature Inventory</h3>
              <div className="flex-1 overflow-y-auto space-y-2 pr-1 custom-scrollbar">
                {signatures.map(sig => {
                  const trustScore = calculateFileTrustScore(sig);
                  return (
                    <button
                      key={sig.filePath}
                      type="button"
                      onClick={() => setSelectedSigId(sig.filePath)}
                      className={`w-full p-3 rounded-2xl border text-left transition-all ${selectedSigId === sig.filePath ? "border-amber-400/40 bg-amber-500/10" : "border-white/10 bg-black/20 hover:border-white/20"}`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-mono text-white truncate max-w-[200px]">{sig.filePath}</span>
                        {sig.signed ? (
                          sig.valid ? (
                            <CheckCircle className="h-4 w-4 text-emerald-400" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-rose-400" />
                          )
                        ) : (
                          <span className="text-[10px] text-slate-500">UNSIGNED</span>
                        )}
                      </div>
                      <div className="flex items-center justify-between text-[10px]">
                        <span className="text-slate-400">Trust Score: <span className={trustScore >= 80 ? "text-emerald-400" : trustScore >= 50 ? "text-amber-400" : "text-rose-400"}>{trustScore}/100</span></span>
                        <span className="text-slate-500">{sig.algorithm}</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="lg:col-span-7 rounded-3xl border border-white/10 bg-white/5 p-5 h-[600px] overflow-y-auto custom-scrollbar">
              {selectedSig ? (
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-white/10 pb-2">
                    <h3 className="text-sm font-bold text-white">Certificate Chain Validation</h3>
                    <span className={`rounded-full border px-2.5 py-1 text-xs font-bold uppercase ${selectedSig.valid ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-rose-500/30 bg-rose-500/10 text-rose-300"}`}>
                      {selectedSig.valid ? "VALID" : "INVALID"}
                    </span>
                  </div>

                  {selectedSig.certificate && (
                    <>
                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <h4 className="text-xs font-bold text-sky-400 uppercase tracking-widest mb-3">Subject Information</h4>
                        <div className="space-y-1 text-xs font-mono">
                          <div className="flex justify-between border-b border-white/5 pb-1">
                            <span className="text-slate-500">Subject CN</span>
                            <span className="text-slate-300">{selectedSig.certificate.subject.split("CN=")[1]?.split(",")[0] || "Unknown"}</span>
                          </div>
                          <div className="flex justify-between border-b border-white/5 pb-1">
                            <span className="text-slate-500">Issuer</span>
                            <span className="text-slate-300 truncate max-w-[300px]">{selectedSig.certificate.issuer.split("CN=")[1]?.split(",")[0] || "Unknown"}</span>
                          </div>
                          <div className="flex justify-between border-b border-white/5 pb-1">
                            <span className="text-slate-500">Serial Number</span>
                            <span className="text-amber-300">{selectedSig.certificate.serialNumber}</span>
                          </div>
                          <div className="flex justify-between border-b border-white/5 pb-1">
                            <span className="text-slate-500">Thumbprint (SHA-1)</span>
                            <span className="text-slate-300">{selectedSig.certificate.thumbprint}</span>
                          </div>
                          <div className="flex justify-between border-b border-white/5 pb-1">
                            <span className="text-slate-500">Valid From</span>
                            <span className="text-slate-300">{new Date(selectedSig.certificate.validFrom).toLocaleDateString()}</span>
                          </div>
                          <div className="flex justify-between border-b border-white/5 pb-1">
                            <span className="text-slate-500">Valid To</span>
                            <span className={Date.now() > selectedSig.certificate.validTo ? "text-rose-400" : "text-emerald-400"}>
                              {new Date(selectedSig.certificate.validTo).toLocaleDateString()}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Key Algorithm</span>
                            <span className="text-slate-300">{selectedSig.certificate.keyAlgorithm}-{selectedSig.certificate.keySize}</span>
                          </div>
                        </div>
                      </div>

                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <h4 className="text-xs font-bold text-amber-400 uppercase tracking-widest mb-3">Certificate Extensions</h4>
                        <div className="space-y-2">
                          {selectedSig.certificate.extensions.map(ext => (
                            <div key={ext.oid} className="text-xs border-l-2 border-amber-500/30 pl-3">
                              <p className="text-amber-300 font-semibold">{ext.name} <span className="text-slate-500">({ext.oid})</span> {ext.critical && <span className="text-rose-400">[CRITICAL]</span>}</p>
                              <p className="text-slate-400 font-mono break-all">{ext.value}</p>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <h4 className="text-xs font-bold text-rose-400 uppercase tracking-widest mb-3">Validation Chain</h4>
                        <div className="space-y-2">
                          {selectedSig.validationChain.map((cert, idx) => (
                            <div key={idx} className={`flex items-center gap-3 p-2 rounded-lg border ${cert.valid ? "border-emerald-500/20 bg-emerald-500/5" : "border-rose-500/20 bg-rose-500/5"}`}>
                              <div className="flex flex-col items-center">
                                <span className="text-[10px] text-slate-500">L{cert.level}</span>
                                {idx === 0 ? <Key className="h-4 w-4 text-slate-400" /> : <Lock className="h-4 w-4 text-slate-400" />}
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-xs font-semibold text-white truncate">{cert.subject}</p>
                                <p className="text-[10px] text-slate-500 truncate">Issued by: {cert.issuer}</p>
                                <p className="text-[10px] font-mono text-slate-600">{cert.thumbprint}</p>
                              </div>
                              <div className="text-right">
                                {cert.trusted ? (
                                  <span className="text-[10px] text-emerald-400 font-bold">TRUSTED</span>
                                ) : (
                                  <span className="text-[10px] text-rose-400 font-bold">UNTRUSTED</span>
                                )}
                                {cert.selfSigned && <span className="block text-[10px] text-amber-400">SELF-SIGNED</span>}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {selectedSig.certificate.revocationStatus && (
                        <div className={`rounded-2xl border p-4 ${selectedSig.certificate.revocationStatus === "revoked" ? "border-rose-500/30 bg-rose-500/10" : "border-emerald-500/30 bg-emerald-500/10"}`}>
                          <div className="flex items-center gap-2 mb-2">
                            {selectedSig.certificate.revocationStatus === "revoked" ? (
                              <AlertTriangle className="h-5 w-5 text-rose-400" />
                            ) : (
                              <CheckCircle className="h-5 w-5 text-emerald-400" />
                            )}
                            <h4 className="text-sm font-bold text-white">Revocation Status</h4>
                          </div>
                          <p className={`text-sm ${selectedSig.certificate.revocationStatus === "revoked" ? "text-rose-400" : "text-emerald-400"}`}>
                            {selectedSig.certificate.revocationStatus.toUpperCase()}
                          </p>
                          {selectedSig.certificate.ocspResponse && (
                            <p className="text-xs text-slate-400 mt-1">OCSP Response: {selectedSig.certificate.ocspResponse}</p>
                          )}
                        </div>
                      )}
                    </>
                  )}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-slate-500">
                  <Fingerprint className="h-12 w-12 text-slate-600 mb-2" />
                  <p>Select a file to view detailed PKI validation and certificate chain.</p>
                </div>
              )}
            </div>
          </>
        )}

        {activeTab === "compliance" && (
          <div className="lg:col-span-12 space-y-6">
            {ALL_COMPLIANCE_FRAMEWORKS.map(framework => (
              <div key={framework.id} className="rounded-3xl border border-white/10 bg-white/5 p-5">
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-4 border-b border-white/10 pb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-lg font-bold text-white">{framework.name}</h3>
                      <span className="text-xs text-slate-500">v{framework.version}</span>
                    </div>
                    <p className="text-xs text-slate-400">{framework.authority} · {framework.description}</p>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <p className="text-2xl font-black text-emerald-400">{framework.complianceScore}%</p>
                      <p className="text-xs text-slate-500">Compliance Score</p>
                    </div>
                    <span className={`rounded-full border px-3 py-1 text-xs font-bold uppercase ${framework.status === "compliant" ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-amber-500/30 bg-amber-500/10 text-amber-300"}`}>
                      {framework.status}
                    </span>
                  </div>
                </div>

                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                  {framework.controls.map(control => (
                    <div key={control.id} className="rounded-2xl border border-white/10 bg-black/20 p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-mono text-sky-400 font-bold">{control.id}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase ${control.status === "implemented" ? "bg-emerald-500/10 text-emerald-300" : "bg-amber-500/10 text-amber-300"}`}>
                          {control.status}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-white mb-1">{control.name}</h4>
                      <p className="text-xs text-slate-400 mb-3 line-clamp-2">{control.description}</p>
                      <div className="flex flex-wrap gap-1">
                        {control.mitreMappings.map(mitre => (
                          <span key={mitre} className="text-[10px] font-mono text-rose-300 bg-rose-500/10 px-1.5 py-0.5 rounded">{mitre}</span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
