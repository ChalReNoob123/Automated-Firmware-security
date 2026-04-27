# SentinelGrid Enterprise SOC - Quick Start Guide

## 🚀 Getting Started in 5 Minutes

### 1. **Access the Platform**
Open the web application in your browser. The dashboard loads automatically with:
- Real-time threat detection
- Live network monitoring
- Framework compliance tracking

### 2. **Navigate the 8 Tabs**

#### **Tab 1: SOC Dashboard** 📊
Default view showing:
- **Top Stats**: Threat pressure, protected sessions, detections, network throughput
- **Threat Alert Stream**: Live alerts with MITRE technique mapping
- **Network Sessions**: All active connections with risk scoring
- **Charts**: Traffic trend, severity distribution, category breakdown
- **Response Ledger**: Automated actions taken

**Key Actions**:
- Click on any alert to see full details
- Hover over connections to see more info
- Use "Inject Event" button to simulate threats

#### **Tab 2: MITRE ATT&CK** 🎯
Explore all 14 tactics and 202 techniques:
- Click tactic selector to filter
- Click technique to expand and see:
  - Detection logic
  - IOC patterns (indicators to search for)
  - Mitigation strategies
  - Data sources for detection
  - Sub-techniques

**Use For**:
- Understanding attack methods
- Finding detection rules
- Identifying mitigations
- Threat hunting

#### **Tab 3: NIST CSF 2.0** ✅
Compliance dashboard with:
- **Overall Score**: 83% (your org's compliance level)
- **6 Functions**: Click to expand and see categories
- **Radar Chart**: Visual compliance posture
- **Compliance Tiers**: Which tier your org fits

**Use For**:
- Compliance audits
- Gap analysis
- Control implementation planning
- Board reporting

#### **Tab 4: CIS Controls** 🛡️
18 controls for enterprise security:
- View all safeguards with implementation status
- Check maturity levels (1-5 scale)
- See attack coverage per control
- Filter by Implementation Group (IG1/IG2/IG3)

**Use For**:
- Security hardening
- Control prioritization
- Regulatory compliance
- Risk assessment

#### **Tab 5: OWASP Top 10** 🔐
10 critical web application risks:
- Read vulnerability descriptions
- View real-world breach examples
- Check mitigation strategies
- Use testing checklist

**Use For**:
- Web app security assessment
- Remediation planning
- Developer training
- Penetration testing

#### **Tab 6: VirusTotal Scanner** 🔍
Real-time threat intelligence scanning:

**Search Types**:
1. **File Hash**: MD5, SHA1, SHA256
   - Example: `d41d8cd98f00b204e9800998ecf8427e`
2. **IP Address**: IPv4 format
   - Example: `185.220.101.47`
3. **Domain**: Any website
   - Example: `update-microsoft-sync[.]com`
4. **URL**: Complete web address
   - Example: `http://malicious-server.com/payload.exe`
5. **Email**: Email address
   - Example: `attacker@domain.com`

**Quick Samples** (Pre-filled):
- Click "Mimikatz MD5" → Shows known password stealer
- Click "C2 Server IP" → Shows command & control indicator
- Click "Phishing Domain" → Shows fake domain
- Click "LockBit SHA256" → Shows ransomware
- Click "Clean Domain" → Shows benign website

**How to Read Results**:
- Green badge: Clean (0 detections)
- Yellow badge: Suspicious (10-49 detections)
- Orange badge: High risk (50-69 detections)
- Red badge: Critical (70+ detections)

**Scan History**: Appears below, click to re-examine

#### **Tab 7: Windows Logs & Registry** 📋

**Event Logs Section**:
- **Live Filter**: Search by message, source, or event ID
- **Level Filter**: Critical, Error, Warning, Information
- **Suspicious Only**: Toggle to show only anomalies
- **Auto-Refresh**: Live ingestion of new events

**Quick Event Reference**:
- 4625: Failed logon (brute force indicator)
- 4698: Scheduled task created (persistence)
- 1102: Audit log cleared (cover-up)
- 4688: Process created (execution)
- 4672: Special privileges (escalation)
- 4720: User created (lateral movement)
- 7045: Service installed (persistence)
- 1116: Malware detected (threat)

**Registry Monitoring Section**:
- Shows suspicious registry changes
- Highlights MITRE technique mappings
- Identifies persistence mechanisms
- Tracks unsafe configurations

**High-Risk Registry Keys to Monitor**:
- `HKCU\...\Run` (autorun persistence)
- `HKLM\SYSTEM\...\Services` (service persistence)
- `HKLM\SOFTWARE\...\Windows Defender` (defense evasion)
- `HKLM\...\Image File Execution Options` (process hijacking)

#### **Tab 8: Threat Intelligence** 🎭

**APT Groups**:
- See threat actor profiles
- View targeting sectors
- Check common TTPs (techniques)
- Understand threat motivation

**Malware Families**:
- View malware details
- See file hashes
- Check YARA detection rules
- Understand capabilities

**Live IOC Feed**:
- Malicious IPs, domains, hashes
- Confidence scores
- Last seen information
- Automated blocking status

---

## 🎮 Interactive Features

### Simulate a Threat
1. Go to **SOC Dashboard** tab
2. Click "Attack Simulation" panel
3. Select attack scenario:
   - **C2 Beacon**: Command & control communication
   - **SSH Brute Force**: Password attack
   - **Ransomware**: Data encryption attack
   - **Lateral Movement**: Internal network breach

**What Happens**:
- Alert appears in threat stream (1-2 seconds)
- Network connection auto-dropped or quarantined
- Risk scores update
- Response action logged

### Generate Multiple Alerts
1. Scroll to "Attack Simulation" panel
2. Click different scenarios repeatedly
3. Watch dashboard update in real-time
4. See correlation patterns detected

### Test Framework Views
1. Click each tab to explore
2. Expand collapsible sections
3. Check real-time metrics
4. View detailed control mappings

---

## 📊 Understanding the Metrics

### Threat Pressure (0-100)
- **0-30**: Normal baseline
- **31-60**: Elevated monitoring
- **61-80**: Active threats detected
- **81-100**: Critical threat activity

### Risk Score (Per Connection)
- **0-30**: Low risk - normal traffic
- **31-60**: Medium risk - monitor
- **61-80**: High risk - investigate
- **81-100**: Critical risk - block

### Threat Confidence (0-100%)
- **90-100%**: Definite threat - auto-block
- **80-89%**: High confidence - escalate
- **70-79%**: Moderate confidence - monitor
- **<70%**: Low confidence - allow

### Detection Confidence
- **Critical (81-100)**: Immediate quarantine
- **High (61-80)**: Drop connection
- **Medium (31-60)**: Rate limiting
- **Low (0-30)**: Log & monitor

---

## 🔍 Key Observations

### Real-Time Indicators
Look for these in alerts:

**C2 Communication**:
- Protocol: HTTPS/TLS
- Periodic beacons every 60 seconds
- Low bandwidth, regular intervals
- External IP connections

**Ransomware Activity**:
- Protocol: SMB/RDP
- Large file access patterns
- File extension changes
- VSS (shadow copy) deletion

**Lateral Movement**:
- Sequential port scanning (22, 445, 3389)
- Protocol switching
- Internal-to-internal traffic
- Credential usage patterns

**Data Exfiltration**:
- Large outbound transfers
- Unusual destinations
- Encrypted channels
- Off-hours activity

---

## 📋 Framework Quick Reference

### MITRE ATT&CK
- **Use for**: Identifying attack techniques
- **View**: MITRE ATT&CK tab
- **Tactics**: TA0001 → TA0040 (14 total)
- **Techniques**: 202 with sub-techniques
- **Key**: Understanding *how* attackers work

### NIST CSF 2.0
- **Use for**: Compliance and governance
- **View**: NIST CSF 2.0 tab
- **Functions**: Govern, Identify, Protect, Detect, Respond, Recover
- **Status**: Your org at 83% compliance
- **Key**: Meeting regulatory requirements

### CIS Controls v8.1
- **Use for**: Security hardening
- **View**: CIS Controls tab
- **Controls**: 18 with 153 safeguards
- **Implementation**: IG1 (basic) → IG3 (advanced)
- **Key**: Practical security implementations

### ISO 27001
- **Use for**: Information security management
- **View**: Built-in compliance dashboard
- **Domains**: 14 areas (assets, access, incident response, etc.)
- **Status**: 88% average compliance
- **Key**: Systematic security approach

### OWASP Top 10
- **Use for**: Web application security
- **View**: OWASP Top 10 tab
- **Risks**: 10 critical vulnerabilities
- **Testing**: Use provided checklists
- **Key**: Protecting web applications

---

## ⚙️ Configuration Tips

### Adjust Detection Sensitivity
- High sensitivity: Catch more potential threats (more false positives)
- Low sensitivity: Reduce false alarms (may miss threats)
- Default: Medium (balanced)

### Focus on Specific Threats
1. Go to SOC Dashboard
2. Use framework tabs to understand attacks
3. Return to dashboard to see detections
4. Watch for correlated patterns

### Create Baseline
First 2 weeks of monitoring:
- Establish normal traffic patterns
- Identify legitimate anomalies
- Tune detection thresholds
- Reduce false positives

---

## 🆘 Troubleshooting

**Q: Why is threat pressure so high?**
A: Simulation attacks are running. Click "Paused" button to stop auto-injection.

**Q: No alerts appearing?**
A: Click "Inject Event" button or select attack scenario to generate alerts.

**Q: Can't find a specific event ID?**
A: Use the search box in Windows Logs tab or filter by level.

**Q: What's the difference between frameworks?**
- **MITRE**: Attack techniques (how)
- **NIST**: Compliance & governance (structure)
- **CIS**: Practical controls (what to do)
- **ISO**: Information security management (system)
- **OWASP**: Web app security (focus area)

---

## 📈 Pro Tips

1. **Use Multiple Frameworks**: Each provides different insights
2. **Correlate Alerts**: Look for patterns across multiple events
3. **Check Baselines**: Compare current behavior to normal
4. **Review Mitigations**: Use MITRE tab to understand fixes
5. **Update Threat Intel**: VirusTotal scanner for suspicious indicators
6. **Monitor Compliance**: Track progress toward compliance goals
7. **Validate Controls**: Use CIS to ensure hardening
8. **Hunt Threats**: Look for MITRE techniques in your environment

---

## 🎯 Common Workflows

### Daily SOC Analyst Task
1. Check SOC Dashboard for overnight alerts
2. Review critical incidents in threat stream
3. Use MITRE ATT&CK to understand techniques
4. Check VirusTotal for IOC validation
5. Update Windows log filters for new patterns
6. Document findings

### Compliance Officer Task
1. Open NIST CSF 2.0 tab
2. Check current compliance score
3. Review non-compliant controls
4. Check CIS Controls implementation status
5. Generate compliance report
6. Plan remediation

### Security Architect Task
1. Review CIS Controls coverage
2. Check ISO 27001 domain compliance
3. Analyze OWASP vulnerabilities
4. Map to MITRE ATT&CK
5. Identify gaps
6. Plan improvements

### Threat Hunter Task
1. Review threat intelligence tab
2. Check for relevant IOCs in VirusTotal
3. Search Windows logs for indicators
4. Correlate with MITRE techniques
5. Look for attack patterns
6. Report findings

---

## 📞 Support Resources

- **MITRE ATT&CK**: https://attack.mitre.org
- **NIST CSF**: https://www.nist.gov/cyberframework
- **CIS Controls**: https://www.cisecurity.org
- **ISO 27001**: https://www.iso.org/isoiec-27001-information-security-management
- **OWASP**: https://owasp.org/Top10/
- **VirusTotal**: https://www.virustotal.com

---

## ✅ Ready to Start

You now have:
- ✅ Access to all 8 specialized views
- ✅ Real-time threat detection
- ✅ Framework compliance tracking
- ✅ Advanced threat intelligence
- ✅ Automated response capabilities
- ✅ 24/7 monitoring ready

**Start exploring the platform now!**

Begin with the **SOC Dashboard** to see live threats, then explore other tabs based on your role (analyst, compliance officer, architect, or threat hunter).

---

**Version**: 2.0 Enterprise  
**Platform**: SentinelGrid  
**Status**: Ready to Use ✅
