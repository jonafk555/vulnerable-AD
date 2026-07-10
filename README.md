<h1 align="center">
  VulnAD-Extended
  <br>
  <sub>Enhanced Vulnerable Active Directory Lab Builder</sub>
</h1>

<p align="center">
  An enhanced fork of <a href="https://github.com/wazehell/vulnerable-AD">VulnAD</a> (by wazehell/@safe_buffer) that provisions a comprehensive vulnerable Active Directory environment covering 30+ attack techniques for red-team training.
</p>

---

### Main Features

- **30+ attack surfaces** provisioned automatically in under 2 minutes
- **Randomized configuration** — every build produces a unique combination of vulnerable users, groups, ACLs, and credentials
- **Modular design** — skip any category with `-Skip*` flags (e.g. `-SkipADCS`, `-SkipDelegation`)
- **Environment-aware** — auto-detects OS version (Server 2019/2022/2025), AD CS installation, KDS Root Key, and LAPS schema before configuring relevant attacks
- **Server 2025 ready** — includes dMSA/BadSuccessor preconditions when running on build 26100+
- **Multi-tier ACL paths** — builds realistic BloodHound-discoverable attack chains (Normal → Mid → High groups)
- Run the script on a DC with Active Directory installed
- Some attacks require a client workstation (domain-joined)

### Supported Attacks

**Baseline (from original VulnAD)**

| Attack | Function |
|--------|----------|
| Abusing ACLs/ACEs (GenericAll, GenericWrite, WriteOwner, WriteDACL, Self, WriteProperty) | `VulnAD-BadAcls` |
| Kerberoasting (5 SPN accounts, 1 with weak password) | `VulnAD-Kerberoasting` |
| AS-REP Roasting (3-6 accounts, pre-auth disabled + weak passwords) | `VulnAD-ASREPRoasting` |
| Abuse DnsAdmins (direct members + nested group) | `VulnAD-DnsAdmins` |
| Password in Object Description (4-7 accounts, varied phrasing) | `VulnAD-PwdInObjectDescription` |
| User Objects with Default Password — `Changeme123!` (3-5 accounts) | `VulnAD-DefaultPassword` |
| Password Spraying — shared password `ncc1701` (8-13 accounts) | `VulnAD-PasswordSpraying` |
| DCSync rights granted to random users (2-4 accounts) | `VulnAD-DCSync` |
| SMB Signing Disabled (client + server) | `VulnAD-DisableSMBSigning` |
| Weak Password Policy (MinLen=4, Complexity=Off, Lockout=1min) | Main function |

**Extended — Kerberos Delegation**

| Attack | Function |
|--------|----------|
| Unconstrained Delegation (member server or placeholder) | `VulnAD-UnconstrainedDelegation` |
| Constrained Delegation — Protocol Transition / Any Auth (`svc_iis`) | `VulnAD-ConstrainedDelegation` |
| Constrained Delegation — Kerberos Only + weak password (`svc_web`) | `VulnAD-ConstrainedDelegation` |
| RBCD preconditions (MAQ=10, GenericWrite on computers) | `VulnAD-RBCDPrep` |
| Shadow Credentials preconditions (GenericAll on computers) | `VulnAD-ShadowCredentialsPrep` |

**Extended — Certificate Attacks**

| Attack | Function |
|--------|----------|
| AD CS ESC1/ESC4/ESC7 hints (if AD CS role installed) | `VulnAD-ADCSVulnerable` |

**Extended — Modern Service Accounts**

| Attack | Function |
|--------|----------|
| gMSA with excessive permissions (Domain Computers can read) | `VulnAD-VulnerableGMSA` |
| gMSA with correct scoping (control group for comparison) | `VulnAD-VulnerableGMSA` |
| dMSA / BadSuccessor CreateChild rights (Server 2025 only) | `VulnAD-DMSAPrep` |

**Extended — LAPS**

| Attack | Function |
|--------|----------|
| Over-privileged LAPS password read access | `VulnAD-VulnerableLAPS` |

**Extended — Legacy / Weak Settings**

| Attack | Function |
|--------|----------|
| Pre-Windows 2000 computer account (predictable password) | `VulnAD-Pre2kComputer` |
| Reversible Encryption enabled (cleartext via secretsdump) | `VulnAD-ReversibleEncryption` |
| GPP cpassword planted in SYSVOL (publicly known AES key) | `VulnAD-GPPPassword` |

**Extended — Coercion Preconditions**

| Attack | Function |
|--------|----------|
| Print Spooler enabled (PrinterBug / MS-RPRN) | `VulnAD-CoercionServices` |
| EFS enabled (PetitPotam / MS-EFSR) | `VulnAD-CoercionServices` |
| DFS Namespace enabled (DFSCoerce / MS-DFSNM) | `VulnAD-CoercionServices` |

**Extended — Persistence Preconditions**

| Attack | Function |
|--------|----------|
| AdminSDHolder ACL backdoor (GenericAll, propagates via SDProp) | `VulnAD-AdminSDHolderBackdoor` |
| Multi-hop ACL chain (A → B → C → Domain Admins) | `VulnAD-MultiHopACL` |

**Attacks enabled by the environment (not configured by script, performed by the student)**

| Attack | Precondition set by script |
|--------|---------------------------|
| Silver Ticket | Kerberoasting → service account hash |
| Golden Ticket | DCSync → krbtgt hash |
| Pass-the-Hash | DCSync or secretsdump → NTLM hash |
| Pass-the-Ticket | Ticket harvest from compromised host |
| Overpass-the-Hash | DCSync → AES key |
| NTLM Relay (SMB/LDAP/ADCS) | SMB Signing disabled + Coercion services |
| Printer Bug + Unconstrained | Unconstrained Delegation + Print Spooler |
| Shadow Credentials → PKINIT | GenericAll on computer object |
| RBCD → S4U | GenericWrite on computer + MAQ=10 |
| BadSuccessor (dMSA abuse) | CreateChild dMSA on OU (Server 2025) |

### Prerequisites

- Windows Server 2019 / 2022 / 2025 with AD DS role installed
- Run as **Domain Admin** on a Domain Controller
- PowerShell 5.1+ with RSAT-AD-PowerShell module
- (Optional) AD CS role for certificate attack labs
- (Optional) LAPS installed for LAPS abuse labs
- (Recommended) Domain-joined workstation for lateral movement labs

### Quick Start

```powershell
# If Active Directory is not installed yet:
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment
Install-ADDSForest `
    -DomainName "yourlab.local" `
    -DomainNetbiosName "YOURLAB" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -Force:$true
# Server will reboot automatically

# After AD is installed, run the script:
. .\VulnAD-Extended-EN.ps1
Invoke-VulnADExtended -DomainName "yourlab.local" -UsersLimit 100
```

### Selective Build

Skip specific modules if your lab doesn't need them or lacks prerequisites:

```powershell
# Skip AD CS (not installed) and dMSA (not Server 2025)
Invoke-VulnADExtended -DomainName "yourlab.local" -SkipADCS -SkipDMSA

# Minimal build: baseline only
Invoke-VulnADExtended -DomainName "yourlab.local" `
    -SkipDelegation -SkipADCS -SkipGMSA -SkipDMSA `
    -SkipLAPS -SkipLegacy -SkipCoercion -SkipPersistence

# Full build (default)
Invoke-VulnADExtended -DomainName "yourlab.local"
```

### Available Skip Flags

| Flag | What it skips |
|------|--------------|
| `-SkipDelegation` | Unconstrained, Constrained, RBCD, Shadow Credentials |
| `-SkipADCS` | AD CS template/ACL configuration |
| `-SkipGMSA` | gMSA over-privilege setup |
| `-SkipDMSA` | dMSA/BadSuccessor (auto-skipped if not Server 2025) |
| `-SkipLAPS` | LAPS over-privilege ACL |
| `-SkipLegacy` | Pre2k account, Reversible Encryption, GPP cpassword |
| `-SkipCoercion` | Print Spooler, EFS, DFS service enablement |
| `-SkipPersistence` | AdminSDHolder backdoor, Multi-hop ACL chain |
| `-SkipSMBSigning` | SMB signing disable |

### Post-Build Recommended Steps

```bash
# 1. Snapshot the DC immediately (baseline for reset between labs)

# 2. From Kali, run initial recon + BloodHound collection
bloodhound-python -u <any_sprayed_user> -p 'ncc1701' -d yourlab.local -ns <DC_IP> -c All

# 3. Work through the labs one by one

# 4. Revert to snapshot between exercises
```

### Environment Diagram

```
┌─────────────────────────────────────────────────────┐
│                   yourlab.local                     │
│                                                     │
│  DC01 (this script runs here)                       │
│  ├── 100 random users (firstname.lastname)          │
│  ├── 5 high/mid/normal groups with cross-ACLs       │
│  ├── 5 SPN service accounts (1 weak password)       │
│  ├── 3-6 AS-REP roastable accounts                  │
│  ├── 8-13 accounts sharing password "ncc1701"       │
│  ├── 3-5 accounts with default "Changeme123!"       │
│  ├── 4-7 accounts with password in description      │
│  ├── 2-4 accounts with DCSync rights                │
│  ├── 2-3 accounts with reversible encryption        │
│  ├── DnsAdmins (users + nested mid-tier group)      │
│  ├── Unconstrained Delegation computer              │
│  ├── Constrained Delegation (AnyAuth + KerbOnly)    │
│  ├── RBCD entry points (GenericWrite on computers)  │
│  ├── Shadow Credentials entry (GenericAll)           │
│  ├── gMSA over-privileged (Domain Computers)        │
│  ├── gMSA secure (control group)                    │
│  ├── Pre2k computer (password = "legacypc")         │
│  ├── GPP cpassword in SYSVOL                        │
│  ├── AdminSDHolder backdoor ACE                     │
│  ├── Multi-hop ACL chain (A→B→C→DA)                 │
│  ├── SMB Signing disabled                           │
│  └── Print Spooler / EFS / DFS enabled              │
│                                                     │
│  [Server 2025 only]                                 │
│  └── dMSA CreateChild rights on OU                  │
│                                                     │
│  [If AD CS installed]                               │
│  └── ESC hints (manual template setup required)     │
│                                                     │
│  SRV01 (optional member server)                     │
│  └── Used for delegation, lateral movement labs     │
│                                                     │
│  WS01 (optional workstation)                        │
│  └── Used for credential harvesting, token labs     │
│                                                     │
│  Kali (attacker)                                    │
│  └── Impacket, NetExec, BloodHound-python,          │
│      Certipy, kerbrute, Coercer, gMSADumper         │
└─────────────────────────────────────────────────────┘
```

### Credits

- Original VulnAD by [wazehell/@safe_buffer](https://github.com/wazehell/vulnerable-AD)
- Extended edition adds delegation, AD CS, gMSA/dMSA, LAPS, pre2k, reversible encryption, GPP, coercion, and persistence attack surfaces

### Disclaimer

**This tool creates an INTENTIONALLY vulnerable Active Directory environment.**

It is designed exclusively for authorized red-team training and security research in isolated lab environments. Never run this script on any network with real users, production data, or internet connectivity. The authors assume no liability for misuse.
