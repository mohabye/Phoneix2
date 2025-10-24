# Phoneix2 - Advanced Linux Forensic Artifact Collector

**Phoneix2** is a **next-generation, modular, Bash-powered forensic artifact collection framework** designed for **incident response**, **threat hunting**, **digital forensics**, and **security auditing** on modern Linux systems.

Built from the ground up with **forensic integrity**, **performance efficiency**, and **analyst usability** in mind, Phoneix2 enables rapid, comprehensive, and repeatable collection of high-value artifacts across the entire system — all in **structured, analysis-ready CSV format**.

Whether you're investigating a breach, hunting for persistence, or conducting a compliance audit, **Phoneix2 gives you the visibility you need — fast.**

---

**Features**

### Comprehensive Artifact Collection

| Category | What’s Collected |
|--------|------------------|
| **Process Intelligence** | Full process tree, PID/PPID, user, CPU/mem, full command line (`/proc/$pid/cmdline`), environment variables, memory maps (`/proc/$pid/maps`), loaded libraries (`ldd`), Linux capabilities, **fileless malware detection** via `(deleted)` executables |
| **Network Forensics** | Active TCP/UDP connections (`ss` or `netstat`), listening ports, ARP cache, routing tables, network interfaces, **VPN/tunnel detection** (tun/tap/wg/ppp), firewall rules (`iptables`, `ufw`), `/etc/hosts` |
| **DNS Intelligence** | DNS queries from `systemd-resolved` and syslog, `/etc/hosts` with **suspicious redirection detection**, `resolv.conf`, DNS cache stats |
| **User & Account Forensics** | `/etc/passwd`, `/etc/shadow` (password policy analysis), login history (`last`, `lastlog`), failed logins, sudoers config + logs, `.bash_history`, `.zsh_history`, SSH keys, currently logged-in users (`w`) |
| **Filesystem Forensics** | SUID/SGID binaries, world-writable directories, hidden files (`.files`), recently modified files (`-mtime -7`), large files in `/tmp`, `/var/tmp`, `/dev/shm` |
| **Service & Persistence** | SystemD units, timers, enabled state, `ExecStart`, user, SysV init scripts, cron jobs, startup scripts |
| **Log Analysis** | Auth logs (`auth.log`, `secure`), system logs (`syslog`, `messages`), kernel logs (`kern.log`, `dmesg`), cron execution, SSH login events |
| **Browser Forensics** | Firefox, Chrome, Chromium profile paths, `History`, `Cookies`, `places.sqlite`, `cookies.sqlite` — with size and modification time |
| **SSH Forensics** | `authorized_keys`, `known_hosts`, `sshd_config` parsing |
| **Persistence Hunting** | Cron jobs, SystemD timers, `/etc/rc*.d/`, user crontabs, `@reboot` entries |

---

### Advanced Analysis Features

- **CSV-Ready Output** — Every field sanitized for commas, newlines, quotes
- **File Hashing** — SHA256 (preferred) or MD5 for executables and binaries
- **Process Tree Visualization** — `bash(123) -> python(456) -> malicious.bin(789)`
- **Fileless Malware Detection** — Identifies running binaries marked `(deleted)`
- **Suspicious `/etc/hosts` Flagging** — Detects phishing-style redirects (e.g., `facebook.com → 192.168.1.100`)
- **Color-Coded Logging** — Real-time feedback with timestamps and severity
- **Timeout Protection** — Prevents hangs on large filesystems (10 min SUID scan, 5 min recent files)
- **Robust Error Handling** — `set -euo pipefail`, `|| true` fallbacks, privilege warnings

---

**Use Cases**

**Incident Response**  
> *“Was there a breach? What’s running? Who logged in? What changed?”*  
Phoneix2 answers all in under 5 minutes.

**Threat Hunting**  
> *“Are there backdoors? Hidden persistence? Fileless malware?”*  
Hunt with confidence using deep system introspection.

**Digital Forensics**  
> *“I need timeline, evidence, and integrity.”*  
Phoneix2 delivers forensically sound, timestamped, hashed artifacts.

**Security Auditing & Compliance**  
> *“Prove due diligence. Show no unauthorized access.”*  
Generate audit-ready reports in seconds.

**Red Team & Penetration Testing**  
> *“Did my payload persist? Is it detectable?”*  
Test your TTPs against real-world forensic tools.

---

**Requirements**

**Operating System**  
Any modern Linux distribution (Ubuntu, Debian, CentOS, RHEL, Kali, Fedora, etc.)

**Privileges**  
Root or `sudo` access **strongly recommended** for complete data collection  
> Without root: limited `/proc`, logs, SUID scanning, and password policy analysis

**Core Dependencies (usually pre-installed)**  
`ps`, `find`, `stat`, `awk`, `grep`, `cut`, `tr`, `readlink`, `date`, `basename`, `dirname`

**Optional (Greatly Enhances Output)**  
`lsof`, `ss`, `netstat`, `ip`, `journalctl`, `systemctl`, `last`, `lastlog`, `passwd`, `w`, `sha256sum`, `md5sum`, `timeout`, `systemd-resolve`, `resolvectl`, `nscd`, `ufw`

---

**Installation**

```bash
# Download the latest version
curl -fsSL https://raw.githubusercontent.com/mohabye/Phoneix2/main/Phoneix2.sh -o Phoneix2.sh

# Or clone the repo
git clone https://github.com/mohabye/Phoneix2.git
cd Phoneix2

# Make executable

chmod +x Phoneix2.sh

sudo ./Phoenix2.sh


```

<img width="1696" height="770" alt="image" src="https://github.com/user-attachments/assets/4ed2d472-a9fc-4c5a-be1b-2e25714ea6ca" />

<img width="1717" height="882" alt="image" src="https://github.com/user-attachments/assets/c7dae94e-b725-4025-9ed6-1007ee106521" />
