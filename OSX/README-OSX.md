````markdown
# WS-Man Passive Inspector — macOS Debug / Local Edition

> **Purpose:**  
> Provide a clean, local workflow for passive WS-Man (SOAP/HTTP) and general HTTP/TLS capture on macOS.  
> No NFQUEUE, no packet injection — just libpcap/BPF sniffing for defender debugging and development.

---

## 🧩 Environment Setup (macOS)

1. **Install dependencies**
   ```bash
   brew install python@3.12 wireshark  # Wireshark gives you libpcap + optional tshark
   /usr/local/opt/python@3.12/bin/pip3 install scapy lxml pyshark
````

*Note*: macOS doesn’t support Linux NFQUEUE; use libpcap/BPF instead.

2. **Confirm Python location**

   ```bash
   which python3
   python3 --version
   ```

3. **Run Python with elevated privileges when sniffing**

   ```bash
   sudo python3 <script>.py
   ```

---

## 🧠 Quick BPF Debug Test (HTTP + HTTPS)

Use the included **`bpf_port_test.py`** for verifying that your BPF filter works and your interface sees traffic.

```bash
sudo python3 bpf_port_test.py --iface en0 --ports 80,443
[+] Starting BPF sniff (filter: "tcp port 80 or tcp port 443") on iface=en0; Ctrl-C to stop
2025-10-29T11:41:55.257099Z 10.0.0.0:61361 -> 8.8.8.8:443 len=1514 flags=A TLS: ClientHello
```

### Expected output

When you browse the web or use `curl`:

```
2025-10-29T12:34:56Z 10.0.0.5:54321 -> 8.8.8.8:80 len=150 flags=PA HTTP: GET / HTTP/1.1
2025-10-29T12:35:01Z 10.0.0.5:54322 -> 8.8.8.8:443 len=517 flags=PA TLS: ClientHello
```

If you see these, BPF is functioning correctly.

If **no output**:

* Check your interface (`ifconfig` to list, likely `en0` or `en1`).
* Try `sudo python3 bpf_port_test.py --iface any` to sniff all interfaces.
* Generate test traffic:

  ```bash
  curl http://example.com/
  curl -k https://example.com/
  ```

---

## 🔍 Passive WS-Man (SOAP) Sniffing

To test WS-Man/WinRM/WSUS style traffic passively (no interception), use:

```bash
sudo python3 wsman_nfqueue.py --iface en0 --out /tmp/wsman_netlog.jsonl
```

* Default ports: 5985 (HTTP), 8530 (WSUS HTTP)
* Output: `/tmp/wsman_netlog.jsonl`
* Captures HTTP payloads containing `<Envelope>` and `<Body>` XML
* Redacts sensitive fields (`Password`, `Credential`, `BinarySecurityToken`)

> **Tip:** If you only want live output (no file), run with:
>
> ```bash
> tail -f /tmp/wsman_netlog.jsonl
> ```

---

## 🔧 Offline Capture / Analysis

You can also capture traffic first, then analyze it later.

1. **Capture raw packets**

   ```bash
   sudo tcpdump -i en0 -w wsman.pcap 'tcp port 5985 or tcp port 8530'
   ```
2. **Extract SOAP envelopes**

   ```bash
   python3 wsman_pcap-extract-offline.py wsman.pcap --out wsman_extracted.jsonl
   ```

---

## 🧪 Local Verification Routine

Use this 3-step flow to confirm your full macOS pipeline:

| Step | Command                                                | Expected Result                      |
| ---- | ------------------------------------------------------ | ------------------------------------ |
| 1    | `sudo python3 tiny_bpf_port_test.py --iface en0`            | See live HTTP/TLS packet lines       |
| 2    | `curl http://example.com`                              | HTTP GET logged in script output     |
| 3    | `curl -k https://example.com`                          | TLS ClientHello logged               |
| 4    | `sudo python3 wsman_nfqueue.py --iface en0`          | Logs SOAP envelopes if any exist     |
| 5    | `sudo tcpdump -n -i en0 'tcp port 80 or tcp port 443'` | tcpdump output matches Python output |

If all five steps produce visible output, your capture layer (BPF) is working perfectly.

---

## 🧱 Troubleshooting

**No packets captured**

* Use `sudo` — macOS restricts raw socket capture.
* Try another interface (`en0`, `en1`, `lo0`, `bridge100`, etc.).
* Disable VPNs or adjust filters; some VPNs tunnel traffic away from en0.

**Permission errors**

* You must run as root or have `pcap` device permissions.
  If you see `Permission denied`, re-run with `sudo`.

**TLS decryption**

* The scripts detect ClientHello but don’t decrypt HTTPS.
  For decryption, capture a keylog (`SSLKEYLOGFILE`) and use Wireshark.

---

## 🧭 Cleanup

No files are written except optional JSONL logs under `/tmp` if you specify `--out`.
To remove:

```bash
sudo rm /tmp/wsman_netlog.jsonl
sudo rm /tmp/wsman_extracted.jsonl
```

---

## ⚙️ Summary

| Component                       | Role                           | macOS Status    |
| ------------------------------- | ------------------------------ | --------------- |
| `netfilterqueue`                | Linux-only packet interception | ❌ Not available |
| `libpcap/BPF`                   | Passive sniffing               | ✅ Works         |
| `tiny_bpf_port_test.py`         | Debug ports 80/443             | ✅ Works         |
| `wsman_nfqueue.py`            | Passive WS-Man SOAP logger     | ✅ Works         |
| `wsman_pcap-extract.py` | Offline SOAP extractor         | ✅ Works         |

---

## 🧩 Next Steps

* If you migrate to a Linux gateway later, swap in `passive_wsman_nfqueue.py` for NFQUEUE mode.
* Keep macOS for analysis and validation, using `tcpdump` + offline extraction for safe review.

---

## 🛡️ Legal & Safety Notice

This toolkit is **defensive** and **passive**.
Use it **only** on systems and networks you own or have explicit written authorization to inspect.
Do not modify or replay captured traffic.

## License
This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2025 wsman-guardian contributors
---

**Author:** Internal Defender Tools Team
**Platform:** macOS / Linux
**License:** MIT (recommended)

```

---

Author: ~Rali0s/3XC
Platform: macOS / Linux
License: MIT

```
