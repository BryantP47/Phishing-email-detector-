# Phishing Email Detector

Analyzes raw emails (`.eml`) and flags phishing using **explainable heuristic rules**,
optionally blended with a **Naive Bayes text classifier** you train on your own data.
Pure Python 3.9+, no third-party dependencies.

## Quick start

```bash
python -m phishing_detector analyze samples/
python -m phishing_detector analyze suspicious.eml --json
```

```
samples/phishing/paypal_account_suspended.eml: PHISHING (score 100%)
  Subject: URGENT: Your account has been suspended
  From:    service@paypa1-secure.com
  [content   ] +3.5  Contains threat language: 'account has been suspended', ...
  [header    ] +3.0  Sender domain 'paypa1-secure.com' imitates 'paypal'
  [url       ] +3.0  Link text shows 'paypal.com' but points to '192.168.45.10'
  [header    ] +2.5  DMARC check result: fail
  ...
```

Each email gets a verdict — `legitimate` (< 40%), `suspicious` (40–70%) or `phishing` (≥ 70%) —
and a list of findings explaining why. The exit code is `1` if any email is
phishing, `2` on errors, otherwise `0`, so it can be used in scripts.

Install as a command with `pip install .` to get `phishing-detector`.

## What it checks

| Category | Indicators |
|---|---|
| Headers | SPF / DKIM / DMARC failures, Reply-To and Return-Path domain mismatch, display-name spoofing (brand name or address in the display name), lookalike sender domains (`paypa1.com`, `rnicrosoft.com`), high-risk sender TLDs |
| Links | Link text showing one domain but pointing to another, raw IP addresses, punycode domains, URL shorteners, `user@host` tricks, high-risk TLDs, excessive subdomains, lookalike brand domains, `data:`/`javascript:` links, plain-HTTP login links, embedded HTML forms, brand mentioned with off-brand links |
| Content | Urgency, threats (account suspension), credential requests, financial lures (prizes, gift cards, wire transfers), generic greetings, all-caps subjects, fake `RE:` replies |
| Attachments | Executable / script-capable types, double extensions (`invoice.pdf.exe`), archives |

Rule weights are summed and mapped to a 0–1 score with a logistic curve
(see `phishing_detector/detector.py`).

## Training the model

The rules work out of the box. To add a statistical model, train on labelled data:

```bash
# CSV with a text column (text/body/email/message), a label column
# (label/class/is_phishing: phishing|legitimate, 1|0, spam|ham), optional subject
python -m phishing_detector train samples/training_data.csv --out model.json

# ...or a directory containing phishing/ and legitimate/ (or ham/) folders of .eml files
python -m phishing_detector train path/to/corpus --out model.json

python -m phishing_detector analyze inbox/ --model model.json --model-weight 0.4
python -m phishing_detector evaluate test.csv --model model.json
```

`samples/training_data.csv` is a tiny synthetic demo set; for real use, train on
a larger corpus such as a public phishing/ham email dataset or your own labelled mail.

## Python API

```python
from phishing_detector import PhishingDetector

detector = PhishingDetector()            # or PhishingDetector.with_model_file("model.json")
result = detector.analyze_file("message.eml")
print(result.verdict, result.score)
for finding in result.findings:
    print(finding.weight, finding.description)
```

## Tests

```bash
python -m unittest discover -s tests -t .
```

## Limitations

Heuristics are signals, not proof: legitimate bulk mail can trip some rules, and
targeted phishing from compromised legitimate accounts may pass them. Domain
handling uses a simplified eTLD+1 approximation rather than the full Public
Suffix List, and links are analyzed statically (no URLs are fetched).

---

# Malware Analysis Sandbox

`malware_sandbox` triages suspicious files, such as the attachments the phishing
detector flags. It does **static analysis** in pure Python, with no
dependencies and nothing executed. It can also do **dynamic analysis**: it
runs the sample in a locked-down Docker container and records what it does.

```bash
python -m malware_sandbox analyze suspicious.bin
python -m malware_sandbox analyze samples/phishing/invoice_malware.eml   # unpacks and scans attachments
python -m malware_sandbox analyze downloads/ --json --out report.json

python -m malware_sandbox build-image                                     # once, needs Docker
python -m malware_sandbox analyze samples/sandbox/fake_dropper.sh --dynamic
```

```
samples/sandbox/fake_dropper.sh: MALICIOUS (score 100%)
  Type:    Bash script [bash], 709 bytes, entropy 4.93
  [script   ] +5.0  Opens a reverse shell: '/dev/tcp/203.0.113.10/4444'
  [behavior ] +4.0  Writes shell profile: /tmp/home/.bashrc
  [behavior ] +3.0  Executes a file it dropped: /tmp/.cache-update
  [behavior ] +3.0  Deletes its own file after starting
  [behavior ] +2.0  Attempts outbound connection to 203.0.113.10:4444
  ...
  Dynamic analysis:
    exit code 0 after 0.4s in image malware-sandbox:latest
    processes: /bin/bash ./sample; chmod +x /tmp/.cache-update; /tmp/.cache-update; uname -a; ...
    network: connect 203.0.113.10:4444 (ENETUNREACH)
    files_deleted: /tmp/work/sample
```

Each file gets a verdict of `clean` (< 40%), `suspicious` (40–70%) or `malicious` (≥ 70%),
plus its hashes, findings, IOCs (URLs, IPs, domains, registry keys, wallets) and
format-specific details. Archives and e-mails are scored by their own
findings plus those of their most suspicious member. The exit code is `1` if any file is
malicious and `2` on errors.

## Static analysis

| Format | What is checked |
|---|---|
| All files | MD5/SHA1/SHA256, real type from magic bytes, entropy, ASCII + UTF-16 strings, IOCs, built-in signatures (EICAR, Mimikatz, Meterpreter, Cobalt Strike, Mirai, XMRig, ransom notes, web shells), optional YARA rules (`--yara rules.yar`, needs `pip install yara-python`), double extensions, RTLO tricks, extension vs. content mismatch |
| Windows PE | Header, sections, imports; packer section names, high-entropy / writable+executable sections, odd entry point, tiny import tables, API combinations for process injection, keylogging, anti-debugging, downloading, crypto, services, privileges |
| Linux ELF | Architecture, interpreter, UPX packing, stripped / missing section headers, executable stack, IoT architectures |
| Office | VBA macro source extracted and decompressed from OLE and OOXML files (MS-OVBA), auto-exec macros, shell/download/API calls, remote template injection, DDE, ActiveX, embedded objects, Equation Editor exploits (RTF/OLE) |
| PDF | `/OpenAction`, `/AA`, `/JavaScript`, `/Launch`, embedded files, XFA, hex-escaped names; FlateDecode streams inflated to find hidden JavaScript and exploit APIs (`util.printf`, `Collab.getIcon`, heap spray) |
| Scripts | PowerShell, VBScript, JScript, batch, shell, Python, HTA and HTML: download cradles, `-EncodedCommand` (decoded and re-scanned), base64 blobs, AMSI/Defender tampering, LOLBins, persistence, reverse shells, ransomware commands, miners, HTML smuggling |
| Containers | ZIP/JAR, gzip, tar and `.eml` files are unpacked in memory and analyzed recursively. The analyzer checks for encrypted archives, path traversal and zip bombs, and enforces size, member and depth limits. For e-mails, it also reports the phishing detector's verdict on the message. |

## Dynamic analysis (`--dynamic`)

ELF binaries and shell, bash, Python and Perl scripts are run under `strace`
inside the `malware-sandbox` image. Windows binaries and documents get static
analysis only. The container runs with:

- `--network none`: there is no network. Connection attempts are still logged
  (for example `ENETUNREACH`).
- `--read-only` root filesystem. Only a 64 MB `/tmp` tmpfs is writable.
- `--cap-drop ALL`, `--security-opt no-new-privileges`, and a non-root user (uid 1000).
- Memory, CPU, PID, open-file and file-size limits, and a hard kill on timeout (`--timeout`, default 30 s).
- The sample is mounted read-only. Only the syscall trace, stdout/stderr and a
  list of created files (path, size, SHA256) come back to the host. Dropped
  files themselves are never copied out.

The syscall trace becomes behavior findings: spawned processes and their
command lines, network connections, dropped and executed files, persistence
(cron, systemd, shell profiles, `authorized_keys`, `ld.so.preload`),
credential reads, self-deletion, anti-debugging (`PTRACE_TRACEME`), process
renaming, fileless execution (`memfd_create`), privilege escalation attempts
and fork bombs.

> **Isolation caveat:** containers share the host kernel. Only detonate real
> malware on a disposable machine or VM. For stronger isolation, use gVisor
> (`--runtime runsc`). To support more formats, extend
> `malware_sandbox/docker/Dockerfile`, for example with Node.js or Wine.

Run the Docker integration tests with `SANDBOX_DOCKER_TESTS=1 python -m unittest discover tests`
after building the image. `samples/sandbox/fake_dropper.sh` is a harmless
script that only imitates dropper behavior, for demos.
