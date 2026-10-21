#!/usr/bin/env python3
# PhoneHackScan - Android & iPhone intrusion check, powered by UCYBERS
# Copyright (C) 2026 UCYBERS
#
# This program is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 3 as published by the Free Software
# Foundation, with the additional terms below, which are permitted by section 7 of
# that licence.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details. You should
# have received a copy of it with this program (the LICENSE file); if not, see
# <https://www.gnu.org/licenses/>.
#
# Additional terms (GNU GPL version 3, section 7) - also in the NOTICE file:
#  a) Attribution (section 7b). Every copy or modified version of this program that
#     you convey, free of charge or for a fee, must keep the attribution
#     "powered by UCYBERS" in the program's start banner and in every report the
#     program produces. It must stay clearly visible and readable: not removed,
#     hidden, shrunk, or coloured to blend into the background.
#  b) Modified versions (section 7c). A modified version that you convey must be
#     clearly marked as different from the original and must not be named
#     PhoneHackScan.
#  c) Names and logo (section 7e). This licence grants no right to use the names
#     PhoneHackScan or UCYBERS, or the UCYBERS logo, as trademarks, except as needed
#     to give the attribution required in (a).
#
# The Cairo font embedded in the report (CAIRO_WOFF2) is not covered by the GPL: it is
# under the SIL Open Font License 1.1, whose full text is at the end of this file.
"""
PhoneHackScan — scan Android phones and iPhones for signs of hacking (spyware / stalkerware).
Runs on Windows, macOS and Linux.

Layers
  1. Quick check over adb: device admins, accessibility services, notification
     readers, keyboards, VPN/proxy, hidden and sideloaded apps.
  2. Full collection with androidqf + analysis with MVT against public spyware
     indicators (Pegasus, Predator, 100+ stalkerware families, ...).
  3. VirusTotal (optional): file hash of every non-system app.
  4. Android 16 Intrusion Logging: analyse logs downloaded from the phone.
  5. Expert package: bundle (optionally age-encrypted) a scan for a helpline.
  6. iPhone: MVT analysis of an encrypted computer backup (Apple Devices / iTunes /
     Finder / idevicebackup2), decrypted temporarily and deleted afterwards.
Output: HTML report (Arabic / English, one click to switch) in ~/phonehackscan/scan-<date>/report.html

Privacy: no phone data leaves this computer. Network use is limited to
downloading the tools and public indicator lists (Google, GitHub, PyPI) and,
only if you enable it, sending app file hashes to VirusTotal. MVT runs with
network access off, so links found in your SMS are never opened.
No apps are installed and no settings or personal data are changed on the phone. During
collection androidqf copies a small helper program to the phone's temporary folder
(/data/local/tmp) and deletes it when it finishes.

Usage
  python phonehackscan.py                        menu (Android / iPhone / quick check)
  python phonehackscan.py --quick                quick check only (about one minute)
  python phonehackscan.py --no-vt                full Android scan without VirusTotal
  python phonehackscan.py --intrusion-logs PATH  analyse Intrusion Logging files (.zip or folder)
  python phonehackscan.py --iphone [FOLDER]      analyse an iPhone backup (found automatically)
  python phonehackscan.py --open-app PACKAGE     open an app's page on the phone to review / uninstall it
  python phonehackscan.py --package [AGE_KEY]    bundle the latest scan for a security expert
On Windows you can also double-click phonehackscan.cmd.
"""

import argparse
import datetime
import getpass
import glob
import hashlib
import html
import json
import os
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
import zipfile
from pathlib import Path

if sys.version_info < (3, 10):
    sys.exit("Python 3.10 or newer is required: https://www.python.org/downloads/")

AQF_FALLBACK_VER = "1.8.3"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
# Indicators are refreshed explicitly in ensure_mvt(), so the analysis itself stays offline.
MVT_QUIET = ["--disable-update-check", "--disable-indicator-update-check"]

IS_WIN = os.name == "nt"
OFFLINE = os.environ.get("ANDROID_SCAN_OFFLINE") == "1"   # skip all downloads (testing)
def _default_base():
    new = Path.home() / "phonehackscan"
    if new.exists():
        return new
    for old in ("android-scan", "phonehackscan"):   # folders of earlier versions: tools, saved key, past scans
        if (Path.home() / old).is_dir():
            return Path.home() / old
    return new


BASE = Path(os.environ.get("ANDROID_SCAN_HOME") or _default_base())
TOOLS = BASE / "tools"

# --------------------------------------------------------------------------- #
#  Console helpers
# --------------------------------------------------------------------------- #
if IS_WIN:
    os.system("")  # turns on ANSI colours in Windows 10+ consoles
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass
_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def step(msg): print("\n" + _c("1", "==> " + msg), flush=True)
def info(msg): print("    " + msg, flush=True)
def ok(msg): print("    " + _c("32", "[ok] " + msg), flush=True)
def warn(msg): print("    " + _c("33", "[!] " + msg), flush=True)


class Fatal(Exception):
    pass


def die(msg):
    raise Fatal(msg)


def interactive():
    return sys.stdin is not None and sys.stdin.isatty()


def pause():
    if interactive():
        try:
            input("    Press Enter to continue (Ctrl+C to stop)... ")
        except EOFError:
            pass


def ask(question, default="n"):
    answer = ""
    if interactive():
        try:
            answer = input(f"    {question} ").strip()
        except EOFError:
            answer = ""
    return (answer or default).lower() in ("y", "yes")


# --------------------------------------------------------------------------- #
#  Platform
# --------------------------------------------------------------------------- #
class Plat:
    def __init__(self, system=None, machine=None):
        system = system or platform.system()
        machine = (machine or platform.machine()).lower()
        self.system = system
        if system == "Windows":
            self.pt_os, self.aqf, self.exe = "windows", "windows_amd64", ".exe"
        elif system == "Darwin":
            self.pt_os, self.aqf, self.exe = "darwin", "macos_universal", ""
        elif system == "Linux":
            self.pt_os, self.exe = "linux", ""
            if machine in ("x86_64", "amd64"):
                self.aqf = "linux_amd64"
            elif machine in ("aarch64", "arm64"):
                self.aqf = "linux_arm64"
            else:
                die(f"Unsupported CPU architecture: {machine}")
        else:
            die(f"Unsupported operating system: {system}")

    @property
    def windows(self):
        return self.system == "Windows"

    def venv_bin(self, venv, name):
        return Path(venv) / ("Scripts" if self.windows else "bin") / (name + self.exe)


def pick_aqf_asset(release_json, plat):
    """Return the download URL of the androidqf binary for this platform, or None."""
    try:
        data = json.loads(release_json)
    except Exception:
        return None
    for a in data.get("assets", []):
        n = a.get("name", "")
        if not n.startswith(f"androidqf_{plat.aqf}_"):
            continue
        if plat.windows == n.endswith(".exe"):
            return a.get("browser_download_url")
    return None


def fallback_aqf_name(plat, ver=AQF_FALLBACK_VER):
    if plat.windows:
        return f"androidqf_windows_amd64_{ver}_unsigned.exe"
    if plat.aqf == "macos_universal":
        return f"androidqf_macos_universal_{ver}_signed"
    return f"androidqf_{plat.aqf}_{ver}"


def expected_checksum(sums_text, asset_name):
    """Find the SHA-256 for an asset in checksums.txt. The Windows release file is
    renamed with an "_unsigned" suffix after the checksums are made, so the
    original name is tried too. The signed macOS binary has no published checksum."""
    names = [asset_name, asset_name.replace("_unsigned", "")]
    for line in (sums_text or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] in names:
            return parts[0].lower()
    return None


# --------------------------------------------------------------------------- #
#  Network helpers (curl first: it uses the system certificate store everywhere,
#  including Windows 10+, which ships curl.exe; urllib as a fallback)
# --------------------------------------------------------------------------- #
def download(url, dest):
    curl = shutil.which("curl")
    if curl and subprocess.run([curl, "-fL", "--progress-bar", "-o", str(dest), url]).returncode == 0:
        return
    try:
        with urllib.request.urlopen(url, timeout=300) as resp, open(dest, "wb") as f:
            shutil.copyfileobj(resp, f)
    except Exception as e:
        die(f"Could not download {url}: {e}")


def fetch_text(url):
    curl = shutil.which("curl")
    if curl:
        r = subprocess.run([curl, "-fsSL", url], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return None


def http_get_with_key(url, header, value):
    """GET url with a secret header; returns (status, body). Status 0 = unreachable.
    With curl the header is passed on stdin so the key never shows in the process list."""
    curl = shutil.which("curl")
    if curl:
        r = subprocess.run([curl, "-s", "--max-time", "30", "-K", "-", "-w", "\n%{http_code}", url],
                           input=f'header = "{header}: {value}"\n', capture_output=True,
                           text=True, encoding="utf-8", errors="replace")
        body, _, code = r.stdout.rpartition("\n")
        try:
            return int(code.strip() or 0), body
        except ValueError:
            return 0, ""
    try:
        req = urllib.request.Request(url, headers={header: value})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def http_status_with_key(url, header, value):
    return http_get_with_key(url, header, value)[0]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_executable(path):
    if not IS_WIN:
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# --------------------------------------------------------------------------- #
#  Tools
# --------------------------------------------------------------------------- #
class Tools:
    def __init__(self, plat):
        self.plat = plat
        self.adb = self.aqf = self.mvt = self.mvt_ios = self.venv = self.venv_python = None

    # adb ------------------------------------------------------------------- #
    def ensure_adb(self):
        p = self.plat
        local = TOOLS / "platform-tools" / ("adb" + p.exe)
        if os.environ.get("ADB_BIN"):
            adb = os.environ["ADB_BIN"]
        elif shutil.which("adb"):
            adb = shutil.which("adb")
        elif local.exists():
            adb = str(local)
        else:
            if OFFLINE:
                die("adb not found (offline mode).")
            if p.aqf == "linux_arm64":
                die("Google does not publish adb for Linux ARM. Install it with your package "
                    "manager (e.g. sudo apt install adb) and run again.")
            info("Downloading Android platform-tools (adb) from Google...")
            z = TOOLS / "platform-tools.zip"
            download(f"https://dl.google.com/android/repository/platform-tools-latest-{p.pt_os}.zip", z)
            with zipfile.ZipFile(z) as zf:
                zf.extractall(TOOLS)
            z.unlink()
            make_executable(local)
            adb = str(local)
        # androidqf looks for adb on PATH first, so both tools share one adb server.
        os.environ["PATH"] = str(Path(adb).resolve().parent) + os.pathsep + os.environ.get("PATH", "")
        self.adb = adb
        ok(f"adb: {adb}")

    # androidqf ------------------------------------------------------------- #
    def ensure_androidqf(self):
        p = self.plat
        if os.environ.get("AQF_BIN"):
            self.aqf = os.environ["AQF_BIN"]
            ok(f"androidqf: {self.aqf}")
            return
        existing = sorted(f for f in glob.glob(str(TOOLS / f"androidqf_{p.aqf}_*")) if not f.endswith(".part"))
        if OFFLINE:
            if not existing:
                die("androidqf not found (offline mode).")
            self.aqf = existing[-1]
            ok(f"androidqf: {self.aqf}")
            return

        url = pick_aqf_asset(fetch_text("https://api.github.com/repos/mvt-project/androidqf/releases/latest") or "", p)
        if not url:
            ver = AQF_FALLBACK_VER
            url = f"https://github.com/mvt-project/androidqf/releases/download/v{ver}/{fallback_aqf_name(p, ver)}"
        name = url.rsplit("/", 1)[-1]
        target = TOOLS / name
        if not target.exists():
            info(f"Downloading {name} ...")
            part = target.with_name(name + ".part")
            download(url, part)
            expected = expected_checksum(fetch_text(url.rsplit("/", 1)[0] + "/checksums.txt"), name)
            if expected:
                if sha256_file(part) != expected:
                    part.unlink()
                    die("androidqf checksum mismatch. Download removed.")
                ok("androidqf checksum verified")
            elif p.system == "Darwin":
                self._verify_macos_signature(part)
            else:
                part.unlink()
                die(f"Could not verify androidqf (no checksum published for {name}).")
            part.replace(target)
            make_executable(target)
        self.aqf = str(target)
        ok(f"androidqf: {self.aqf}")

    @staticmethod
    def _verify_macos_signature(path):
        if subprocess.run(["codesign", "--verify", "--strict", str(path)], capture_output=True).returncode != 0:
            path.unlink()
            die("androidqf code signature is not valid. Download removed.")
        out = subprocess.run(["codesign", "-dv", "--verbose=2", str(path)], capture_output=True, text=True).stderr
        m = re.search(r"^Authority=(.+)$", out, re.M)
        signer = m.group(1) if m else ""
        if signer.startswith("Developer ID Application"):
            ok(f"androidqf code signature verified ({signer})")
        else:
            warn(f"androidqf is signed, but not with an Apple Developer ID ({signer or 'ad-hoc'}).")
            if not ask("Type yes to continue anyway:", "n"):
                path.unlink()
                die("Stopped.")

    # Python venv + MVT ------------------------------------------------------- #
    def ensure_venv(self):
        venv = Path(os.environ.get("MVT_VENV") or TOOLS / "mvt-venv")
        py = self.plat.venv_bin(venv, "python")
        if not py.exists():
            if OFFLINE:
                die("Python environment not found (offline mode).")
            r = subprocess.run([sys.executable, "-m", "venv", str(venv)])
            if r.returncode != 0 or not py.exists():
                die("Could not create a Python virtual environment."
                    + ("" if IS_WIN else " On Debian/Ubuntu run: sudo apt install python3-venv"))
        self.venv = venv
        self.venv_python = str(py)

    def pip_install(self, *packages):
        r = subprocess.run([self.venv_python, "-m", "pip", "install", "--quiet",
                            "--disable-pip-version-check", "--upgrade", *packages])
        if r.returncode != 0:
            die(f"Could not install {' '.join(packages)} with pip.")

    def ensure_mvt(self):
        self.ensure_venv()
        self.mvt = str(self.plat.venv_bin(self.venv, "mvt-android"))
        self.mvt_ios = str(self.plat.venv_bin(self.venv, "mvt-ios"))
        pip_mark, ioc_mark = TOOLS / ".mvt_updated", TOOLS / ".iocs_updated"
        if not OFFLINE:
            if Path(self.mvt).exists() and _fresh(pip_mark, 24):
                info("MVT was updated less than a day ago.")
            else:
                info("Installing / updating MVT (first run takes a minute)...")
                self.pip_install("mvt")
                _touch(pip_mark)
        if not Path(self.mvt).exists():
            die(f"mvt-android not found in {self.venv}")
        if not OFFLINE:
            if _fresh(ioc_mark, 12):
                info("Spyware indicators were updated less than 12 hours ago.")
            else:
                info("Downloading the latest public spyware indicators (IOCs), usually 1-3 minutes...")
                n = self._download_iocs()
                if n:
                    ok(f"{n} indicator files downloaded")
                    _touch(ioc_mark)
                else:
                    warn("Could not update indicators; MVT will use the ones it already has.")
        out = subprocess.run([self.mvt, "version"], capture_output=True, text=True).stdout
        m = re.search(r"\d{4}\.\d+\.\d+", out)
        ok(f"MVT: {m.group(0) if m else 'installed'}")

    def _download_iocs(self):
        """Run 'mvt-android download-iocs' and show a live count instead of silence."""
        env = dict(os.environ, COLUMNS="250")
        proc = subprocess.Popen([self.mvt, "download-iocs"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", env=env)
        n = 0
        for line in proc.stdout:
            if "Downloaded indicators" in line:
                n += 1
                print(f"\r    {n} files downloaded...", end="", flush=True)
        proc.wait()
        if n:
            print("\r" + " " * 40 + "\r", end="", flush=True)
        return n


def _fresh(marker, hours):
    try:
        return time.time() - marker.stat().st_mtime < hours * 3600
    except OSError:
        return False


def _touch(marker):
    marker.write_text(datetime.datetime.now().isoformat(timespec="seconds"))


# --------------------------------------------------------------------------- #
#  VirusTotal
# --------------------------------------------------------------------------- #
def _prompt_vt_key():
    """Hidden prompt. Cleans what was pasted (spaces, line breaks, stray control
    characters such as a literal Ctrl+V) and checks it looks like a VirusTotal key."""
    for _ in range(3):
        try:
            raw = getpass.getpass("    Paste your VirusTotal API key (or press Enter to skip): ")
        except EOFError:
            return ""
        if not raw.strip():
            return ""
        key = re.sub(r"[^0-9A-Za-z]", "", raw)
        if re.fullmatch(r"[0-9a-fA-F]{64}", key):
            info(f"Key received: {key[:4]}...{key[-4:]} (64 characters)")
            return key
        warn(f"That does not look like a VirusTotal API key: {len(key)} characters received, 64 expected.")
        info("Copy it again from virustotal.com > your profile picture > API key.")
        info("If Ctrl+V does nothing in this window, right-click inside it to paste.")
    return ""


def _vt_status(key):
    # One test lookup (the EICAR test file) so a wrong key does not break the analysis later.
    return http_status_with_key(f"https://www.virustotal.com/api/v3/files/{EICAR_SHA256}", "x-apikey", key)


VT_STATUS = ["skipped"]   # why VirusTotal was not used, for the report


def setup_vt(enabled):
    keyfile = BASE / ".vt_api_key"
    if not enabled:
        info("VirusTotal: off (--no-vt)")
        VT_STATUS[0] = "off"
        return ""
    key, typed = os.environ.get("MVT_VT_API_KEY", "").strip(), False
    if not key and keyfile.exists():
        key = keyfile.read_text().strip()
    if not key and interactive():
        info("Optional: check every installed app on VirusTotal (~70 antivirus engines).")
        info("Free key: sign in at virustotal.com > your profile picture > API key.")
        key, typed = _prompt_vt_key(), True

    while key and not OFFLINE:
        code = _vt_status(key)
        if code in (200, 404):
            break
        if code in (401, 403):
            warn(f"VirusTotal rejected the key ending in ...{key[-4:]} (HTTP {code}).")
            VT_STATUS[0] = "rejected"
            if interactive() and ask("Try another key? [y/N]", "n"):
                key, typed = _prompt_vt_key(), True
                continue
        elif code == 429:
            warn("VirusTotal quota for this key is used up for now (500 lookups a day on free keys).")
            VT_STATUS[0] = "quota"
        else:
            warn(f"Could not reach VirusTotal (HTTP {code or 'none'}).")
            VT_STATUS[0] = "unreachable"
        key = ""

    if key and typed and ask("Save the key for next time (readable only by your user)? [y/N]", "n"):
        keyfile.write_text(key)
        if not IS_WIN:
            os.chmod(keyfile, 0o600)
        ok(f"Saved to {keyfile}")
    if key:
        ok("VirusTotal: on (only app file hashes are sent, never the apps or your data)")
    else:
        info("VirusTotal: skipped. The scan continues without it.")
    return key


# --------------------------------------------------------------------------- #
#  Phone connection
# --------------------------------------------------------------------------- #
def wait_for_device(adb, plat):
    subprocess.run([adb, "start-server"], capture_output=True)
    last = None
    while True:
        out = subprocess.run([adb, "devices"], capture_output=True, text=True).stdout.replace("\r", "")
        rows = [l.split() for l in out.splitlines()[1:] if len(l.split()) >= 2]
        ready = [r[0] for r in rows if r[1] == "device"]
        if len(ready) == 1:
            ok(f"Phone connected (serial {ready[0]})")
            return ready[0]
        if len(ready) > 1:
            state = "many"
        elif any(r[1] == "unauthorized" for r in rows):
            state = "unauth"
        elif "no permissions" in out:
            state = "perm"
        else:
            state = "none"
        if state != last:
            if state == "many":
                warn("More than one Android device is connected. Disconnect all but the one to scan.")
            elif state == "unauth":
                warn("Unlock the phone and tap 'Allow' on the 'Allow USB debugging?' prompt "
                     "(tick 'Always allow from this computer').")
            elif state == "perm":
                warn("Linux cannot access the phone over USB (no permissions).")
                info("Debian/Ubuntu fix:  sudo apt install android-sdk-platform-tools-common  then replug the phone.")
            else:
                info("Waiting for the phone... Check that:")
                info("  - USB debugging is ON (Settings > Developer options > USB debugging)")
                info("  - the cable supports data (not charge-only) and the phone is unlocked")
                if plat.windows:
                    info("  - Windows has the phone maker's USB driver (Samsung: 'Samsung Android USB Driver';")
                    info("    Pixel: 'Google USB Driver'; others: the OEM driver page of the maker)")
            last = state
        time.sleep(2)


# --------------------------------------------------------------------------- #
#  Quick check over adb (read-only)
# --------------------------------------------------------------------------- #
KNOWN_STORES = {
    "com.android.vending", "com.google.android.feedback", "com.sec.android.app.samsungapps",
    "com.huawei.appmarket", "com.xiaomi.market", "com.xiaomi.mipicks", "com.heytap.market",
    "com.oppo.market", "com.bbk.appstore", "com.vivo.appstore", "com.amazon.venezia",
    "org.fdroid.fdroid", "com.aurora.store", "com.transsion.appstore",
    # preinstalled updaters shipped with the phone
    "com.samsung.android.app.updatecenter", "com.sec.android.preloadinstaller",
    "com.facebook.system", "com.miui.packageinstaller.update",
}
SENSITIVE = {
    "android.permission.ACCESS_FINE_LOCATION": "location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "background_location",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.CAMERA": "camera",
    "android.permission.READ_SMS": "sms",
    "android.permission.RECEIVE_SMS": "sms",
    "android.permission.READ_CALL_LOG": "call_log",
    "android.permission.READ_CONTACTS": "contacts",
}
DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")
WEIGHTS = {"profile_manager": 0, "owner": 3, "admin": 2, "accessibility": 2, "notifications": 2, "hidden": 2,
           "keyboard": 1, "vpn": 1, "sideloaded": 1}


def quick_check(adb, serial, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)

    def sh(*args, save=None):
        try:
            r = subprocess.run([adb, "-s", serial, "shell", *args], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
            txt = (r.stdout + (r.stderr or "")).replace("\r", "")
        except Exception as ex:
            txt = f"Exception: {ex}"
        if save:
            (out_dir / save).write_text(txt, encoding="utf-8")
        return txt

    def setting(ns, key):
        v = sh("settings", "get", ns, key).strip()
        return "" if v in ("", "null") else v

    def components(value):
        return [c for c in value.split(":") if "/" in c]

    props = dict(re.findall(r"^\[(.+?)\]: \[(.*)\]$", sh("getprop", save="getprop.txt"), re.M))
    device = {
        "manufacturer": props.get("ro.product.manufacturer", ""),
        "model": props.get("ro.product.model", ""),
        "android": props.get("ro.build.version.release", ""),
        "sdk": props.get("ro.build.version.sdk", ""),
        "patch": props.get("ro.build.version.security_patch", ""),
    }

    packages, apps_error = {}, ""
    for attempt in (["pm", "list", "packages", "-3", "-i", "--user", "0"],
                    ["cmd", "package", "list", "packages", "-3", "-i", "--user", "0"],
                    ["pm", "list", "packages", "-3", "-i"]):
        out = sh(*attempt, save="packages_third_party.txt")
        for line in out.splitlines():
            m = re.match(r"\s*package:(\S+)(?:\s+installer=(\S*))?", line)
            if m:
                packages[m.group(1)] = m.group(2) or "null"
        if packages:
            apps_error = ""
            break
        err = next((l.strip() for l in out.splitlines() if re.search(r"Exception|Error|Unknown option", l)), "")
        apps_error = apps_error or err[:200]

    launch = sh("cmd", "package", "query-activities", "--brief", "--user", "0", "-a", "android.intent.action.MAIN",
                "-c", "android.intent.category.LAUNCHER", save="launcher_activities.txt")
    launchable = set(re.findall(r"([A-Za-z][\w.]*)/[\w.$]+", launch))

    dp = sh("dumpsys", "device_policy", save="device_policy.txt")
    admins = set(re.findall(r"ComponentInfo\{([\w.]+)/", dp))
    admins |= set(re.findall(r"^\s+([A-Za-z][\w.]*)/[\w.$]+:\s*$", dp, re.M))
    owners_txt = sh("dpm", "list-owners", save="owners.txt").strip()
    owner_detail = {}
    for user, pkg, kind in re.findall(r"User\s+(\S+):\s*admin=([\w.]+)/[^,\s]*,(\w+)", owners_txt):
        try:
            user = int(user)  # Python also reads Arabic-Indic digits, as printed on Arabic phones
        except ValueError:
            pass
        if kind == "DeviceOwner":
            k = "device"
        elif pkg.startswith("com.samsung.knox.securefolder"):
            k = "securefolder"
        elif kind == "ManagedProfileOwner" or owner_detail.get((user, pkg)) == "work":
            k = "work"
        else:
            k = owner_detail.get((user, pkg), "profile")
        if owner_detail.get((user, pkg)) != "device":
            owner_detail[(user, pkg)] = k
    owners_list = [{"user": u, "package": p_, "kind": k} for (u, p_), k in owner_detail.items()]
    if not owners_list:  # older Android: no "dpm list-owners"
        for pkg in re.findall(r"Device Owner:.*?package=([\w.]+)", dp, re.S):
            owners_list.append({"user": 0, "package": pkg, "kind": "device"})
    owners = {o["package"] for o in owners_list if o["kind"] == "device"}

    acc = components(setting("secure", "enabled_accessibility_services"))
    nls = components(setting("secure", "enabled_notification_listeners"))
    imes = components(setting("secure", "enabled_input_methods"))
    vpn = setting("secure", "always_on_vpn_app")
    proxy = setting("global", "http_proxy")
    if proxy in (":0", "0"):
        proxy = ""

    def pk(comps):
        return {c.split("/")[0] for c in comps}
    acc_p, nls_p, ime_p = pk(acc), pk(nls), pk(imes)

    apps = []
    profile_managers = {o["package"] for o in owners_list if o["kind"] in ("work", "securefolder")}
    for name, installer in sorted(packages.items()):
        flags = []
        if name in profile_managers and name not in owners:
            apps.append({"package": name, "installer": installer, "flags": ["profile_manager"], "score": 0})
            continue
        if name in owners: flags.append("owner")
        if name in admins: flags.append("admin")
        if name in acc_p: flags.append("accessibility")
        if name in nls_p: flags.append("notifications")
        if name in ime_p: flags.append("keyboard")
        if vpn and name == vpn: flags.append("vpn")
        if launchable and name not in launchable: flags.append("hidden")
        if installer not in KNOWN_STORES: flags.append("sideloaded")
        if flags:
            apps.append({"package": name, "installer": installer, "flags": flags,
                         "score": sum(WEIGHTS[f] for f in flags)})

    apps.sort(key=lambda a: (-a["score"], a["package"]))
    for a in apps[:60]:
        d = sh("dumpsys", "package", a["package"])
        m = re.search(r"firstInstallTime=([^\n]+)", d)
        a["installed"] = m.group(1).strip().translate(DIGITS) if m else ""
        m = re.search(r"versionName=([^\n]+)", d)
        a["version"] = m.group(1).strip().translate(DIGITS) if m else ""
        granted = re.findall(r"(android\.permission\.[A-Z_]+): granted=true", d)
        a["permissions"] = sorted({SENSITIVE[p] for p in granted if p in SENSITIVE})
        strong = {"owner", "admin", "accessibility", "notifications"} & set(a["flags"])
        a["review"] = a["score"] >= 4 or ("hidden" in a["flags"] and bool(strong))

    result = {
        "device": device, "third_party_count": len(packages), "launcher_check": bool(launchable),
        "third_party": sorted(packages),
        "owners": sorted(owners), "owners_detail": owners_list, "owners_raw": owners_txt,
        "apps_ok": not apps_error, "apps_error": apps_error, "admins": sorted(admins),
        "accessibility": acc, "notification_listeners": nls, "keyboards": imes,
        "always_on_vpn": vpn, "http_proxy": proxy, "apps": apps,
    }
    (out_dir / "quick.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    info(f"Device: {device['manufacturer']} {device['model']} | Android {device['android']} | "
         f"security patch {device['patch']}")
    if apps_error:
        warn(f"Could not read the app list: {apps_error}")
    else:
        info(f"Third-party apps: {len(packages)} | flagged for review: {sum(1 for a in apps if a.get('review'))}")
    for a in apps:
        if a.get("review"):
            info(f"  - {a['package']}  [{', '.join(a['flags'])}]")
    for o in owners_list:
        label = {"device": "DEVICE OWNER (controls the whole phone)", "work": "work profile",
                 "securefolder": "Samsung Secure Folder"}.get(o["kind"], "profile owner")
        (warn if o["kind"] == "device" else info)(f"Managed: {label} - user {o['user']} - {o['package']}")
    if proxy:
        info(f"Global HTTP proxy set: {proxy}")
    if vpn:
        info(f"Always-on VPN: {vpn}")


def open_app_page(adb, serial, package):
    """Show the app's "App info" page on the phone (Uninstall, Force stop, Permissions).
    Nothing is changed: the user decides on the phone."""
    if not re.fullmatch(r"[A-Za-z][\w]*(\.[A-Za-z0-9_]+)+", package or ""):
        die(f"'{package}' is not a package name (example: com.example.app).")
    r = subprocess.run([adb, "-s", serial, "shell", "am", "start", "-a", "android.settings.APPLICATION_DETAILS_SETTINGS",
                        "-d", f"package:{package}"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (r.stdout + r.stderr)
    if r.returncode != 0 or "Error" in out:
        warn(f"Could not open the page of {package} (is it installed for your main user?).")
        return False
    ok(f"Opened the App info page of {package} on the phone.")
    info("On the phone: if 'Uninstall' is greyed out, first switch the app off in Settings > ... > Device admin apps.")
    return True


def offer_open_review_apps(adb, serial, run):
    q = _load(run / "quick" / "quick.json", {})
    review = [a for a in q.get("apps", []) if a.get("review")]
    if not review or not interactive():
        return
    print()
    warn(f"{len(review)} app(s) marked for review in the report.")
    info("If you think someone close to you installed one of them, read the safety note in the report first:")
    info("removing it may alert them.")
    if not ask("Open the page of each of these apps on the phone, one at a time, to review or uninstall it? [y/N]", "n"):
        return
    for i, a in enumerate(review, 1):
        info(f"({i}/{len(review)}) {a['package']}  [{', '.join(a['flags'])}]")
        open_app_page(adb, serial, a["package"])
        if i < len(review):
            try:
                input("    Press Enter for the next app... ")
            except EOFError:
                return


# --------------------------------------------------------------------------- #
#  Full collection + MVT
# --------------------------------------------------------------------------- #
class AqfProgress(threading.Thread):
    """One-line progress bar for androidqf's app-copy step.

    androidqf prints nothing while it copies app files, but it writes every step to
    command.log in the acquisition folder. This thread follows that file and redraws
    a single line, so androidqf's own questions and messages are left untouched."""

    BAR = 24

    def __init__(self, log_path, adb, serial):
        super().__init__(daemon=True)
        self.log_path, self.adb, self.serial = Path(log_path), adb, serial
        self.stop_event = threading.Event()
        self.tty = sys.stdout.isatty()
        self.total = self.expected = None
        self.filter_failed = False
        self.apps = self.files = self.removed = 0
        self.active = self.done = False
        self.drawn = self.dirty = False   # dirty: androidqf printed below the bar
        self.last_draw = 0.0
        self.last_pct_printed = -10

    def _expected(self):
        # androidqf skips the apps listed by "pm list packages -s" (system apps) when
        # "Only non-system packages" is chosen. If that command failed (e.g. Samsung
        # Secure Folder), it copies every app.
        if self.filter_failed:
            return self.total
        try:
            out = subprocess.run([self.adb, "-s", self.serial, "shell", "pm", "list", "packages", "-s"],
                                 capture_output=True, text=True, timeout=60).stdout
            system = sum(1 for l in out.splitlines() if l.startswith("package:"))
            return max(1, self.total - system) if system else self.total
        except Exception:
            return self.total

    def _title(self, text):
        if self.tty:
            sys.stdout.write(f"\033]0;{text}\007")

    def _draw(self, force=False):
        now = time.time()
        if not force and now - self.last_draw < 0.4:
            return
        self.last_draw = now
        exp = self.expected or self.total or 0
        pct = min(100, int(self.apps * 100 / exp)) if exp else 0
        if self.tty:
            filled = self.BAR * pct // 100
            bar = "#" * filled + "-" * (self.BAR - filled)
            text = f"    [{bar}] {pct:3d}%  {self.apps}/{exp} apps"
            sys.stdout.write(("\033[1A\r\033[K" if self.drawn else "") + text + "\n")
            self.drawn = True
            self._title(f"androidqf {pct}% - copying apps")
            sys.stdout.flush()
        elif pct >= self.last_pct_printed + 10:
            self.last_pct_printed = pct - pct % 10
            print(f"    copying apps: {pct}% ({self.apps}/{exp})", flush=True)

    def _finish(self):
        if self.active and not self.done:
            self.done = True
            self._title("PhoneHackScan")
            if not self.dirty:
                msg = f"    Copied {self.files} app files from {self.apps} apps ({self.removed} trusted copies removed)"
                sys.stdout.write(("\033[1A\r\033[K" if self.tty and self.drawn else "") + msg + "\n")
            sys.stdout.flush()

    def _line(self, line):
        if "Failed to get packages filtered by `-s`" in line:
            self.filter_failed = True
        m = re.search(r"Found a total of (\d+) installed packages", line)
        if m:
            self.total = int(m.group(1))
            return
        if "Found Android package:" in line:
            if not self.active:
                self.active = True
                self.expected = self._expected()
            self.apps += 1
        elif "] Downloaded " in line:
            self.files += 1
        elif "Trusted APK removed" in line:
            self.removed += 1
        elif self.active and re.search(r"\[(INFO|WARNING|ERROR|CRITICAL)\]", line):
            self.dirty = True
            self._finish()  # androidqf moved on to its next step (or printed an error)
            return
        else:
            return
        if self.active and not self.done and not self.dirty:
            last = self.expected is not None and self.apps >= self.expected
            self._draw(force=last)
            if last:
                self.dirty = True  # the bar stays at 100%; androidqf's next lines go below it

    def run(self):
        while not self.log_path.exists():
            if self.stop_event.wait(0.5):
                return
        with open(self.log_path, encoding="utf-8", errors="replace") as f:
            buf = ""
            while True:
                chunk = f.read()
                if chunk:
                    buf += chunk
                    *lines, buf = buf.split("\n")
                    if self.active and any(re.search(r"\[(INFO|WARNING|ERROR|CRITICAL)\]", l) for l in lines):
                        self.dirty = True
                    for line in lines:
                        self._line(line)
                elif self.stop_event.wait(0.1):
                    for line in (buf + f.read()).split("\n"):  # last lines written before exit
                        self._line(line)
                    break

    def stop(self):
        self.stop_event.set()
        self.join(timeout=3)
        self._finish()


def run_androidqf(aqf, serial, run, adb=None):
    print("""
    androidqf will now ask a few questions. Recommended answers
    (arrow keys, then Enter):

      Backup          ->  Only SMS
                          then tap "Back up my data" on the phone (leave the password empty)
      Download        ->  Only non-system packages
      Remove          ->  Yes
      Intrusion Logs  ->  Yes  if you turned on Intrusion Logging (Android 16 Advanced Protection),
                          then confirm on the phone. Otherwise No.
                          (This question only appears on phones that support it.)

    Keep the phone unlocked and connected. This usually takes 5-20 minutes.""", flush=True)
    pause()
    # Run androidqf from its own folder. On Windows, androidqf 1.8.x works out "its own
    # folder" with a slash-only path function, so it actually uses the current folder:
    # it unpacks its adb.exe there and then looks for it next to androidqf.exe. Started
    # from anywhere else it fails with "Impossible to find ADB".
    # ANDROID_SERIAL: some androidqf steps (the SMS backup) call adb without "-s"; adb then
    # refuses to work when another device or an emulator is also listed.
    progress = AqfProgress(run / "acquisition" / "command.log", adb or "adb", serial)
    progress.start()
    try:
        r = subprocess.run([aqf, "-o", str(run / "acquisition"), "-s", serial],
                           cwd=str(Path(aqf).resolve().parent), env=dict(os.environ, ANDROID_SERIAL=serial))
    finally:
        progress.stop()
    if r.returncode != 0:
        warn("androidqf exited with an error; trying to analyse what was collected.")

    zips = sorted(run.glob("*.zip")) + sorted(run.glob("*/*.zip"))
    if zips:
        return zips[0]
    if list(run.glob("*.zip.age")) + list(run.glob("*/*.zip.age")):
        warn("The collection is encrypted with an age key (key.txt). Decrypt it, then run MVT on it.")
        return None
    acq = run / "acquisition"
    if acq.is_dir() and any(acq.iterdir()):
        return acq
    return None


def mvt_env(vt_key=""):
    env = dict(os.environ, MVT_NETWORK_ACCESS_ALLOWED="False")
    if vt_key:
        env["MVT_VT_API_KEY"] = vt_key
    return env


def mvt_failed_hint(plat, out_dir, cmd_tail):
    if (out_dir / "info.json").exists():
        return
    warn("MVT did not finish.")
    if plat.windows:
        info("MVT does not officially support Windows yet. If this keeps failing, run the analysis")
        info("inside WSL (Windows Subsystem for Linux), which reads your Windows files directly:")
        info("  wsl --install            (once, then restart Windows and open 'Ubuntu')")
        info("  sudo apt update && sudo apt install -y python3-venv")
        info("  python3 -m venv ~/mvt && ~/mvt/bin/pip install mvt && ~/mvt/bin/mvt-android download-iocs")
        info(f"  ~/mvt/bin/mvt-android {cmd_tail}")
        info("Windows paths are under /mnt/c/... inside WSL (C:\\Users\\you -> /mnt/c/Users/you).")


def run_mvt(tools, plat, aqf_out, run):
    out = run / "mvt"
    if not aqf_out:
        warn("No androidqf data to analyse; skipping MVT.")
        return
    info(f"Analysing {aqf_out}")
    subprocess.run([tools.mvt, *MVT_QUIET, "check-androidqf", "-o", str(out), str(aqf_out)], env=mvt_env())
    mvt_failed_hint(plat, out, f'check-androidqf -o "<output folder>" "<{aqf_out.name}>"')


def _load_aqf_packages(aqf_out):
    """packages.json from an androidqf folder or zip (None if missing)."""
    try:
        if Path(aqf_out).is_dir():
            for f in Path(aqf_out).rglob("packages.json"):
                return json.loads(f.read_text(encoding="utf-8"))
        else:
            with zipfile.ZipFile(aqf_out) as z:
                for n in z.namelist():
                    if n.endswith("packages.json"):
                        return json.loads(z.read(n).decode("utf-8"))
    except Exception:
        pass
    return None


def run_virustotal(run, aqf_out, key):
    """Look up the user's own apps only (third-party list from the quick check).
    Some phones (e.g. Samsung with Secure Folder) make androidqf mark every app as
    non-system, which would send hundreds of system apps to VirusTotal."""
    pkgs = _load_aqf_packages(aqf_out) if aqf_out else None
    if not pkgs:
        warn("No app data from androidqf; skipping VirusTotal.")
        _vt_save(run, [], 0, "no_data")
        return
    q = _load(run / "quick" / "quick.json", {})
    mine = set(q.get("third_party", [])) if q.get("apps_ok") else set()
    if not mine:
        mine = {p["name"] for p in pkgs if p.get("third_party")}
    if not mine:
        warn("Could not tell your apps from system apps; skipping VirusTotal to stay within the free limit.")
        _vt_save(run, [], 0, "no_list")
        return
    hashes = {}
    for p in pkgs:
        if p.get("name") in mine:
            for f in p.get("files") or []:
                if f.get("sha256"):
                    hashes.setdefault(f["sha256"].lower(), []).append({"package": p["name"], "path": f.get("path", "")})
    if not hashes:
        warn("androidqf did not record app file hashes; skipping VirusTotal.")
        _vt_save(run, [], 0, "no_hashes")
        return
    total = len(hashes)
    info(f"Checking {total} app files from {len(mine)} of your apps (about {max(1, total * 15 // 60)} min; "
         "free keys allow 4 lookups a minute).")
    info("Press Ctrl+C to stop VirusTotal early; the results so far and the report are kept.")
    results, status = [], "done"
    try:
        _vt_loop(hashes, key, results)
    except KeyboardInterrupt:
        print()
        warn("VirusTotal stopped by you; continuing with the results so far.")
        status = "stopped"
    _vt_save(run, results, len(hashes), status)


def _vt_loop(hashes, key, results):
    total = len(hashes)
    for i, (h, owners) in enumerate(hashes.items(), 1):
        print(f"\r    VirusTotal: {i}/{total}", end="", flush=True)
        code, body = http_get_with_key(f"https://www.virustotal.com/api/v3/files/{h}", "x-apikey", key)
        entry = {"sha256": h, "apps": owners}
        if code == 200:
            try:
                attrs = json.loads(body)["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})
                entry.update(status="known", malicious=int(stats.get("malicious", 0)),
                             engines=len(attrs.get("last_analysis_results", {})),
                             label=(attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", ""))
            except Exception:
                entry["status"] = "error"
        elif code == 404:
            entry["status"] = "unknown"
        elif code == 429:
            print()
            warn("VirusTotal quota reached; stopping lookups (the results so far are kept).")
            break
        else:
            entry["status"] = f"error {code}"
        results.append(entry)
        if i < total:
            time.sleep(15)
    print()


def _vt_save(run, results, total, status="done"):
    (run / "virustotal.json").write_text(json.dumps({"checked": len(results), "total": total, "results": results,
                                                     "status": status},
                                                    ensure_ascii=False, indent=2), encoding="utf-8")
    flagged = [r for r in results if r.get("malicious")]
    unknown = [r for r in results if r.get("status") == "unknown"]
    (warn if flagged else ok)(f"VirusTotal: {len(results)} checked, {len(flagged)} flagged by at least one engine, "
                             f"{len(unknown)} never seen by VirusTotal")


def run_intrusion_logs(tools, plat, path, run):
    path = Path(path).expanduser()
    if not path.exists():
        die(f"Not found: {path}")
    if path.name.endswith(".age"):
        die("This file is encrypted. Decrypt it first, then pass the .zip or folder.")
    out = run / "mvt"
    subprocess.run([tools.mvt, *MVT_QUIET, "check-intrusion-logs", "-o", str(out), str(path)], env=mvt_env())
    mvt_failed_hint(plat, out, f'check-intrusion-logs -o "<output folder>" "<{path.name}>"')


# --------------------------------------------------------------------------- #
#  iPhone (encrypted computer backup + MVT)
# --------------------------------------------------------------------------- #
def iphone_backup_roots(plat):
    """Where Apple's apps keep iPhone backups (support.apple.com/HT204215)."""
    if os.environ.get("IPHONE_BACKUP_ROOT"):
        return [Path(os.environ["IPHONE_BACKUP_ROOT"])]
    home = Path.home()
    if plat.windows:
        roots = [home / "Apple" / "MobileSync" / "Backup"]
        if os.environ.get("APPDATA"):
            roots.append(Path(os.environ["APPDATA"]) / "Apple Computer" / "MobileSync" / "Backup")
        return roots
    if plat.system == "Darwin":
        return [home / "Library" / "Application Support" / "MobileSync" / "Backup"]
    return [home / "iphone-backup"]


def _is_backup(d):
    return (d / "Info.plist").is_file() and ((d / "Manifest.db").exists() or (d / "Manifest.plist").exists())


def read_backup(d):
    info = {}
    try:
        with open(d / "Info.plist", "rb") as f:
            info = plistlib.load(f)
    except Exception:
        pass
    encrypted = False
    try:
        with open(d / "Manifest.plist", "rb") as f:
            encrypted = bool(plistlib.load(f).get("IsEncrypted", False))
    except Exception:
        pass
    date = info.get("Last Backup Date")
    if not isinstance(date, datetime.datetime):
        date = datetime.datetime.fromtimestamp((d / "Info.plist").stat().st_mtime)
    return {
        "path": str(d), "name": info.get("Device Name") or info.get("Display Name") or "iPhone",
        "model": info.get("Product Type", ""), "ios": info.get("Product Version", ""),
        "date": date, "encrypted": encrypted,
        "apps": sorted(a for a in (info.get("Installed Applications") or []) if isinstance(a, str)),
    }


def find_iphone_backups(roots):
    found = []
    for root in roots:
        root = Path(root)
        try:
            if _is_backup(root):
                found.append(read_backup(root))
                continue
            for d in root.iterdir():
                if d.is_dir() and _is_backup(d):
                    found.append(read_backup(d))
        except PermissionError:
            if platform.system() == "Darwin":
                warn(f"macOS blocked access to {root}.")
                info("Give the Terminal app 'Full Disk Access': System Settings > Privacy & Security >")
                info("Full Disk Access > turn on Terminal (or your terminal app), then run the tool again.")
        except OSError:
            pass
    return sorted(found, key=lambda b: b["date"], reverse=True)


IPHONE_HOWTO = {
    "Windows": """    How to make an ENCRYPTED iPhone backup on Windows:
      1) Install "Apple Devices" from the Microsoft Store (or iTunes from apple.com).
      2) Connect the iPhone with a cable, unlock it and tap "Trust", then enter its passcode.
      3) In Apple Devices: General > Backups > tick "Encrypt local backup" and choose a
         password you will remember (Apple cannot recover it). Then click "Back Up Now".""",
    "Darwin": """    How to make an ENCRYPTED iPhone backup on a Mac:
      1) Connect the iPhone with a cable, unlock it and tap "Trust", then enter its passcode.
      2) Open Finder, click the iPhone in the sidebar, open the "General" tab.
      3) Choose "Back up all of the data on your iPhone to this Mac", tick "Encrypt local
         backup", choose a password you will remember, then click "Back Up Now".""",
    "Linux": """    How to make an ENCRYPTED iPhone backup on Linux:
      1) sudo apt install libimobiledevice-utils usbmuxd     (Debian/Ubuntu)
      2) Connect the iPhone, unlock it, tap "Trust", then run:  idevicepair pair
      3) idevicebackup2 -i encryption on        (choose a password you will remember)
      4) mkdir -p ~/iphone-backup && idevicebackup2 backup --full ~/iphone-backup""",
}


def choose_iphone_backup(plat, path):
    roots = [Path(path).expanduser()] if path else iphone_backup_roots(plat)
    while True:
        backups = find_iphone_backups(roots)
        if backups:
            break
        warn("No iPhone backup found in: " + ", ".join(str(r) for r in roots))
        print(IPHONE_HOWTO.get(plat.system, IPHONE_HOWTO["Linux"]), flush=True)
        if not interactive():
            die("No iPhone backup to analyse.")
        try:
            input("    When the backup has finished, press Enter to look again (Ctrl+C to stop)... ")
        except EOFError:
            die("No iPhone backup to analyse.")

    if len(backups) > 1 and interactive():
        info("iPhone backups found:")
        for i, b in enumerate(backups, 1):
            info(f"  {i}) {b['name']}  ({b['model']}, iOS {b['ios']})  {b['date']:%Y-%m-%d %H:%M}"
                 f"  {'encrypted' if b['encrypted'] else 'NOT encrypted'}")
        try:
            pick = input("    Which one? [1]: ").strip() or "1"
            b = backups[max(0, min(len(backups), int(pick)) - 1)]
        except (ValueError, EOFError):
            b = backups[0]
    else:
        b = backups[0]

    ok(f"Backup: {b['name']} ({b['model']}, iOS {b['ios']}), made {b['date']:%Y-%m-%d %H:%M}")
    info(f"Folder: {b['path']}")
    age_days = (datetime.datetime.now() - b["date"]).days
    if age_days >= 1:
        warn(f"This backup is {age_days} day(s) old. For a current picture, make a new backup first.")
        if interactive() and not ask("Use it anyway? [Y/n]", "y"):
            die("Make a new backup, then run the tool again.")
    if not b["encrypted"]:
        warn("This backup is NOT encrypted. Unencrypted backups leave out much of what MVT checks")
        info("(call history, Safari history, health and network data...).")
        print(IPHONE_HOWTO.get(plat.system, IPHONE_HOWTO["Linux"]), flush=True)
        if interactive() and not ask("Analyse this unencrypted backup anyway? [y/N]", "n"):
            die("Make an encrypted backup, then run the tool again.")
    return b


def _folder_size(p):
    total = 0
    for root, _, files in os.walk(p):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def decrypt_iphone_backup(tools, backup, run):
    """Decrypt into the scan folder. The password is only passed to MVT through an
    environment variable, never on the command line, and is not stored."""
    dest = run / "decrypted"
    need = _folder_size(backup["path"])
    free = shutil.disk_usage(run).free
    if need and free < need * 1.1:
        warn(f"Not enough free disk space: the decrypted copy needs about {need / 1e9:.1f} GB, "
             f"{free / 1e9:.1f} GB free.")
        die("Free some space on this disk, then run the tool again.")
    info(f"The decrypted copy needs about {need / 1e9:.1f} GB on this computer while it is analysed.")
    for attempt in range(3):
        if not interactive():
            pw = os.environ.get("MVT_IOS_BACKUP_PASSWORD", "")
        else:
            try:
                pw = getpass.getpass("    Backup password (the one chosen for 'Encrypt local backup'): ")
            except EOFError:
                pw = ""
        if not pw:
            die("The backup password is needed to analyse an encrypted backup.")
        shutil.rmtree(dest, ignore_errors=True)
        info("Decrypting (a few minutes for a large backup)...")
        r = subprocess.run([tools.mvt_ios, *MVT_QUIET, "decrypt-backup", "-d", str(dest), backup["path"]],
                           env=dict(mvt_env(), MVT_IOS_BACKUP_PASSWORD=pw), capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        if r.returncode == 0 and (dest / "Manifest.db").exists():
            ok("Backup decrypted")
            return dest
        out = (r.stdout + r.stderr).lower()
        if "password" in out or "decrypt" in out:
            warn("Could not decrypt the backup: wrong password?")
        else:
            warn("Could not decrypt the backup.")
            info((r.stdout + r.stderr).strip().splitlines()[-1] if (r.stdout + r.stderr).strip() else "")
        if not interactive():
            break
    shutil.rmtree(dest, ignore_errors=True)
    die("The backup could not be decrypted.")


def scan_iphone(tools, plat, path, run):
    step("1. Preparing tools")
    tools.ensure_mvt()
    step("2. Find the iPhone backup")
    backup = choose_iphone_backup(plat, path)
    (run / "iphone.json").write_text(json.dumps(dict(backup, date=backup["date"].isoformat()), ensure_ascii=False,
                                                indent=2), encoding="utf-8")
    target = Path(backup["path"])
    if backup["encrypted"]:
        step("3. Decrypt the backup")
        target = decrypt_iphone_backup(tools, backup, run)
    step(("4" if backup["encrypted"] else "3") + ". Analysis with MVT")
    subprocess.run([tools.mvt_ios, *MVT_QUIET, "check-backup", "-o", str(run / "mvt"), str(target)], env=mvt_env())
    mvt_failed_hint(plat, run / "mvt", f'check-backup -o "<output folder>" "<{target.name}>"')
    if backup["encrypted"]:
        info("The decrypted copy holds your messages, photos and other data without encryption.")
        if ask("Delete it now? The analysis results are kept. [Y/n]", "y"):
            shutil.rmtree(target, ignore_errors=True)
            ok("Decrypted copy deleted")
        else:
            warn(f"Decrypted copy kept in {target}. Delete it when you are done.")


# --------------------------------------------------------------------------- #
#  Expert package
# --------------------------------------------------------------------------- #
PYRAGE_ENCRYPT = """
import sys, pyrage
from pyrage import x25519
src, key = sys.argv[1:3]
pyrage.encrypt_file(src, src + ".age", [x25519.Recipient.from_str(key.strip())])
"""


def make_package(tools, age_key):
    scans = sorted(p for p in BASE.glob("scan-*") if p.is_dir())
    if not scans:
        die(f"No scan found in {BASE}. Run a scan first.")
    latest = scans[-1]
    out = BASE / f"expert-package-{latest.name}.zip"
    info(f"Packaging {latest}")
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for f in latest.rglob("*"):
            if f.is_file() and "decrypted" not in f.relative_to(latest).parts:
                z.write(f, f.relative_to(BASE).as_posix())
                n += 1
    info(f"{n} files, {out.stat().st_size / 1e6:.1f} MB")
    if age_key:
        tools.ensure_venv()
        if subprocess.run([tools.venv_python, "-c", "import pyrage"], capture_output=True).returncode != 0:
            if OFFLINE:
                out.unlink()
                die("pyrage not installed (offline mode).")
            tools.pip_install("pyrage")
        r = subprocess.run([tools.venv_python, "-c", PYRAGE_ENCRYPT, str(out), age_key], capture_output=True)
        out.unlink()
        if r.returncode != 0:
            Path(str(out) + ".age").unlink(missing_ok=True)
            die("Encryption failed (nothing was kept). Check the age key you were given.")
        ok(f"Encrypted package: {out}.age")
        info("Only the holder of the matching private key can open it. Send it the way the expert tells you.")
    else:
        ok(f"Package: {out}")
        warn("This file is NOT encrypted and may contain your SMS backup.")
        info("Ask the expert for an age public key (starts with age1) and run:  --package age1...")
    info("Who can help (free for journalists, activists and civil society):")
    info("  Access Now Digital Security Helpline  https://www.accessnow.org/help/")
    info("  Amnesty International Security Lab     https://securitylab.amnesty.org/get-help/")
    info("  Stalkerware (partner / family abuse)   https://stopstalkerware.org")


# --------------------------------------------------------------------------- #
#  HTML report — Arabic / English, switchable with one button
# --------------------------------------------------------------------------- #
# UCYBERS logo (PNG, 389x112, white wordmark), shown on the dark header band of the report.
UCYBERS_LOGO_PNG = "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"

LEVELS = {"CRITICAL": ("حرج", "Critical"), "HIGH": ("مرتفع", "High"), "MEDIUM": ("متوسط", "Medium"),
          "LOW": ("منخفض", "Low"), "INFORMATIONAL": ("معلوماتي", "Info")}
FLAGS = {
    "owner": ("يدير الهاتف كله (Device/Profile Owner)", "Controls the whole phone (Device/Profile Owner)"),
    "admin": ("مسؤول جهاز (Device admin) — يصعّب حذفه", "Device admin — harder to remove"),
    "accessibility": ("خدمة إمكانية الوصول — يقرأ الشاشة ويتحكم باللمس",
                      "Accessibility service — can read the screen and tap for you"),
    "notifications": ("يقرأ كل الإشعارات والرسائل", "Reads all notifications and messages"),
    "keyboard": ("لوحة مفاتيح — يرى ما تكتبه", "Keyboard — sees what you type"),
    "vpn": ("VPN دائم التشغيل — يمر عبره كل اتصالك", "Always-on VPN — all your traffic goes through it"),
    "hidden": ("بلا أيقونة في قائمة التطبيقات", "No icon in the app drawer"),
    "sideloaded": ("مثبّت من خارج متجر معروف", "Installed from outside a known store"),
    "profile_manager": ("يدير ملف العمل أو المجلد الآمن — طبيعي", "Manages the work profile or Secure Folder — normal"),
}
PERMS = {"location": ("الموقع", "Location"), "background_location": ("الموقع في الخلفية", "Background location"),
         "microphone": ("الميكروفون", "Microphone"), "camera": ("الكاميرا", "Camera"), "sms": ("الرسائل", "SMS"),
         "call_log": ("سجل المكالمات", "Call log"), "contacts": ("جهات الاتصال", "Contacts")}

# Cairo font (Arabic + Latin, weights 400-700, subset), embedded so the report looks the same
# everywhere and works offline. Licence: SIL Open Font License 1.1, text at the end of this file.
CAIRO_WOFF2 = "d09GMgABAAAAAKpcABMAAAABrjQAAKnrAAMhSAAAAAAAAAAAAAAAAAAAAAAAAAAAGoYPG4HUMhyeCD9IVkFShjcGYD9TVEFUbiceAI1UL0QRCAqCskiB/BYwgfRAATYCJAOTfAuKAAAEIAWERAcgW7uMkQA6Zd0uAsHro52jbUmnpYB/YyrYNi16dVdHHltuZqBgurlT7lap6nEAPvv///9/y7IIuZzZ0NndO5eQIPikaD39ktgjkEiKUjPZQ7FT7rIokM0jlbX2Q0HdUZZEYG8cRkr0iH6gKkSYkqkOxfbOkxEdhaOljqcznBqC3NBozxMm2ZdwEsZwuirQbtfEjiRoT2M6ZQ//cvJA7240a+nhllDcuDhGa5Q2K3O/uLUGSkBaENZN1m9ZxX1UVFwSdzxSiPVuP62GFdrxNTJHFSwopfCT3DE+EmspHK2SOg6D/2kHKkkh8pOpv6Zkyjf3Mh8qNLNvSwwSFC93liAWpO/cP2/zFxo1QbPjZLSEkyjkZ/RxwMQlsP9VvLmx7M9GXke073Y2a6eKjyXMlrbmzf/47WYIrm4zuyH8+Gauk/Uj63h328XSf23ARRenYe1ezLvqYTlxbktfJl5x4xdmeKVAdJqPiI7FXozyWQfEY3OoEtFmTzzxhf8n3OzPfTNJsEKQ1lcMVsW/iUmG53+bf+65l09I+CNSpohGRObIyP7m/E19zsg155r1zMwcmZERNXOOkaHiJzMzZ4yMnJEaOTPzoZmRc2YOvzlnRGZGZmbMzJyRD/8vnfV/696qUqkkIYHA2OCAQ7fdgQ5xXsyZwj0/5O3Pu7f+Ia3i6sU84czr7HFoYwwIJFWp3wp+adJuO8fe+huBMDw0ViEkQiks9+zwNKf/oEiAkBBTSIgQJY5HL7noRYhgJhVbCy1VWZ1JzWbWmXem7X7XtWvZ1u3z9Px+tDPzUEuWMtvpYhpJWwoxbGp4IpPYfymite/LqHn7jxXu30N9wgEpQgsOiIwFdAqFA3aM2/AA+8s3Niu0g/kP4uQQMhjy8v7K+3o1t6VOexsiRCP5HUBDc1bOnnD6NUIXALrMCU94ENpDC68XfsAhbXDz/fLgr73cyTPmhD9hO5U/o9ZsN7sQdgJhhIT9Sh8PBXbrGMUZhR5xYNTP59n/uXFTcFjxFUzFYZJ2pAL+3q7/fvsoiMO8eX5KE2+9aIAzYQzbqnn5gHpewAEFuQgD/gsNQ6EnHAXRuSk33ctxaJbp3J7zqqcE0wD1n5rz+T+AGkERGMrQBgaQ0tRoEo1Jbm7Lr6Vmkvf6YvtXf/3Wvy6Wr5R6e8stOdRVSjLs3t4TQIiq9Kn69I9NFaCKGI5wwbJlWWDBzFFuVVUCe3dVabj5niJrKi1Aw4yvy2/y7XyRNQmw4vIeM23Z7Lz8komOAoxdqmSGQj4ha2vHNjAofLdEQ/VKl+46qe5sFhlYYGDoIviZV1ghaKlpjQiSn4ffmT6RIJmG0X7DdPX6AySEZZp+Bfifc/UmwpR/KelygRdYmBX+lN2J0eflGY1v0K4q6v6q/3LEJTIAsnCQIR8itm9vKnM1LP8WlmFIKVVHqC50hMmLcCIdSAQwM/prn59ic4+YhIW+kOKldfUGJHEjCjDd/0Z1hYn2f3NVNjVZyByzBJJnl1itPqOTqu7+nU73ICwgpiDpCnYvzSGTIhDuHLJCtOjnVu07ocCoVf6kOuVOyP3/TVdf+q4egirQzKFa3wj4BjVjJPgG/rqUw66P7MmND7Kq+0rUe/VUUCrBjKRqdQuJ2UVS97aQYL4GvgHGsXznnWjGqOkxxkXrbc+ssS5JNtw4nGi9TTcKNo8W/r9XrUz5+4wD1/WVfDadrYkUZOvS4OOB3SBwm23Idei/zmM85ClnWFKQjJJMsbKZlnyqSKF4+Lzprge0C3FqSbC7ZFg2SrCK+pZgZPm9S5NKHs213ZTWCbHYviC/ABbC7iTL/56lSSkNhYAtKTvpMH+fqnZ9T5Ao0WlUKtyxHUqVt51DSNu4reu293YFP0h9EFChQVrLYnshyh7DUgpIWQnT9aFiiaKU2pXSGsg02Eqh5S3ebOuXQ6/H7CmnY845nRY+Z9HbvKokOQV+Y4wZhBFCiD7vaf0ttP/fo7+VvSxLCEGCDDKIyCAhhLxSym5fT5K4Pe697DUsDxlERIIECSGkQWR4X4UM2YpkKSc2xc6k32d/LT+TANau0chnHE0pYsqb03qaN6ftx19TH5ftzuxg7mKZQ4YhRIwYwjOEgEdt1q9NY7MF7DPcL61ConUJ835Rp8Wrg+MrGiQTBRU3v/ARjhLAcsBKAdsxSJY9ZUI4QjaEo5gh/GRDiIbbGdS5LgZ1gUtBXUQT1H/F42zeeENtwbSF8iVRYn5Dm27eZzmKoldii0lVRx5GVgOQGEkAOtSBTYIAOlPLBYmdgTdhUopHBvGFuI4Cuo/uH0yE4C9Es8MDM3aBpOd07tzjal0bac+ubWnn6ZW99P/p+aA9ujanV3bW91gIWy92pMjT0mfvzKmkbwUWl90/ZPLDOv7cNCAHdIWQ0f8FZuYttIUTnNKpmOoQWvNvFqCZs8DmjX8KJzThiUzRFE/ZlE/lVE3N1E7d1E/DNE3ztEzriNUWAhYM2MADAkcJXGAADf/r2rYkK6oBbcf1Q03jmKRZTgsulTa2dT5EQIbEhfQeU00+zpp86vXuj+JE7HGa5UVZ1U07mc4254ut7dXuev/g8ApkhZ0exBsIhiNFZZW2stbujs5AHny49P6HN8NcxdDJl/vjUB/1lCuw3lafDfCBASQLCMPh5USiNAbb3DEZwATl2N4Hs8D6d62Oww/AHE0AFXNmuLsCQiLixMz5IEoqvb1WqX8DSSFSGON9DXAurXnDK5//W3kidQDc5HyUOx9ZrW/9ordbGvyPVqMmtzUbYTLOnABmTi4+fmERZcrVqNWiVZt2AwYNGbZcpizZip2noHRZuSvUQTwfoiF8qiF8qSF8L5Hs4kR6oaqREHWPhKhnJKjekRD1j4RocCREQxP2Xwwj0+9tgKh9wQBHRzMCtDn29cRRrd1SSeceHnWZaOdFW+nWuw1v04knsDM9n2DshNFmTV2px5eM7smY0zuDfjLsM/q03ElP9Ut2/PUVquXSMpMQTOFOYm5YLfQw0ZacTilL4ynmhE51U0tSjBSNvPLyzJ84xJhcem3uyehgqPJZvYNFZ9lYqTS2tBBtXkpS+Cv/uadcNKVaWkNabEVNofGTfhO7UX7iW/uE14fobwZZoYiasOLLkEKF+qTlWf6Tz3ha93EAaYRQAWhAQ+XE2RKfcLWUu2B0Ifj8fOkroaIdE16slUoqaUgJSxlqh0sfekfKHHaipg2nY02f9L4vf/ilVjjCTlQ0qtKqGW2ybpqcsrpl8spu+owlr2QmyuGGlLwNqMxUQKcxB+g79wP00/w6anB1MR4VVyppVlecb+66FXy3uArVeNVZD1lT3LOV1iCbfscfYIJZGSDjSwWrMmpa6486g0mjTgfF377rAYAFB2zlCWbV2v/bGinHiXYMkYkOD2g8zPFKaE/xOt9nXy6b6j8CU4gGADDqsjq8+5MhIKGgxVBs67GiriDLidSJmuwy0Xy4MEGS1AeQ0oyGGrOHl6SU1y6n7qbJmzRshXfeIfv+gI8h3G6iSR4a6LcsNbSTabveKpKCpV8VLpkfvuXWmqq8D7kvL5mHpugPv2V9C7TGtOVOrubIapKcdAcGylidKrSibYZkIkFPyyFJuKOJ/QXp0en7bkss84Vm66R1xhNATKAXXeOHR46VcWTBBQnD3t+aNo2dYCy5jKtZOX952efHgmWYWTaf76b+FUBQjveBbdXH9B7ixZqVLtpACEgo6Mw7T1k7w7elNOvcuPf0+NCpje5dgD3jwIkLNx58BC5PmOYtJWMAkGFrmpVl7eWAPAWKlCj/pysVAFzDS2o3wOQjXOe6U6XvS+YTAuKyqufkLdXU20+GcSN4ycOOjN/nx9QA8JX8nfhxvbcbzW4iLdp06NJzHzxs8AjKWKV6uXWuw8nzzIIlq1jNFy5gQ4ymW33W3u7yPnHYP0IbWAOYurbWGwL4US3LKxRoRUPrs276N99raMkd/kdrlAAxyJiQvJOrXFWFgwqTlB/yhUu1YSWaZB1xtc1qTnuu13O+vpx/JIGoui/6cjJzbDAt/1Efy0HMtAnMAo25QqEYCMG2FxJnaVputwmWDmW6ECTyxdTUYpF79LeiAA3oTtn2GC5jc9BDWzHnGWfAss3p8Q9usNP5gC0BBIEWkRqLIWwnrqLdMmO78LVRSNemKR+lBifWzwkn6SUsCiwWj78aQ8zzi43c5PHiHnqd9oS9zOOsvMNM5s/g25Upng8VVWcABCQUtBhGR5ZtbyN0cTmQgnIwipM/67AiLtInOPcVQ/q7wjoUACKTp0CREuUMWpNmDN2R4M73JfMJAfGXxKbXtK7X0qBJi7Y7SJeeh+Ax555N6U0/b0s+iq04zFStheF+5I7chEamUbyDgYSa9HTJjGqrVLa6RWkY2GPfjGnaLEZn3vvQe3UWc1AJx6cSrrmRISChoMWwX+njkHsUCxXI5XvUMO4+RqRX69mS/OpOUN7VRCbIiIb1Fwj+l92NxjO61qjozWMUNGuq+jb/WACWPwAl8nUw55i19hNQCPi8571R204vQXwE5EAc32VobV+bS5qEk7P79r7cCTYC4zMVWDEq3uoLZYZeWMkgA4/fVeYp2/oixyzdy9V3dDmvNuvazm7Op5elJpZGEShwkiUZKXBzUV++0IlByX5n7MqxLXIEYV+8mfSly2mms+FUPDAlWx+ij8SYLpYTvV5qJHmwtsdytdkZ8emzeCBtvwswcjnhgnJnQge2S46GyrDYXW/5nOJM2Khi4IHm3I8iFKhNkSEgoaDFMCssRRyRYp5wMEySeQbgwIkLNx58C59xRtJDVp2cS+QpUKREuVwpLUQZ8yQXaFikUTKPCIhZWLeLUZ3JMcrydOrz5P1cX/6oqOh7Dv9cqsvcaHYz06JNhy4999s8bPAoaaxZTTwIn+Qw1zVeZJasvnfN1qY2DjFa5gl2bd5fPqRyJGSRqqnrumFBz0Xf8olmA4OXD7W3IpQkPCwV4VV2c+MWhglIPzlDbYJDpKSq2rREqulc1b+XtIF2sqIP8X4vwyoTx3aNZrCIU+sJ3VUKhcAxLthHygFwqUTQMXz1m0vc/Yuhxw2Ne7eqOJFSfh0r7HXqM3H52AgzlRJ70emWYKv3DjYo2Z5x4MSFGw++48DGcWgAM9OGXw2eL7VkaQeIkvmMgHgUQmaqNSY5D46MqXtjdfG6UeVmpkV76EANXXqrYaQVBdAAIKrpAlmyyqj2ot07gDv5xEt/yB+QJCommjsTgegz7Y1Uytg4liRZXZd0SPbgndF06s3NhqU1xkOclYOu092kfFCnl9idg0ck3jdTnecjui6ELLx4Nv1XBGNLFQRgbXoDAM8YotFDYItwuEmj0rLHmjdExA0jb2iRDjh7DKYqgBR7e3mXs6ZpyQRH93JLt/KUCqOKJBOgb3hE5pc4ixJ5MuWQWlsCAE4wRN2rWFsnLlzMM9V9ORfc+oh/L9iN00AVxvk9OcbqjbK6/UylFbvP3/ORtjv3QS/HI2gHWZyTyMPZVxru+he/yc66Tq3ngQoAQ/I+7i33PtSajFq0P8klaQs6lTjvjovt4aR/9wAHvtOkH+bW4DxhFGnD5a44tMAcu7xM7j+qIMFB0g9S4DTSfIRZpxHV56ho9pUoJs4z/WdsKm0gkEvZHLokaBELKLxAYddFPkMiuKs0kjmdP5qdCg5JJca6o28ZfFuFornPMfE7PGha5sz9EqfSyJh0WGf/iubuCad74Je3mf/KJHGRISChoMVQedgJE3gIyIxQUNFA6JhYYGwcXHsM4ZsAASGUkio1oev92QtszhvulT4umSp80laDqdRXqtIIrvPTYWMyWm61luzWUCfv897hfQ7NdMMFgrtCJqo9aYlUs88luxhW07WNmyq3eeiEyj0w7I2htSDcSoVqESCPl4jNAeYAFYD9as1FsivlgVRt+6lLkpIcwyE2y1Tp8yJDQEJBZ/6bNKFAr7WMBZVxclzyU96NWP9EuvtNPFqamk6vGMbvOs1u6nfDrWTkO6q+L5nPCIiqCWdv/Sq/OtJwE2nRpkOXXj8csFHO9jO43sJBekurfKbQRz4PLpGVmxu3MEwSpjMYjzr3sO03ysFxbDt1VAfjx6OTnb6nPZGCetU7ndAhN5g/FZuYben/RSvJfdHF5D9CbLu42K3Ms2VX9+vkE/vU52UO+YEYFaZb5Tz9Wdo39UwnQbx8MaYKCNh/pjwH2RgHfqds/oXa80d4eQjs+TdR7RhSqNyTd0n6okk3J1ZzEz47KQGATMMCHI4wsVc0JLHVWI4H3veBpuGiEaJEUD+lRmtIJcFnVCBoPOokt8XWELELgb+8JUWrC1O7djfQ2PNXSsNcscqvDCFnYwzU4fGQB9BBBcABOZw0jVZVt8Daa48OCzU1aRgJGHydmx0Xgy4yg3/avcfwAWsmYifO+3Uio4vPV217Vo1SFvann1jTuGf3hD6LXbL7aheEk0YaJAljCENOI97I6v2a0AjBgHwRv/qaxlwzbAI8R1dcdYrhkAIBuLrwK93s5dGL5atJk+ilUPkjyomqwJdCsoktpbM/b1icLDVdFOlkYX9E2Yn5xReSxYgAW+jaF0QG6RvfGI5Vf5q62zIaUGwR61dkfRaNDlPSRO5uicCVAProOQIWyXX67jONKFCeHFpzx0EXbiQGkM5Pagy+psWcBRqaRP3Cg4cUwDKvzrNKU9V6E/lZBSY4taDH7gJEDJF/FqSdt1Le+ghIlae1V+x3f1etmDKH0Aqn2q5ORjXdlACwr3sfcn+svaHI62dBPMkK16uIWApAVMU/Grq7dZin1eO2zB89zjDsiWSVcS/v8fGzANBraiMML7en6vpoc3aU9VOKcoqDTuKr+CHh+JqhysNAaPW+U2l9P7yo0Y6KivZfdErL3RPe2EBGVgwiijYyBCQUtBjCo2cf7cm6yy0VlVAjHkgC/A7v3jQdszMzDVn2hXNIngJFSpSbB8Tw0Rw1sgASiIeNkvmMgFirfVh0I9F0K9GmQ5eeh7Wr8RlOEkCJQwvMyHjT70IqcrYgsYHLxOpI7qod2ph7/po2tzidSEWr7JiIxKiCne4jUMCukb4jn2FCYEJgQpiFIFbRAimAGW9pSALc1QAQ2C8WEfL2VBqB9aB8c5MSAdfjI+WV6nVK36adrXIuk6dAkRLleIyIRUlKIxBhrABGyXxCQMxCAANpuoW06dCllwW29/o9ZkMvRBJAOaVHWpasxfEQfwkRmNRODNt8evp0qUHsteEfB3Tl+EzwOByWCW7XSedYLaQipD9MHmnNoVl+M7oP10zeAe9bbd12a4Q13sCy+LUeq0XBd0ujMslh1ULzBN+QummtItLjU7gxigrMgpDKUHg3aEH61qmkXUWSC3Pr8BlwUZHKHg37QFCBrPXAq+QEiRupPDezHMB7we1DiF8oKyyDQ0BCQYvhx1RC4IqCkfjbdHB+p/grMHxxMoIBSwo48BBMbLOJkE0BqNCgi3FewYRldiKVNHM6OSbhBKGgOHDiwo3HvwCvfS/43wsQzwEOSXUIKxtHMlFi25xnXoo4JLx5hPzBabfnLp3GrDKoEpW6osjkKVCkRHlVOe8d4yNspQ+ClfJScJTMJwTErK7qpw9yV9Qj8sQzL7zyNn3PureyD+CTL775cX0YDZq0aLujIncv95L7iYGHrHgEixNjP7naN0YSHeaKF15klqzGtYyXPmc2B6MK1Zk6uApzOlKmA6O3ET7PkGehu3E/fdpTkSEgoaAzelCpMxu7X47WAEWsFAYRe4ohSuYzAmKzO7QPEYlzfV43btzMtGjToUuv4eeQmWEbSZ9TYQWgF00QGQISCjozvbE5gCV3B6iQJjB+YkHiRnzqXwcik6dAkRLlciVlQenVTlIxTUAcJfOIgOgqfrWmfPTl1qPe+rUeBF9g4+8J/XOpLnGjwc1MizYduvTcb/MQPWouY8UhDG0soA7Li8ySVZYEAEIaIC4fG8p57F/WGWax6jV/7S20XZktp9im76bsXJiP7wi0+U4tewADtyAJTvzuWvcieyD3IGZ1hl/kU3ajEzG9eAVhQbxK6ppRPk9jO66nWtaGebc5V7iz7nNHBcJU3xVNicRWLqX5o/M56K7t82wBXOTnwNRCJc7nIuPAiQs3HnyzzC9alvD5HOSbCiBK5hEBMctSMPIH33m6vhrv+YKZas0nqtzMtGjToUvvKF7syjckzOQhrodFYskqA0vcu8vHkdvVEJFmBpbAISChoEeGUBdrMDhVJ7RBseMAd01je8KBExduPPgUoJ/NRQIg0SgaqWotLoAceQoUKVHOXCF1tG+evKGrltKUzGcExL46uH0KIPhj7kk3eC/dm0XqdXEkfg6Nr2lzE2nRHjphDV167qOHtDy6hrFhPzylVtaV9gJZssp6r9ZV7iD2KISo0eICMx2ttoUQe7UaGIJDQEJBwxSWcomqOQsCG3aYgDoYgAMnLtx48GXeU5zl7TDlSkkgOfIUKFKinIHpk7PAJR6U0CiZRwTErD/PRBp46UJZci/hnVycWrU3Ej8ZSLS5ibRoZ4Hicg/db8iGRcqoU3vVKiWILsWLzJJVlvL7CsSSqAamgrNEyjwOqSyAg3MtDcnwXCp987jkzRfgYHh62y/fexQMb1l28/qVsVRbyVOdnZX8bZCoXFV7/UEyGmBr30gZ2bh4Qtw9YWppqWpZm3gyRRdywxhyGvE4i02mcKk1iprTRZQzGnS1TfnuvNJ8HArSkgLo3ZvYikV4IdnhgKHnwjuw9xPaOLNUMqmrIxjQtVgtwXkeqGcwUKUiii6BIAkDPZO3jgaW4GgmxNARkXr6byg0mZ4itH6rf+K4RBKDIHYTCLjLSfpDStkMxthBKYA0X8jBstlctiI27Dhw4sKNB5+Dkc8hdBiJECX2jzjpjQuIgxI/mHeXemvKKTzxXpGCDf1i75L3iUOvsowKQPXrcAAEJNQeHU8NlVgmBbA0EbNn1943/7ufwNTfJIxCiAWv6z7F156Mes8Ty1uzawfv5FYC2iEPpvNrw/xalwEjQIfhS8WyMXAdXP4y+hHI2fXL6wqE0Onp6V7LbyP5Ofzf51usRWTimlkWv2PTQd5tQzj5LxA2TVuvHl76Rqq0nIxg5AZrZNIWvjXtJlhPeYN2AHUVhRn7Unn1SNVSA07gD73YIhLZ5Ds5OVl0YIR9uuH+HYTVntRFJpNl63FM4gc5m/TVOEl/qBMs876W3iNvS6hCsXp9wLbjCKqqRB11ZRStKXhN6zrW4faihCK8MmBrMd/q77oS6JY4PoZ4a7lHuYKtim3ppr5VyDhye/+T2W18I+jRRuG4TuSG0d05/Y51F8Q0cTiO/BwBF2yd8TkEZNmKpe4dcG8xLXLHuvURVghXjW2q8K2Fgaawjd89nl0OPomQ69IibSnt0paNEZdwLbuHzFJH5kctOBegOS89QFVg6fgOj43SR/49ILsGpM+1Y8r625CwJqylSuVq3X/XpkHK0zkRVeWHa3Nv86fXTq3VOvmJA3PTJpmY955xU3xBf4LKS6W93HRX9hGQjEPuCFp3reJWMsqPvlc7tSEf7HuAmxURjM3HxxrnPcGqVAmjiVwO8l9IxO83hezKR/BP/Bf2VbGa3PtY2b1mIpuzc9S0F2k+1S8hIx2mXcIshTSxTSVsC6vjXzmWTvEUVx+JHgOQJkYSUm5mEar/JqDh6WqxxqeTSY3f10ZacoTT7IZdUf3H+sqyAvOfk/wCd9JY5xCHsgz4kUpmXJ1cJNp7GVKX0bzAd9IiCzn29agZ+m/IGGZydW3AdVgmb/WJ4RcmgJLVuB1AJ7SMFMdOkh8nCqAPMfCWZUKLGfuPUh/5EMjIZRvg64bmI8xgl6oFbVEeA1GcxQWeQ9gGRvqbI/TQf6N4b81EIBKF2DxM+g/sQoXD6Rg/eSuD+13+YU2l0TIPaB7K/niF4y//duz0WeCxQp4LM7AiygqoMuxMtAZBxtAPvFfNadlga3EUCZi7B/SHcsJrAdJxxhaAEy116/Ae9P/n0kf3Yy/IDyBkZv8r0sTb7MWuC9C863mdLO34JJ4AALxbHsnAY5m6cp7UG47clO/wao3GMrSazSMJazaocRLPYQR3R6+xU4b4oCKGZ2b+3qP60xGN4llmcfgLx2LgrMFpMata3QRbBflSVm38n8d1iTF6Vy3WOZH+mtNHsPBo5z67HjEZtq7D6YP9R5S3Qgaa8dt+4jXnCLaNSN/ktcpY+rOv0JLcGZnak6rHHpq0MQykP/BG6shYuY95PvNA+oNC1JdI8Q9+IZDvnj633HMjEt5PuXf7E0KHKwPY7T37kuadfHM+fiT8mo6Wxx0MFBQBdivqO3gXd3ReOGprHGMCIg8BS1XEaudEx5+xSx7xpY0d/QIUt2zPibH3FXxOh73FupehezvEihDurWKuPNFpajseD7pyxMnmZIjuDce9ROiY8Z1jvRs1hAEmDYaOh5pPjEtcXEjSjbA7oqKasWtTK20bG0M7RyO0j0yksbG1NBxNRIUfY4j+u/1/MCkIDcc8UQxLur2M3CkFDYzuo6npNSuDZmMcq2HlRvBoGJ9G8GtnAppMsPFcSIwkLWjLKXJpxl7IKCGVNaQy1uTKNYUb6RwIkI6m8zCW9egd5UPz+CzrffmpFtd10XqMRfoGTIYaY6QZjDWladliZgUWAyflA5WjdnaEXIu1OHpxg49VEnUDNyE2lyjSqkojeVVmhCYfOc8kErsKE7daUeWo8qyTZddXDgFpLKRMKUOKnKLUo0OQPhmYEDpOpR48A6Ag2LAEInaQE60EwCrEFchSIA4vXsxiHBPhi3iQTR4R2NSuYCmEgcKWeHGROLEIKrY4Y/8WowQ22dcJHTr2LIPFMli4wcQDF7wU3NnO/DZoHtFfMEBZDKF0MkXqNBkwHqgGChC3NlNUdAZCKBdrjUMf5rCGPenDG/4IRjjSkY08Rh1t40So9Vn33kMA7tYOXDcCWFlc6JS0j1AxF6CTLY52FNG2AKx2pISz3qu5Rw68Z4F2+8Rh0oV+2GFcxHC78NZlzQTWbb0/mgvTV2XzTCxqc+j7zGlzB1PGZkZt7sDI32DQG50CBoKgvT8aqL05aH3g6xPlUKO9PlGshQc1FFndthprq88af3+Qsc8OigFihaRJBIfUGq188Fbc8FKf0CnnZZ92b39ImzmR4ZsOdtrpDaqnBjoLE1iE1rdvom+0npPDYKR+37V/agJA38PIO8Deulrdb8uaDjBb73XUHbM7Zvd+7S/ayVQA6LILgGnPggGdz9QiSoB9Tvcr+VfB99/NPyZ+C5XxKDlF2p4rSf/NnYLNlsd5fUWEn/xzkMN8Di3he59f8g+cQ9RPf5gz+918Y/LQIWVsyJnTvfuKwvbGPfzAhNHTffxV0abJxcJCQp9+8zY0f8P/v/yvggOLj3s951I1gv0ZWu2RocOYGMHUG381vXUHEx9io+kUkYiOUwIlUgIlUpRiFE8h4CQFQSSCHRShkEKKUCJdRIl0EcUojhIoWsWDAYzpWCSdCDIwXeFDsOdqpYBSqO1OxzRzmvOy00bDvVE8LpIOwQIR5O6JVkd/hpTcwA6EjqcIGNhx6KtyJU2nWYTsDVK4OH3DZeoQNYEQWhBiaMZH75IDrD2FSejkGshZWEhjGyGoIAQHRDjQk4IREE3iBq5Ur+zQqC5ekHixl8EQ1vpguNUnhB6EGAERngmHPdZgu0GEgbvAEPYOfnhzxItgEGIniKMnR1kcD21IQx+5MRbFQA00uwHLZ2zY87eWC4OBY2AQTiCEFER4PWfQPxwlNiyQGs4n7vnjWYAp7P0CRHiXtQejs5saSEDIhKnJCHPuuDCv5DySJcTy9M2QpZeQVhcnq8iMy6RyKg+MLUh9luVYVkIdNMNgbiotXCyMSLEqxVMqxJr8mBJSR0Lk9sRNpFClEA1HD3LlVUepW1gRYbEkJcekZbK1TTXXWLU3QHz9kKldFsWNDlR25DtxceHvMR9Z76aPQ7bmvOiN3muLya/cYetOkRR9hDQuPgx7P3rSWxDz8bhHPUrfrwX4vRIVzhVFTe1eN9ib98bT04gegOjI1MHilb0izvK0FMa9B57RGiyx/C1TO3YNE4pzejQD8nyXB/dU89z6tNnDLTZF9qGM+9QgxX8420wH3bzpnpj7oIFm5Efr0rfZPPiRN75iVojKrafidVmPwE3gvPLKwzNrT0DD6hppHtNY3QNSgQIAoHvHf3TffpkpEwu/kD/9H8ZR01w/kx75odzu1djYPTHizR9vuiL4BbugK0F5EnYfqtgHIMy3cf/WeYfAaB3MuyvugXV6MkYNEJrcJvKrd3R+FTUU79qhI31YrOZbTXUfWc6Rhm73LnqQdZVu+anvi257/JIKRLt8RpKMDj5/xLggFa+Gs6JhKAvsfxG0985iC8eogPzJGTtE2ldHhnHFNKlDRIY08SkQadKAzVpI0+LOKM6l744eNOFnjWxDJv4cAkjCSzT3OUvUdMuTPHbmrC6QzAAAtv6Gnqjp+mAQObMkl9R1V0yg9pkZt1/NT8i1RhJepLIbKOZTs+jode0dfb2ot/OvKN4VvXk9THldcgl1Snf4lWCJ8ntST2rM/NyAcqo5yr+9EqMN9Z/aHrFIqG3NKdeI2iU7qWedUHu3FaPhU18WzM69Gg66mjrjC1f14ccYXtIwYwDie+V46VLo4v9Nr/JgjhFXEZY/fWOH5FbmM1hR5VxvO2COf6ywC7P7mWyJnMO7eYxx5HhOzI7YkKWZgDRYQVUEddYT1qPWtdMN9RxuR+kVi7g1hgKA4RvIv8KbMO5z+e+lsVuZe7bl6GNwjiaLa7KGz8nc07jCt4jmaynZzKkckf6Hryr7QG0e8avWhkRKq+kawuJtDkRh/9UCy1r1MPph6gxsWkExtyLwtMQ4TBsaYxQYylGHDANEKQ1kL3Ldaj7UfbLnAvQZSHkIANjvEbfO793Df+EEs2rwwXnJpy79bF4/5JBUa98hnpXxGUwDFWn2qbLUXDFdWc8SSizeS0gvc5U728I+a9I9A+z3HZ+JZ2z/4VCcOm04iKR+lNbBZU3rUE+ovRtA7VoWAFzqu/Tm0uwEgFp9kKKPqJU4M3OzUXXg4yHH9b32yJ+l2pN+VZVbyV7CcBBP4EN3EqtHqzS985AuNVtCPRp+yAyomDGNmlUCawr3VFUEMtw+wo1I3Ae1pwBIP9u/hY3tYiKoFDAZzA/8ftblAKSPgaSxA98CBf4lTqpNCByIgSc6LtE/IFAsFkSI8ciZkt2YBtGwqdjekAh7wsGQAseKBwWnO5fDuX2CF+Ht8tcQGXvIlMow4LRTmq+FWIwJLdUy3Pox0h1jMJPNkQxp9GQw+YzncUqZyzJWspm9NNDEOVRBIBNayPEq6gl+EAYZUAIqaIJxMn2C44EOLOBCIERDATSADgwd1m9F4RXrIzxiQxCiyI+SUEV1tEV3zG/cbfd2fNMlRqAQvPJ4KgHRoRMcTADSAB1IjADlHx0cqi0ia+XQBKh1zBj5vWUurd2RsWuAqPeahFxW9gy6DUG3fp17JajhGUJAXwRSEBUJQHV3LYgqhIBeA1KQGwqgjr8WxD/wAH0IGFEdVkDvC2pe4yt4E80QE9AmL+LoYsxzZBZ8gBoZtQXUHGXco2rGBfwwiS/sBnuSJ/XuavfONg/orKB6vjsAuhmQfIMTk0UPuBqRhNLvPdzLyJoRvnVe4AQZy73YA4yAgDR+xJv/z+tO1vcFPOdAm3SKA7gAoXoImipR5309QmUhrtBIt9h1RSStWslAE7XwRoYPernP9mX0XhoMg63e76OKkxZRz+bRGKZJdYjf4EY1rWBXnud0q8GQk2Il4HmkmwJD6R7myozI/WAYEniqy6N57G2ieA4SlhDiRh70ToNxXW11MigrPRqyZIjO9pFvGUmDFc5DveofaBXyXUoFQxxwt6lPO8Dq7VOe2iiBPjUKoyn5/Vv30z40iNCwK0ZM85RI8XEZdRYrIFxsVAZyH2SBq9RNKC3WIv/CKYphgfJu/8Ar5YxQw0EQor060Mn4iZRDGUigjKaSoyjby60hwbqihJrm+DjyFcK4RgYGaDVi31AnZ6Ae1ImLGdV3UF0sAxyQCHS5ICVN1q4Fbm8vH3rGnuX3WNIQCNBYfZgNRq7kkK5pMrXHZzAxQ8XEFpLnJZ+a9Rt8TDtf3MSqeQjjkXwid/YQmZ22gv99mBPjPZTPFqYT2r10sCIuR46eS2l2DWAqrr7+1rFVD7NY22wS9ilBbPFO9GhaEMOUawqr1rMhO5KGmdmaSOEmXitmiRpswizzbXxoxxbCbx4kghUMxgAk0AzDECogifGxYIvqiZab0Fpt6eNHlWaIZTvwISgHx4XeLJPgt7L0uB+chbrYuPfSNTiK4iSpS3LSVvgYQtJsDP3uID39U/5502FAhwNWQ6i3VEz8ZfElY2DjSRDVQPJDU4cfj8/X0kjbFuOP5G+zwz/VJlgR0V1t8FgxI1RPhwNoD5uiZCv+waEbKWK59Di+HTMjVNcL/8Uh/GsxC7C+FWyUNDIooREP/1AYKoHj91hg6XaJCiYe0Zx+JdGx86JqR978d4rDzkG3JguxBBYJy2EL7Pd/3VkxtaSUr3OcZNsbxnCBdtjNQToXJVC7f1oTH4BC1X+y9s7uNodR4sLLeiGiJUqB+sseBygH2N3+sgb7NgRi5eOqHTMzDL4cYCd0Le2CoydITpasBTfDajMqDTXvuNR7m2d7eGKI+UebyJFDdNX2iV/QInouGAxjYS4shy1hZ9iXHIsDrmIUFOBdIBgzvnxJzFE9Ak+5g1xe2GLJjCtGWlXz4OoKlbrGs5miOBc3fs9NFc7CjLvasA5piOfRfvzSGB7hySBBAxvrEVFgRYpcKML3fXtamjiiHFhfh5pi+SMTvb00OmmXbNh2LZqpHFjDeb4DP8wa2WoxpVm/8Cp1GPn9lsRZawgXSgtOyOF2VRJ3q/Iu5GUVEv0n1oFPfCFwvgv5giJQggaaYQT0MDh+BKaIRUU85KEJZkNnZ+DiTJyAQrMaNseyG0e1Rl0b//WtSkaCXKNjxyKqtrx+/1yRnoKMLHuI5qsn585ESprOV/NRi7ZWd8lvg+/Xjs8boIo9vlIJWly8RxNteYXEn12G98qC3bXTpcMB2rFE8btlUX1+1Z3y9IT8Q9uqu/uXRZIMmgbK9JnYfS5HQNs3bsxlY7GeZ/O3+INoNr9zhiR0kK0H/e7fSUiiQJkaWq36GU0GqoRJIF9AjTZj1lOq02GowMqSejDz7FqxD+k4OjG/41qmkGVi4Ychv3+/P+rJqdJd61A1Nrmg4oEWNN7RnOrjHcx0utdX+agwZWUPWxMV47oru1cZ2THNW7LzgM3OVJAzT3VO5SEj5wHMUkilDjAYN2ZoKB+MoYGo6M7tLtqf9szv1kqmfemo6u7LUJQXXT5yp5WXFMvf1mYVhqIMf5pncgKpqxg6OuNdHJo37UOn5Df2jEJ70X75UzvUR2c/cOdW0N5QvXAh8pyflED+/s8YRQWUevkCJLTkZvsp4ALJAufndjI/r5NMv1Z1dY48BWKL23CN19ap3w94cPqUaufio+reGYIn1f6IlPvOx5/22k0kTwfDPrIvgO/pyf3ZeXkUfoa9VSjedlZ7qL4uvBao3/f3J2g+9Mxy1H3uGKX9PDAZLAcee8EGum8416VdZITnCZjUTTNwbCXLTFNQclw+lDIm6miRRjLfHa5YQgPqtw9p5J2K7eJuco/0LG7as+8J9jTKhvcWuDaavZlDtCMdxxCP3XDs/FHmSYqQ6NXGqUId9/3tfxKlSSchlaFWnXoNtJo0mwhDGi4eDZ0ceQoYONiVq1StVr1GzVq169StV79Bw0aNmzTtlEzZcuQ57YyzzvndLW169OrT76EBfxn0tyHPQ5gGoZPNdjnhBz/6yUm/ueGmW/6n0W2v4ioVRzo1rWy58ukZwcpUqFKjToMmLdp06NKjz4AhI8ZMmJJBJotcrnwFChW54y6dRwweM3pi2FMjnhkdl1BApJB+dF6CZGLpZPIVU6qgUa9ZG70BRiaTZipgyqmCiUdKIx/ELahMnTZ9xiyXr4RKtXotOvQzGnsuJ5LJlA2VK08+VIEzCqGKnVcCVeoCBZTSRWVQKpeVQ1W4Qg1VqUo1lMZ1NVAt7tIRtfrDn0Tt/vEvUac160TdtmwT9ZPIRIM0OpGBySIa5nCJRgVCojGRmGhSjhJNGzpGZk1kiEWuQKwoqg5wMjl5nEJFSuGUUVY5nPIqKA5VCQExVA0oqKFqwcAM5SRFYYeqOxFxqHqTkYeqPyVVmF7wyEtvcb3IYNw0rpc89so7vMjshJlv/CueeO19/KuGTZqNf81Tb/wb/7oRZnPxb3jmHx/+9HjTqKlYMPo5Jcdp5/zsF5f86qpr7rjnDw906fOXR5545oXX3jZqWglRoLTqVERCwyckkekl7e7r8ECnP+l16c7x2fI7vUrZ0IYtUjyxLKWqNesOEeFtq6BtDEeOEicMrIaCtn7CQVszkaCtm6KgrZ7ioG0dJCRnK4O2YUqDtvYFlmuLpja4kS4dXwerPvviqZfL7sc3yCUwvlGubKBNVQIx2rtEVQ4uH+JiwRDJ0jraQGtlE0Faj3PCiuqiELLxTgZjnaz4QVT/3dxiWyggZiLzITj1WjevL17k8c1nf5jXZ78VSQuT+88va3s9dDIq/Kbnd4ZatI8w8U4SSA9In5SCPbU67A1fMBToLWdBe8voZEfaFXoHS1AQpumRvwXbaCH8mO7DRie74LCRx9t3HsEbZyao2yfrSstly1eohEKZcmrVaui06aDXa8AQ4/9y+BGbKasA5JVSVjEiKmZF8SSn6onmr1skU54zzrvgosuuqHLdXb+77089HvrbY08999Ib75qU50iRMiqojILR2awkowyhm9bsBA94txhf+zDJ5CpQrJSSSoVKGq97qlu0atepW79BBsNGjZkwabpxsyyoUDnlVUJGd8a1hUAGKYVDHiGEle7HZ4V2RBGOQr36AfwzyVa78NHRYaRF/1yP5qiFnnWzxFuNBd1DtJHTNkdmZHPIi896deey04e6iRuyBUPdvtvqrSCEshOiss7+gP0Lexf2LexZExZAkWRs9llLw1+NXtcuk363B0Ls1SH1GLr3c+Rls2RlegM12oBjDEMdZKambmbW+q1pW7tpenS+pjkkH86vnInNK1BQVZa9SagJ23B7Pt9W3dn0RjEP4407q3m4zcTnLbkUCpgvSqjkV6zIUjFKRc5suaXyN/Vpi66c1jTZq7lcq0Kdza0WpymqIahbp20c1R+1V+vSYWsifXEbMZNG7WcPJ83Gw8mEEfvandRMNJSss8ZhTtsYrUrWWu1Q+TZYuRDd/pcnb+v5JifI3snbed8U5P1jWA9MWKfk6Bycsz2GzVfNsuXKpxfKqNCmE8K22epUpXbYsmFkGG3ZV2mPs5+Ut/VQ2UW1okt0kCfHHHWZKiccme3i7ve1Gxzjw/R+W4/wZhxGUBVXg7m3QZOoUh0OMLIkw5xnvHatDiTGs+GrQxeoWG+cb1SWf/Q8/uCO9Svf/V4xfjzKZi/onATxOrAijLbkJa4up83qjSYouL0+/+YaRaIxIZnOF0uVWqPTHd7ePWDDbwcOdEqW0wrw9YJbtDN4Dm8H3BYvzWSkIomihgYLow1CvOTa3suUFrQQDKTKrjQYiF6qW2YYOhSGKz7G3kYQbwVefMnE5dl9n+c5oCj+XsPcMUhkjKvkTKTTa7bm4aLV1dxybSRybecVRiBVHgFS/JXkhkRCGnuOn6gXTdymfrvb7+3nCYu0f2t5sN0fllXnYQFNY3f3QJE0vgwVM2U/7ocW+vy63Z5P51F43mW9Xf+qVrbYTI1F81M+KHD5sfGsd+5kMysX1u6vRkKvwJUryogHysv9wq+UBUqJLQzmT4elTCMaWxMKK/fIMrMuN3ZKuNKFgKAUvlCcnu5gmGUSP9zCoM3tuWXTs1dS+iaZ+csuq+T5trdFfzD+YF4U82+azUM50ExE8sllyo/NnO26A4OBDHfYYkysQVKWSZKSQz+2cALS/TnH8Xw3jlVVU9Mji4nDKR7xCkcRon47HIo04LbJqPjVz4OZHLZcfr90rYnyrAkJXXvqfA2Tg+hwTZhtay4c2NGzM8CsRUZr89NLC6oHYh6e0sTvdKQABlwLOtFhbvNi6f9/BIKOkxdgAgD6tc0BOsIQIoUBFTigK7jL/YOzmSjY40XrbAagyfKbw+MHAUztA4BDmLxODDBCJodRoF9/PDi05U6UL0kzwYNlAKvqr6PeP6/avqrDS0SQTgwfRSsNCx/8u9n7pPCstdomEgt+0thCix0MqXKF7XTAESdIZPmHIZtZ2gEShdY62fSlMulMBtODucWzGL32K9as3bg18px21nmXVLnuN41avIJbv3X3waNXzXtm0eIlraXydJ7U8Edusn0yWeTyFShSrJSSSoVK1TRq1Kqn1Uxn7Ny1e8/eRTJAC8KoLZwDwIQ3NkNla6wpAeSmaRzGz1+cJKg/6S72OjKdmBvoP3JEo1aj2hnntKuu3Zwb7hgXi+et27h97+Er5z797OL4P5bCNI5Iv4BcKPykJWkHhTLl1DevToMmLVqdunTr0atPiUKtXwSOsshpYG2BhvmnfvzfP3z7Rql/9AJY1ixYyw+LxJJhSbdA/2y1uP8J/2f7P7sALO8DsHz3JQMAwLM/8+9rZewaQAbXK57kp4HcLiWHzeInrk9OWCnYB8eLy+AW4ezCFkcBZFfsBTWa1eZYZrMAyLcaNg1IwdAT4pMPYBAO5npcGsIwALCwDAA4lv7r/dEUrp6800uKY4Ucj6nHonDyh14fomIOnkklaeezXFwKP/mbWU8tALyTOnYAwOdZ3dvHqWc/hzhMEw94X3yIn/hjjnGCZk7jj5vIWVpoFUTxKAmloA6iiS6GPMRe7gekxxwfkRKDAUJL9eQSn858tfy/r2A9OHh2NjAyTYgES0ZBS+fEKT0DIxMzq198/AKCQjhxCUnphFgyuHF1lFFx5cadqpoHj959+PTlW13f0MjY1MzaxtbOMb48As49QlLASM8kX5Z22f1RJpdUOXrlcuze7uvkoUPVtz+6TLEfhPBcjYTB0QgUhpSGkorapTPnLshZONnYuTmCcokJi4hK8ZooyMopySsquya6xxO8efbi1a0fbQ1NXa2sdazMLSztDRx49EK5/uJo/OSHpPdjJJ2QE9fO+dmlkS4mG45xU9nQ5197O7bN1anTaHbDKaP0tE4kHTswaotqxoZDvOqXnRwH26nj3vTEP+lBip7+8P1RXIFCZyiVuWiUyXMV1K6YLWvSrKKcAyICOiYGnX9jLWJmgYXmzHOys/GmogSbc1WlKgHMLCBWPn4BhYLCIuzmR9o4tsYRNY6kG5OUGbB84gCnCvxJ0xMD5YPKDV7/4vIiJytXvjzFSpxXSuEClXKXVapWRaPGdS107mrV5nftOtzXSe9P3Xr16DfgoUFD/mZg9NiwEU9NMntjuuOGWYAE5eUUKqVIecWw6k5MRM8gV558BbLlDG8bRQVGypwemAsYTIx9DzQJPP362oPl0ykyqonzOD52AGZdt/+B3R6o3QVg0DkAijsAZE6MNickO4kal2kFayz7wB5XJkzAmQS6gAe+Gc+ssK0F7BIiVIa/9xhlgf9vYgFDGdqig5owMMSVXI1pCYaPfVISB8qTs8DILTjwvdCXw7VB0jG4HGiJ5A+EcaDZI7CEic4LG5KFWahIwxYclCaYBHOVQ8fwWJlxVOlNAeHGXIvbE5lhAenmFW8vCbJwM7d5wAb5gGyCgrL3JZKM7tEkwxITug9XkhHXM8O1DGmRHCVosk0i7VQCEw/AYRGokJottN9C7ggj/+wEHjTRpnxJuXAucDeAUABsUB5ikxewsRStU9jrtkfWvG8MjOEb9kTDmpXT3gPez8ms3bp4x3cqK6/X+ljfOkp+p8XBYVDTQ9YDAAuDi+ELz3Hl9x1ll3209uZ3FuU0c6taN3Ab6egCJoEwEdYxDiGHkfhKJNVDMKo1WTIHLPjVt9gCozBXyAoUeJnhDJ2ZIRDhCRBCR2Pp7U+OpYHPcLa73Sgj3+FOBgxqmw3Z4EtcilyOLgAp4Sy7YCmnAJjjT3yu/oEcRGTEDNej7UK4V84yC4Np6ivoVQrUD3L04u2UXmKH5gFCWUbOC7o29HYIxIPowH5YVG7BAlyZAePJbEx8WWAhD3J+mRdCABjOZu4DIdwzUqYGjkjwNes7hyJia6iRmKeK8tYYI6VMy5072LZqx5sta26i8djtbBg1vTIzaSxeyR5q3TH6B8LNRuXhr69KCSKKXf9LIy59Z3cJPtm1rnRg38NnbncH7ejMeirPK4JnLyCJFA/uxcjSOjZyJjJ2RP9LMo727WtLdbjcxRXSgTSiROvBNAQgvlykXGF7hZIcYQdYW2LzMQ/QlU202+Z2iOF5Y4UQElnk35DpcYR7MaSGuflYkq3hiTgEvQDr0EBzVdzZZSHUS6wKw5jCsOXdR8iigEKCDtOiXWwNXl/bqz5wOgmCFuMpj4TsxR1vS5PsCZ8T5AcenSWhMAonezEUB9GWnbDKWC4UqSQh1pDlSpd1cZLK1EmJrb0r1KXdKzaIAAG2UxgnBFgvgo+MtXbPmpNr7ZpClkQVCJ+vP5ZwKwRD3ZGNhxzhk/Vg8o2RjYECIfABFzbhzWaI6sQ30qOrHqn9dE1Bq7wOsUgrUom8Xr4g42NWNs0q42zD+anmqxuwjsh8z1Vzp/rLMrHcpklCAaQp+uwNMhyXGL28kyvcxeWArQnpet6WuEj0fQX2Z1fdm4E7MEAB/SBAOYJh66k1GBYI58Vce9aiMzsp49YjXH366Y6hbUTjqYLycQbyHB3aC7/348PX7Sp4lGzsOLH5CY9R3jNW+bPkIWdx2Ln7SnfDiZxkaISnDCQ3j9QtMV6zN4GXabEqcE9d0+uFKNm4O9LdsHGQfD38ZRY5QViFR0Y0bvJ+PXVmevkdWZW4Fwk/v5F3msu3hpNMh90LrSXqDXEZNyTdSOuWMvUJuSova0zJ1puPs+2DGMirvRcOdhPrJoZaJ98qFppskAzo2kmMWriAq+pAGV4uFfE+aEEWw7PbZb0yQuJtGzidm9FP7SvuDT5CmGvfTjM+jgND/JDs0GcF++x1IkOwRE7dLGd7BSK7Z/8vMLXrNSz3aAnGkfsKGukpjS7x7ZunrBdcY85sYclWg+tDz0ZBA6+pG9YIHcROeUrKWdZW8azTH4nOaSm3c0yCGUtIDkpN103P5gcZbCYTvUKt13/b/6za4YbSlcL4pSVhBUdKlKqe4nOTabDZ/WZPLjxGZ6KnTJkT2TTw48vFj7MY7i9qvjrA8GeQyUmTNwZ259VffqZYI3knVsyKv2z/DHqh4GUxk2LAptI+dO74JA7OwZJkSHc5cQnguCbGyyagrOe/UPuq7q5PKGw2S9flwOBsnEabVV5VvSXdFIhtD0qG8LpfXuIiWy4EbI3638poVoalIi0xSTGlMuMOW3BEATtawUQIhnvRWQHD7f6AagIrXYPhq9b8q8Xd4vRRUf6NkalLiC6TXAC640fKnVxvoxg19scvbtnW+WSJQvgISgrcSOBewEsf0v9qsxjs5VV12gfsa4cKn700MgTRa/NKmoaL/KFgKLVSQDo7ifIl3GSny+JvOUWxd5SeOpDyUc0oei1VuVWJNixERqqisP/F6SRTUwwfCiBzfA8DuQQZbsyo9AWwaizKLkl+HUNSEf02t/zimA+xyJTyR74aLXKK2svzGY0OxaUgjLOxKs0VtFnHasLXTNX6BiH2CoGaUXdrztRWS+SmSU7gKvDtPtszBeuF+ki1xrHoDEt49M1u0kFEhgrCjxkTtt2IKY/W3BRhLth5egYhw0l5u+043uV/uh64j3OEL/Lo8qUx5bS4OwK2GAtEACJVm5b0ZpGru704fev3OLHr3sr1vAiK+RwWBE6432dvX+04YSuXgN3ionv00pzkhHYH73322RohxWnTapcJ+jiMJtZml5CbBuKrATALycXDdNhj4ahntd0+ehCX/FRZt8wbTFBMAi2Ir3Rb+UR/0byqtzTExNmcAo8VLtIDuIKCCTDXjRAucw/YjWJc5k7xw9Lr/QWYgZxDzykEo8rriKdbvKzS6TIV0ec/HDLYQAIGqtrwyiHI4HjBL671DPEg7oMyUXbMjLnZ9RkqeCMcCmv02uctIG3OgcNUdbuaEuTYBgyPTIGphFac1jmpn5JSNyQvYLEr7LRBr4rm0nvUkzrnejW39wqAksqP6maCbLx0GOgweInpWNqiFYuVjCE1HmNrQne/DWXRJFPVsD8yn5P3tgFeW7xKiw2upZunt2Zx0WkVo/pZWf+UCaWK0+PrfQdyrNervLWJJhNtWQEPioc8Usir4LceiVnQzpjbZcxhAzS13oU+83cIpDfJyDT6HFgAGtw92TXB1HSYXDcHCNd0pnqZYHQHb2zakptd3n1cq+DOvvaQHMHOyrUXLZvFaaIKZ6N2pGgOWkATZjeMZRjUCcWJpQ0vVbjLHr6AIA+Z846lUZG+cYWlyoaTLBqWpbU5/0l159kN1DgardjxRR1m2gKFlWXsmhtkiXePmyIaxpu9Bb2E3syiHMnJf9nNCTdnTrB8is0xl9eis+RKjuRiie8Ms100fHWzYGKVLs3PwK3bLOvn2U/wda/Ml0utFtNm58ILltVWw5QBVTUibjuSvKbvfFUwDnLUMRXwZmgaUg++JpTwR1P+yfOTnOjtBqXUSephjRQwqsXxw48uODBg5az8Wz54V9+9HYVPkCe+fz7F9BvXafYCZN5aO43AcbbdsP5T9vaswB7TXhUkPLUSm8XfuqRETpMt0Q4iJcjuIKME5DqqBRi143P4g76yDODyuWZMPqtOFD3v5ea8j8T7RBd5LsN2ZNg5/Nxl6TJAOLD4a2xhD4nkIfTZPkWn5WEjoIgTHV3K/UbWRgaxyqkRW2gt48/jMoWgcH6na4ZgvUKjRcysIcJQcM3omxmJklpYqjLi0+ZUI3i107ZTQzPHVr40scMo5KO0V/nFh523b901YVnNjzAsllvhDEk+HU7RLbdTErYvLhpzVewtuZGBxglBZES0/FIMMljvk9wSoEh4a7Ka5wd9IJXyAmLK9HqKqiTK2sttiLLODC2Jzx/Xoi2+1hHFQSlTX4+Q+4oHZRdMzAzc+a4FW7Xy040D7qXRSZ+l2559DcteoNg8nRobIi6Z6cAXS55a63aiy2kbyCmfJfpx/KuQ6p1w9jzhBfkAQ7tUeawPuA8tV4t3OySEcnDRDffc/XMfkUsNn4HmHb14Xz4SdXtsYIuXL5ICHGYG6Y0yxzEKh7qRIJoz/aj7xpgnV82X+2CAlgvAzD8uf1zEdWfMSisg0NpeBMxgOVlDUsbXGqETwUQ+gV7mTBzix9J1FwbYzZJ7W/jS22Mh4uQBLGIfqtsF5tDnN6gdN//6Xeo01KRXAdGKuGJ4tN5p0mC7o/FSkR6c1htzv88x3fWBXNqX+IWziujQq22T+Hjkf7RxE+VEF3sWzS2A4StGIN3xnFboU3GbGayjhNvTFoxLEy7F2kIZ8jjmkWnuwNtEQsOSDQmNlucLVjg455bMymKBtMYmWxJPA2vNLyBvHWNqpl45hkUSn/Q1NXi/KHKEJubCydQGCVtyxOsMhtok39pjCDpEpstHsbZr/zC+Lkyflsn5UHJxW8uNG3pLMRjh8hrrAfTH8q9L/nhEruY3/MVzmuIbZPgCdroumYO2OX6NSSAdnkeNJNN1/EUg7CMMm5K3zYAnkrkLLxsY2/k38mkg64Ss7gr7/lQ+75rn4cWpS472/RF8xyJspobJKayhBOmpVPO5EhfQ2ckWyRogNHXVsei/Kns9R7JjaEJuG6Z7Ra8rQN/bUaNZeSvuedb1SwA99cxTmiTXPRoOC9+1iFUd2WfPajnRpSfpZg0FPJ15wb56GHqAFEIMPS6l96ie3WaXQQHTbAeodJ51PffuKyUpTEIbWjzitwa//TBUubMm+sGaa9VjOAeM4K8B9UfLepLnZOb0pZra82yln6WL6JkhlCi6u7lPSylq/LnJeVY5x3x5Gwu6UJUh96kGTSsq7BmjFNv2BxbpOQOjRFKKpkCWycBiDwAJqwSD07V+nD6NBqSSb7wvHtSooHuasrrJEAwa1MquFWXs5TeyegE43q0j4q4TXAzPiMM6jSVb7nYP968knPVgHyEdroFiuv+Ozs4HEFuDP5vBV2i8ee4xN81XeaqxGAxV5/uKoBbr92anmKof3y+lNJqvXrMYFmJ7WGmfpv7QkhNAozFkwiefMTWf+TBsenk4D9PE+r5H9jvl1MnPOSvU6OubjYWNu29bAVe1wKO66Q9bXuBZ97QPCJKBweK2WhLy2aqnDZX0AcHGBdfG2ndw/t4xfHN1ZlGRJkCLtnmHi3LzC2f6Sv03HmZ99srHuCH8urIWGZq9lKl3y0ZihmMMgH8lIvR9rb+qbTVbzNgN2xnE7LmMZUNvU0URuvy4yq4o2JWWT/Y41o0e7kWNXvNIM+wADqcd21M4tkDs+tl+edSDEz3Ns1FSOcVfs3lLh4FS0FBiLCcx08ojbTV6mzJbpNqst0V3GQ2MtGvU2nJfL/bAzPv05p6CLCHT566MF+FWMrlGukmjyzk1yGapGq1ZfV7OWr61BMWe9x8sLmDo2m0yv7XVGz0lH5OE+cccNnjIGxjkmBGztbFeH2oCsE+WvQJU6ppuzLLi7gDdqcn7w2ZeM31aj77Hr7MJe0rs4adek/rR6HIz5uCWP3VRPnyxYSUntiT1PuWjFNHCsd49TzbC+dwuitb6yONi6O8kZ5lj+2ztAi0xldGRUKUqVxFJ8sWLyt9arOqFd8HUO2YwBzfv8PaZfrEvs36OqNp2ctc7d+nwtJ6iXDh2tiJq/I58eegze27sR5eve2kRTN0YbQJGYbRzFD5y3lCGddPQpdGJr55+MeqAuqY14gg2OeenJDTy6r099I01WGmLSH6xMTziKP8p8Y8baUG5enrxymmf4gne9P92mP6MThzSAMIXF9yeyDcMN+OPiPvIqaXsk56l70D3IRC8+QgqSZd79FJ35NqnsW+rdCzneoSgvGA9J36JrBK+feEh8WnbUxLnClHeD6YqkJWA1Miyiomz4SLiiqziGhnCs8V9FoTmwoemWEaOjcO3Jbc47cktPAjm5IrrEvnRlr6/rLEgePOhu1aRU0QZcbrIUznVtVrPEdtRnUXG92Lqc7IxlXzYItQdBQSNJ9NzS5Nx2+DNo3DkV4aN8WcEpm9R+2BvIgNmMAC0yNcozyuhzgYj1OX5JQ1yRBiMd6O3RJsWXCgkjpPn4ohsKS3OKtZ4IN9LUcf+0dcV+kwwevDh9yB406cp1fhiLrs0e+OqnAE4GOac69vFt/sKs0nmb2BS2K7GrmWLeWXPl3RF9pzN7F4m3c+2yu0fNfPXLc9Y5tVCBfZF6NspZVtBd8CWZa3ENt+ZTfGthDbgWNQ24JXv7u3N3DcQbG0dKMzc3zug2w+4W21efx5rrKqcPeU3I4gU2JMV5fDrWL8eKN48idJeohNGT7599VJaYdFv6QUJrT1+8d7+Usry3HCDyEtQalT77f6fSDDpT79jl6nOhIITQHfgsxnP1uyNSkD82eyx+lrmeCAXBG/+665WZNa4XZlN1Tr34s/yRacp5PWZHM5FENT6uhbdNXux1W53ZmtNjjL4Upw54nabbffu3nxk7t5hStsAIt/d19YPZVixy8gPrrl/8g4q7scKQPBmlKNGoixzuPMbjcRZSvFw3PPxntPql2hmMWyxwk+DFBTbG4ckvh9vet5NcMbSlY/+WS24YaaPlHgZJTST0qLz1/EtbHecE3U4zvyCC2+NJSlMlBSBNNlBu5bnZKDaZG5tea0YfN360D5jf7cVGBLcrZLsKt/XvlFvFOT2hSDvt74R78bqdgm4ceZ04e7WrKmm8PRpcHztpqa3jbmusQI481Nt4brTc6vbMfDPbwD/gX+gatdJ3iIv/H75w+CuE4wnGOBH7udzJceMx40ln81xwf7Sukekevj50v2PiA12cDbBCntcShaUlr4DI1G/JqVByyyxm3L7LAmOuNQcmJtmy/qX9F2PF2a+7uCL7VXCA2Y0wcjYURB7aC75hdaV4krwZIIF8jqy27zMlyZJIvklEcMabVk2E23dZI2zxzDVZu69x71pyrr6jlGn3ZONOJjmaOOyanavJd4ew9bAjCaDleJAsyzUJkZJz474kGBD0sFVEokr+Yv/V4NNRrMD3EkgP/9htx55+9CaRIN8Km5HSZ24r0FVaoXMGeSI1Ujwxkqo2Td+KA2oAUDiLdbw+qtLMzpKlU5cjI6bGXVmEybnOypicZDCHxZgDr4AUlVaIvghgV32NhVXbCwW9ZXmuAnvP/78TaTL476U/liKle5650fvjYUX8Opd1LApH2f/cRwkoFr6uztMmVXlWojxxkahhOtzQIM5RaRfxpeeqihaaJ2W7623B2xaoyK1p5bSeYIhOc8yihw2b/ormbFPpoGlhC/COfzuUKW6p1xjpEddrgN4NnghMd3/MHuheDhmK+f/3ewm8RwbBuU3DBaD1E7zXlei53u6gdEuLYX5x3MyyZxl7mmA+hWJpYtNOSwqd9Nr31PiT/7X5uCWyvVyZ5CTxbgQs7DMXB71hUxgkjhCLFN8dFf5mXhsVfMfYnuIguSH+p1NJqdVpODXlMgSfrc7EKtfvZPAGXwudU6vyM1V6nM5MZMG7PcrPkNJ20XXmOjO5DJzAhJnwnhOy2n2L37YtUNmqu7qEk/J31UGKV/eCo3O7uP9iLyUY8wWozS6V1iClBS/Amp39LrXilU/HkMXz/+AoN8CJLe7ClzN9L/uCWmqV8S528zYNLWJ5sCUQQmeGq6mjO589uNmzC2K8URDycjzMpp47uOFx2JC+l4GMp0Y8vwVcr7z0wKITwiW5fD6S8IZneVZXp/oyQ2XaD1vEzTnbsdHbFaKf7NWcyi6Vptavh3Md6hYl14psu2OBvONQiUEy9Nef1eFzmsKyxt3RKRZ9UK+AcOC+fnA2XqPpLzSL7JYc9fiw6YafQjWHKR6IYgQPpb8OSjaAprB8kjCxnc9rL9iJHSjVyPoLK6R9lWpPKk/RX/ZQtP9RAvD9XkBHVXyzs/I249tI0947sYrg6K8R6W1or5adZh8WPlZJc1kEpMikEkj/s24+UNZwGYwZLz/iwhZAAXU/M6iWml/o6qIcNoYM/3uO1SBHZ9dzgngjJCYFrGWaYuBfcZjke61MvhespV8XNQBvkugGGOXTi0zz/x0Fi+qOMOhuaYjQ066VpVtCNBlTHPs0r4oc++D+07sR8+wyLnd9k+driRlrhwKs0BwESHmx+hoI+7708lOrZqx7H9nN3+tY9CiM9buPL+bKMWbJFCvkuJJU5NtvzgdNNYwa0LDS9VfHdm7JzHxnYY1P65ZLoKE/jAP3ErUvE1D7LGwBd7h2bHHsud/2rUfpyXehboY47vBIPBVgtGiprZHYj2xZrTntFQKU0oXPPc96XeddHB43b1g91OC/qd86+6BLf33kOqncH1H/H1HcNVPIf33phtnGmYAeedfO/8KDTw3eC+kfLj7n9DgswM68ORNo9GVfw8Zfoo78hTy5jtAbCM0Em29P89nYN87X1yr3EupmiNAMfOK82YUK7s0e43tQfcLKsG3InFidHMspirOl0IkEHC0J2BUp4UInqmxWp1exApbIQhGvJDToudfzlRc4PN/UmT+Co4kjwmK1ar0wkdBjpIPEZ4+4TlJl9syMmxyPtP87cV8+G0YVGnP+EV4BH7loeN32ri+bCYKxcruA/59szJTuYPauDAQ50rOPLqPxa/nFmILBIvIffASnAx/HSu3lWJetpmC7UvBQiXJV6NgeC7/9bkEtn2l8xoAgvLLoby9G/SrvRbv5FZHizQ7otdnh/GBOR//zvSlsZBejYpsXFONkbvb5LnFJvEfhW59Qb4sEsB/R0Cbl29NW6royyPK27iuAKHqwwIH3p0dcplOlrFamaMMZ6tyVHFv/TPl9/dIh1FnfvyX678gpHTROvhxthPR4FjcOoBajxi2EqAaC/HapfjTgwlGd+TSrJ7Mpb4lk890qiZCAYbyOxh3HGTA/UufOd1Dbp7JD/t93cq8vvqfwUm4C7zzkoL+VKNuJj//Dsr2Ts+izBybIQaJKZCX+VXgFDwFc2/Ft29KrvvR+K93MsfRaCHFQYnB5HDYnZQIpfShAkS5ylaakZ8f4sss8uPIcZu9dljz/MPv7+KqP8+9i9xF0kptgtz3uUbaLV6NkXD6qzv4eBM6MOxC1ySHUG4qGfSGtsE5Xy+dKO8rfodVeVkcK5NtDcrnqgLFqWtQgm66jk3qcs8cgI9w03UoVjkNKF6MZHm+WhciuVUykvy/snjYeMvADUAijdTJ/K/pUyHNtkE2YBZ5qSq4JFOFEIrFd0FpaDuc3bWEKre7fMJf4GQ4VNO+38l2h3rGJbZFZHHIhhATkCn63BaygyHC20zd148Gl6ugkq9/NSq2rURWgqfgdjiBlzbtNJqG2+Df5KSN5nluQ3iJU9cB34D/nD4yuunlqzFiLM8esOQIq6xwpSCLZU76lW5eLaLoAsrMcI5GUtIDjv/8zDT0M67g+B89d7tzu9Ch2MmBMvL3PtbF0mo7WY/tzefx/Wak1NguyJ+AJ5BVyvYAUiOqEeUfibDCmAxRCBNhHcnPy6xwO4qzNm/GZJ7gjGw+klHgNgSo9jhwJy1vRVZ+u6DUaEH4fl7+3j2d8IM1BU+lRZle0It6pR5ZGY+uRlf8SbS722oLlfJpxSUzSdnw3yMIrgyonHN/kM/NPzd9IvcWxe10Uty3ctWRKrGgLhwWdFRpIm/fhzNwG/zsDzVZIII8Wenx/CUVBfBJundfE3mCY1BrrTSQ4u1J4eTioDsp0YLrQRVSMmWmADfr5yw3Z7c4AWeaaXi6qFIT8K+eFi56W261lfXIzKauEd7TqjYmEKNT5sw/hLx5hY/UDQm63PS1vH/xtI5pm5F8lh0SB87tKX3dyH4jZ81hZaX+F4NPLLXifPyvo+qc20a+Unbvgvf1PCafzFnX7sCSNmsHxIafZ6UfuKnDh7nGly/glPuitMXvSTfuoxKOUWi6/bkX/Z7VmWoPEyXvpmV6Vkxm0eztAD4Om1JhQWak10MeexAmzqLlcfMfkbHzGPCGtsHD3MXyh5kxX2ksV6sdN2R7E+l6PuAJ+PL73PCjPGzdOqq+2I6p55mkZUFlHs4cLhNt+sbm5nVzzOJAUvOdiI09rlAsifPvkjiI+U+iitVKVBnaFS6qxOWqfCkvrSUEs/8UV5c7cClF4rBckFy9FgjhNtiPWBzrcuGEWXAbfGjgHUT69o+RUXx348882KXM6qj4sw1dFo09awUEyXWNmz5eUcbvVVndXcrCYKcy3XDV78d50090v2F3C7g5ZrOL0020g/hI1fSXmJpPcAO52n18fDxwHgxcHsdx2/60+l27uCaZP2lYIaGg6ruyJCOqSKVClSc7bX7zvGDnN8qj2c2ViSHky3VpaasuZlmZwv4yArH8pC+voShebnXiXuHs9uzOy4I72UcfbA477/yJA3BXn3CiImewL6eI74/3JpFO1Pvw1ckKwyCnwpO1vPaVohCfItNfqNRoA0q5X+FDfKlP3WazHj2b6ntxFXXzGX+XZLRXK4NvP8udhC+/8+1+N4v/vuHgV+ZDFWRaRjMX8dQBygpQFbgZvhZVhx3jmrZJ0HPp05m2sUvwRm4rl12yY19UlkT5NsR5u2VVXyv48uEG8+/FLmG9+ZefsnRhd9+3KMpxUvLRxRqG9iUtyIBnXEa9JYEe27mlX5m5/iMWGdaFShL2GVi1/hU4MADy9ow4HyT4+WY6kvjLdZstllbo0ud/O1w1P9Ol+aqL0WdHmqXgIzgZLhLxYHq63+VyH+bWpjlzRX4lMc6UGGhxJyaa0e0UmRIqEuQy3EggJNpwZ07uZ2y5pdCrfJVCiBtJQNAoozW+HJUqP/+WIFW7/b1dtx0MNwNSW7XNDXkuwEmFfo6Hy/eCqx5yoWTS5U923iNda7Cngv3VSHppec59g9GTyrXlDnoGs5ihNyoZkP9fK7f02K+iHPjz0BK47cmyzV+lymsBpDbRr/uXq2eQN1tCljxLQA23wYN3njXpDvHUstAFvhB6V7s8lhFtXzfQBFBc5zUvluaA0/6JPfw+ch/0vCHc2/kDJcLtHh8sbPyCpc1/uanO7WJZmWhbiaQPF5uz4UUFvF6+v5rAf1xQxQTwIbjQuGQCtR2O/WIM4zs08zUWF4L+sHIbl66HterZJaPo/Y3sj98GEGdzrcTVHWqdWokT4mYt+txbylZsffbYlkduajpWQAiHdhCA+TyGLiKLan28S4uYlM1t5lKEvi13PrSsPQ6qqAQDmkBFrZ9/S/+zS38UoXwLt99HXs+fg+cd9k/sBYIyUfD5Ye1S2FYvTMlc+/XfKuGXjN2DaS95r7E9tOhyGXUq2maFL51SsN9ZTersEVtGkdGl8YIQuA1WvOnpWvs6gml9HfD9DEsj3bGqs5wUSSovNXUJu/SbbQI0xPLOyQUQufS0WLDtLhm75Pb6J1hJSvTTE7wJBqGx0SvBGU5bNKsWgZdWUVIB+oo9C/MfoUHYax8Ar9pWwaydU1FddHr0L7zHPY9rOS6zYK11M7I515r+Qc3L2xJy5B0BEvnGaqkulJevC1bL9JTDF0M4SFhMM8GG7By4wBI1pj8Ze4G8shG2wHq44/QmWrEABwUvHiZqYRMMAqimkuuyShogKaFR1GgIhzVZWWG1IbwWCE1S6KKX9Vp7tS0npMistOakdmiLIS2PJzXaktT2HCi/gSEl4EzN5MO+BfDo483+Vwb8RVW/vDUQ+eVm8M/m7sh9q/uqCvXS9/wvQaH04FhRxGY2Oyx2englATpvQbEC1XmScrUxr6xb5du4AHrX5lfQTAouLNvv2Z8b0ZfmuxlWYT1SX5AX6pIi6gXPwiX7CgjKMgTtFuonda3Tf36HkjGEApocnCZgF8WbU+3ygZJWk/q/v4NsYgvBpVRMJGMDLDNmJrI/qTDdKkjVX1hb48ceh4MWf9BcJ+w2pB/NvfIfji6xrouKGuXnATpRh7KKqSb7lYA+aRPBhybDQVhfblPNlK3jD+1AXa+a5zfKRZQzacWV7G4hy8/lbDX/18KbBOJX3zDeAfQ3NjuI59waKQwoCTlFqXpn2mRlfeoqvbeIk5NXzMn3pq5smMjZ2JLnsgmPDhPq3IX41o7jooxL7YS2oJtYt/oo0OUd7XS/u861AKzB115emwelmgUmmwKmPzgGxZqsn9uJ6c1NheVKtiff+dupJ+w2QEoQ+FFwUn+csdaS4Irj2iG9XqZ+xZhpXUFrDfKzn7W7Q3Gvajq1tx1EnreMl+HKE/Th7/Ux0m5oLdJIpQQ0SPX6yx8Wtdz49YZPXxhaOAVoKL4/wYlesXHWmuiMS4MQj1NF/VjEvoJbKsGFp+0G3HvxuN1MU7lAHYTdmvoaNWAlBJr8yh2tJemTFl8lPy/VEvux5SfOYeOy1FBxL2g9KfmNRmnvrG22aasblA6b3e2CIbcJYlzxUQDk2mExgF8SnOQH6QyHfVcTICWoilKgDAGkVr8tjsa90sTJyXE18+1wKz/flStufODLLL6ZqRPYIXEJXmVXOEhbMwU3xahm1qBOumAnobKbUwKyPJ/SbvMp8mT3wIMEhiX240KCUbnFtIxdXNQBeuRPn6A1dVY3QVnVDRpbsCmg3NFclT5t9lRxpA7alTkdsDHaLPocCPFCEKwHF6KHVg0Og3Xv8z1Mu8HAgBG+EGHABgPT7nHh/NfEGYuFBFztYob4WjeYfHLH7HWn/nN9NmB9kR0O1x8mE+bIKSS8RH2eqr2dSXlhv/mzCV+w9n2KKU6Vgz+MY82QKdNEc5YJ00jEtdPxmru55uXkLJs0tfZBQ2e6xgcOfaFYn2V+xxF6w44ryium59EVYO5D3Kz2eQj2kylNVJo/BXuxT5tw+mruyljrwlIKY76Zz+v6Ccy9n5/tR/JprloJJjrmQNZdIoH9dGxUWkrPJxjdfZXmSi7NQ6bbKOjGnwClFMx+YCPXfUVYYXoHAeve55leS6dcs3yUXZnKWo4XCPBbWExV0/dmDZn3hgqmLZCJJC2dpCORDiWupwvupeD9dFo1PiUazLyPVf95wPruPYPzIueMMFlhU2o/URbkBILZNEcN/yT6k81JrXTyGip5DBCqS5ASEOOJIi9kAG6z15DVxe+MUWQP2QF50y3ug/2hjbMZ21mO3eoHZ3+S/hQJ+gm8npm+hRcF/0S53B/sB8zXTMs4Z89WdX0syZXailMttNeuhSugkQGS5ZaG+VGR35E1I1TCxtj3g0eDYPlYFK+S3UMYzssjTLCHeE0xrp857YwR3LBWg+tn9HLqfwB16a4fuvaMXly/RosbZoxw2n92Ybwm0M1GAx9uvABeJbAcC/UDzkhbUubPlBc07ILcQkoYMxEQOF4Dil7E3ih079fzovfrXrAleeOO3Pda7j4CdWTHVn3RR0zNLQt15QhUEb72KdVSnCq15Uo+7oo7e5aT7nq1N+rgIF3s2Eg8Yc2RniUDJ75G+wzdh1t3HGD9zQI/d3PGW5CfcaHJ/WvztvVKpgjHZzSzwjGw8lSHpeNCh7njtO30djGu4kJ260/ZTm0/dWf7he2gnmKl0i5baSBgqzkLsbRngdlsX23/2Wsat85Yyfh7tr4MOgWBnZT91HZ8i9FNcmDSJYMMx49iJ6DEvI2GPQRJIhMbzcfKCcbXYCoHmO8lpXGTOVFYdpKY+OyuXc+RxIlUdBQnhYNDPw8yJoG5/5GmCO47ADVRTHp33bp3iOIkNhaHS+am/fMuMLvDxNcIRjmWhMcyEyWEPYaNPDGKhsGRcDLDJZhkGbDtS+vVmWl8GIGPzy6vxgc0fFWiNdfMgZM+iI2F/r+fc5/wvRkthPH5Q+t5ftuLoL8vCcNOy8/6ljP+kexN8y+8bhrN3jZZs+Mn/cojep+efuCJbU/kmSOAX9+P/hLBvry1bJ4CkPonOS/uS/A6nv3WYionr6KkYmiuorgCPHy9s1LS05RzZtVo3pN9HUfVbVuvlRZdWp/sxjazTIfa03iEK3l5V/5g0nPfpBCKTMH03kguQjen2FOQZwqXVX/1PzpZth5d7sWUCmYKg8szKirWS8srZZubOiRbS8oey6hJ4daaoiFloVmdSPLwRESYxV4rOEXJPkEKGnJwto8KQFpCRataWmHOS3NDCsX6x8ZZ0gwTwsvO8/D4UCaP5NzSs3lT5aW9cU7AxSA467bJwfeHhOS2bI81Oywee+ft3dAqsd3pqig+CE2kS99Uy6WZePfN98D3ZoI2KM8M6LIUgUK5zgHBndbOnk5wfxvlz4eiOOO7BDP3LnrLl8q0r76hjTjZDiVfACs+y9/BypLawtwC6rmjlmhjz/lavHFtJuf9bxOarSyBikt3PLz0Vx9DMrkEEzNFj/1JS53GNZz9+8NTfopMvcNiXwImlXvAbhl1eyyjg3Y3MuAwj7nc5tEBu7NHyiHZsjQkSCWjHNkseG45jrYwwlH2puOWP8c/dIFuM9YUZDcaMtMKr3vTMw0u02QwPPS0rjoyMM77jIgkO88U/sTCM5USeOKG692ZXdpLOr7zDV2PQdmc07Izhz5IZ7ySJgeUgwbEbcRuxMCNa/FrEVf0CNHfcoDbeAI5AZDoAWTAox5GhgHJ13/QKxSUIE5hOSLb1A8NVm1Ll70bHYVz5Jp92onXtfh3z/wu5x6pGgQUa0pAofCrVIpA0oNBECD+S/1MFKqrC1lQqfJvU1O/lafO3JKzBWPwbhf9GgSh+3nw2ujGaxlZZwu+FWY9qY49lMF0xbkSznSctsfDMTT5Gz/LeJeXnBCmWCCF9UYNUpFuYjribKjNnafheHMMUf7jf2PxP1bqejpM/6h4lUNdXJEBfJ8HaRbIkpWPc+d2CYmkB8sYUS++h0sVfKJRHYeO07a7sGizDwfuHrgAXTDXPG1Zc5JcfDzxSGLJcfJKy2KP+Tx0/gD4g/DCVfvV5+z3rtuvvwBMg3aNHQxxOAf27d+L27t/3wH8gb0r54Ttge4je6udeLHB24AUzmOAQW1/yv7kpSsA/OQAshvZ4d/3GgRuove9AZ25f6s/fycBfxwZvwpfHbePX4evjy+bhp+Hwfg9wvRRDgbbAX267/PGWgKxehUHh0Gsn+x7vagQHO7bVQef+hZk6S8Frc8Eg4/Fr4nX8dZYAhfzhEJxCs3lok+lNk9giHjLKhZrhRmPN6/o6lZZ5C9y2bEBJlF2JxN62StMimnLDd1uAVl3WFf+YrJ+ucLSEa+QMVeJGLtK/Zv6bdU63bqdSA7r6lLPz1eLpDeIAfDhBIQPJ1gTAJ686n5XRFaIqEWihBqehZdwg+FUcnBtqwWHlmi0nw82xPNe4gEC6+dZR1znz+mRU2drTaC6kTowSKFJOyp1sIFGaRzoJX1BJH9Bcnc8mfgF0GX/ckW9i5GC+3XnkY2X9BTy3v+B7u8J175mxjIz+YkZKNyfdPoPODSRKjSgn/nXtOi91t2uMiK1Bjc9w4V086c1QOaxxO91zmaAR0bWa8bWe+whOARGPpFdkbGu32JLr0hlV55KmfgkhXKHgt3wM5b6f3CNbXm1DJ18+Z+UEz+lYFPKq1hJ6GO3cTtfwYLkjgJiAZh8RF32XtrUU2hSFZHQThJVipV85nSaIhckFQrKXGUUaAcwvaibYWfo01oQrUY1Ds3OEFhmIa9YCZ2vVMSL+BCwfJ/GkqXi3mnyUEFZavxDHWtE/SP3Lvdsr/7/925nABVaRd9srozon6yP/PZR0gfyjzr4e+vD3zW4lv3zLbzFHt+pi879oc9OIkcvVer/a/B/itdGqYczCLuq/xYStilwZeh3lW7lDcKvPcMuVXi78vtFOxVgNQSIbI+uEy8X2p7Xqdpu3ZrEZ9+90lP36spY0b1TAKcjkfbt2oBQvKnCUfLVlEB1TKGyTLP8s4elsefrjd2O2dj9K3ELpzZxj6NG554fpAT6i93pjrj3021eTU1udb6TEqibV1OjbOggBW3+Z4dbqbHjI43tHq+3fzZ0zu5U5sbO90hQnZRXQj1vPcnbEf+VQRzarlPB187kSD60w0mgsePXje2+39j+nfwt79u54rKrM79EKYxO8a6xXBzavoLQT5k5CQd26GSMz88ticdn1I3tHxNRZGIUlk+YzyzKLlydJqBX+3gAOLfNqvoFAJybvxrEDianrtB/8f1vwpe5zMqb/ezYc415/lo/d2CzTLhsODxFvmzXVxlf1DL0QO85KUouQQD71KW0wH4g4C8wUAf1iYFz83rBu8OcuQfhJF8uVYPS/+pqlKpxzH5RxSJXDXt+O6auFPDaGK0L+5sJ7z7cY1y7yG9pKEDXcrllmdwfN7Dc+ocItxsY9uMWtAa2d0xU7GzQLezuVhru68ofAxypdVLdDne/St5Uh+le19/YjX2SLvXeVyu57mbuMZ+lDlvF2kz5iypDGdQJlb9BOB4iW/eiqtYfk5cmctLjkBe10G56DO5lOn31OOjVPukTf8K9dPjj9M+ZRUDywPTU7jh+2dr215dVCQmfwqRIHvpBmTtjcvN29vIaz+EH8XmoOgdJPk2eXrcXwQtSMOHptXk9nY6fi1vBmJ9dpPt44fjkC66ay8Q/I036D/MEdVlH6PLfOiVHz7lFq12XgMXwm9w7cy+wPItTNwTb1/g69ZHsN53WCM7ek+q8nwO93scDc3wObZtbXL9hoew982+7lZ1b+FL234RwtcVBf2BPs1qOso9Wc1wN9fUqsZyt+x6w3RlrmGdBfNl1qq9rwlwsq7HtddnbrOzFsp93uamlxv1KxAIIuVmaF0hr4Izs/QDtey0XC6pht/QrMQwhNw40Ia6B2cBenA2cBQH0KsDtirb10pXClGELx+WLbjjGXmPwgnMERETMS4t0OdkyqnXisO7Guloclj7+SaOCHOcCPyuQBHSqdUcfVmDrGWuYZCCnfWQ8uOixgvS40BNBehJ6wvnHkzEmet7zi7scdFfrZOlfq7HSNnl3YPmazDb8r50IIp9215MIuqv1jeFqX2bDWAMKjnzfGfsPu+htwysCjFNq18oiBhCbQEwLRPQjASHww2lxnf+sWANRyH7kxaCdFxaxt9fVOnlDc30+Doj8acMXiTmArgLsjrPYWL7hTjfSTXQz3U532Dt3B9Rjg7vv1g4f8ZCPecRjnnDG07XNdskG5O9wZOjYyNhEZppmHU6yow1Yb03szfoe0sW3zyrjiMrCsfF8kPrtf8eJh3zMIx7zhDOe8syWfTTaS3kye4vSBr+1r1Q4D/9+ki4ffazt67/7T3vF1v37D/HWYljGtKyA+NjzZYuYP8P6vi4uyLXUC/57qWcKF61fff/l6t0HsHdNwKID60IANQKYcgAobi/duiVhjtDRbJz+75eSrnB+07KvQzbZSfidDq6u/vcTTqGXofikH6wJUPUOA+iMNfbX62poaz62LCwLXz/yffPB8/FDdd1KcPf6P8wTu7wxhKcuWvOde0Hb5Vy1/+brXZh6S/576nl/tlPq15ML453LJ5ZSv/z/U8bYO0WovQK7Y+FLF35a7D938JObz/99yUTqt5mFhWItbOX7QAoAvt8/e/4XQCNgY7bDU3DPVjNa0N9uV5uH7WFbigL0T5eg4MXpDILFXKhrm3e0uhiJlJXN8GFPC1uw7WrjzM7uO8HBPVvNaNqutov1Mim4Z3qGyiSwIo/MmVnP50XQuFUHgm+262ntsK1ndfEjujqTgsZgR+1YbEAtxCw1IItZXaDsovVngLvejA0D9Ob0xBNPb5ODxq06NK2nIKGXSUHjdAcdcJ5lQNSzAL5av6Nbo4Zt72CnXSrbMtwG+Gfbp2oUsevnv+2KqlHDORMxL5lRNqsyWUiuVxO8rbuFZCJ0CHV7WWkmIGcCVgVQJlQBdJmtnjnGExIItne83LMJ+f8kELwWPCnRIGnMNDudGQN3dEypywBRbUW0MyYixx69U2azEtClxnGuySB7wbhDG1mnJulbD9NViBMYJRbGnaBwjKsR4yPFGaLvkvxlhBm3I2btR81fNUdB3mWt5FY4wb6KnjtdUTtuVNwAZpECYxyluGdTSYo8pskToRv+Jutn3C2Y9YNaHaecaOXQtiK0CRMg5XKcbZYmDFue67W2LNhlZvIvnwHi1YOjlThvEJAX1m85ufvs98hUR+rZosnSSDJ5OPa8RfP24ri1QnMsQetl3Szz0Qahgxix7SC9+y+4utt7GRZ8nRBbSPkj3dpbgWiP33pNRj57ajwxzHncXsBHmMEftOkQuGXE9g7Xzptwk7VC8xGCWW3q3pmfBveJjbCPqN+qm/FtsjN2tMQW7g3mgb2hw1ucEDoIxAZg0orYKKqjEglhQEkJy2mbcDKtCIQBAjFNktU0Ga1fkZyNCu0SQ7t1M3HWaKmtWUBKGtZYQ67GaL00e5EQCVAzmIw2iUmH1KIk5lHa7vVnr3DvbHMOzkIMe2bFreyJylHihNiw95x4dVQiI6GGQEZvE0wyQrJacsfWGlK4AgklAnFuto5uY54mWdZzs8dMPm2LnkwgGIJ36V3EVV2bzNQOiQyl6hxLDPBQiy+qvokehti6L8gCbDahqrroWEtmFqqJMQAezsaL/YPUK7UpOEFSZs9cuYQL4KKu82/7nGYVdJxxrCXpsszujZGRWlvH9j+kS+0DOMFCmZ2ePkq4AAtR13T3htOsinac0ciYrLFxDdyFO2vHlkwRlPepKms1APsfqUvtAzjBQpk9xX2UcAEWoq5zrjecZhV0nFFLHU3x8FZqTS2twC/LhRc8ubwOE9xsS9anx8A8V/kdF2zUhXxT0Hzvhhn13PNQu6NOco8wkfVdhhWbi1U2NpXTteCBj9YOIlO2BRWzo0lpotIsZRpUPLDsxJgPrvduHq/uwl+iNnECNXmKEI+8P4xmNpv6JyGA7pGgMpOGtIbA/4pT4YLFi4+tPhenyF0PvI49DhGlHCY+0876xa+uuem2Pi+8zX0kQBeyGMEo7mYCk3mRV/iYH+SsEO3TJWnUoV4NaUTj+tcpmLuv8U0e4Tl+1i/4Za/yG94YNrj1EReCuBD6eB//33BNdTmybOFrbVBASA49CYRPcnnGZFpmZHXWZVO2ZmdakQiVP+KoAgN7tTXN6LTbWo1adauo/dg9o0+8yv20yzus2n/bnblw+dr9PqHhJAmSCpN6k7YmLSa9mPRm0kdJXyX9nHTXxkJG0Wg0AU1Hp6OlaC1aj4bRPnQxugbdiu5Dj6NXoi+iHy4GyQnJluTVyfPJO5Nfx6AwuZgKTCOmCzOMmcHsxFzDvIx5G/MJ5hvM37YMrBCrwOZgLVg3NoTdib2TokvpSBlMmUpZk7Ip5V1cKq4c9xhuK24f7hjuadzHeDTeiffjS/C1+DZ8P/4kIYYAE3oIo4TlhMcIWwn7CMcITxMuE14g3CB8SPiSmEL0E9cQzxBvkVSkPBJE8pDCpH7SIdIp0jnSXXIqOUjeTt5HPkL+kaKljFPOUz6lJlElVDN1lvo+jULz0MK0SloTrZu2QNtFO0j7gHaPzqIP0y/Qr9O/Y9AZWoaeATN8jOWMS4x/mC5mgFnKrGO2MweYh5hfMn9i/s5SsVpYvawx1grWBtY21n7WcdZp1iXWs6zXWO+xHrDp7HS2lA2xQ+wu9jB7hr2OvcDewz7CfpJ9kf0C+wb7Q/bX7Fts5CsRvrbHQWISuZ3vUteq704dScFIpY/h025mXHdx3eu16LDLFKJ/53H12hv//fX1g+nCW4TLSFyZZFvO5Ef+kG75W0bkVVvT/tor/Vbj9aCK9UfN0jOq0Ctaq7e1Tbt0SJ+rWWvxQ4mWw3JCkCrIEKgF+QKrIFKwSyAr/1fqSmvlK9xQvareVQvfUo9kMHiwT539qN92flcaxUxbW9i+3dgRu2Z6e2Tj9q83feHq4bv+7dd8yJ/6mL8Zi4c3nkf0SBv1o3PMxfm4jN9ojrbQx0AYwxSTMRMFOIYwMENDYA9nuEMEorAbAhyFBDk4iwu4jCrcQCPu4QH68CiRVHMn3/JE/pp/5Qsu5yt3MZ4HKeIJSpnPcyznDerYwX4O01yupRX1Ut/VkfqxcktR1dVYD+rseagUKjOVuUq/cli5Qjmv3K08qjytvKZ8VfmDKlplVa1WbVEdVD2hekb1tuor1S3VQ3WyOl2tVhvUhepnNWiNULNc86oWaIlatlaiLdLOaT/U6rSD6JwxX8rTmpGsiZEi1xhxec1LEdU0McN/GFTmHHDJGNiA0vCvePjottAy62yz33Hn3XvTEMmrKr3rbncnu65ytx2KW2+7f1uu+JyQlCMKlgFAHi2/8L6d3Z9kt0QZEtPjrL0mJ0xA9IP1ZQt42WN+vtn8sJzok4mWujiRH4hnDNkvz3EDt64hWa6OImB4LyAhjGOKRpOJM8U1O9w/iR8m2Av1T6euvYBHLUA/3GAAb62td9O5kxUrNVPRhqMVluHoM+5qLdys0UfT54UPGZ32R6E0PdVy97NNROudB4iAxjygOE/tFnVBjg9SVi3qiWbDq2uS0hsp1F6aSC1yKbwgjueToiK2SGwl8mVbbqAwG+hm2kTGypZYa82P62v/jZL8OmbNdLKsqTgGjmlSSWTpc84Hzx9RTpOnNoO3m05jXkmjheKz8ugzHkKDVlZAm6PATU+0LASEIvtD5lp4VqMSQyiaBXktwZI814YD2NQu8gFVYriFKqE9/qJatk1+Dtmo6I6DMBXRVQPChsSlDckQ5uTuidS/X5tmP5679oq1ofY3sGuyE70y0T9d0ySa6QnWxxC7h1P+xLsk++HoVxYhgTfX1FSqWtBeeUrCjypxpD0vIVnNLRgbnZK7ljX4DepAIAIzJoPgI5V9yOiGHYfHdetRpbyXn1WU60neaFrM48+e/uzjlw9fn5GbnoB5+vcX0CBr7gsrQFUTJog3CrsqWKtVnMs4wZB7185VuxCaaPtVyOb0Bpb6/R62sOzJys2G0W76OJVuX1vb3z2RphCbXs/aHdZLSw2bC1aKEN/rkIic0qEuZ9lZ6cH6DVZ302/C926433K9q/cfpSkI0+tY+/Bf/TXx2N+9ejDLk+acqBjrMahVuye+7Vx/VftT7LDMPgAZZObZxljjghxeuBAhmwpiLEEepjEDwqM5I8arWC2pUgkyNq+gK3wkdiovkg7YdLZJlJLr6/oQ9Hy2dq05BdZWdqJ3J5ruWgi85SNaXI6f3f7mAyfSjzn49GJwO/3jp4V9//Ht+p199NaI77VmY91IzEZbt2ybzC/jofjTIjoSZoFm42Ec5z31g+a40iETBmaOUxqi9zHLrj9tnFXuoJf1aYpnaFWV5ae2Njc3Ruh0XLtWSwYv2fFuWvR5LF5m5ePAHVdu7aaPQZmeYUVODew9uwn4/LgPN6Ll8Bo4tofJ/S4NxfMJf2jcdt7yyUMQpqV1LpGirCC0CczxwqSAo5HwJNlhwTyFbLAZZBTULNYdzA1mdJHLaTUuzFgD8oAPERunUVkOB1qmvopjf6GBhusiIXSySgXUTlG/RSIjrOw2vThuxuJPH6e3TaW5KhplFdmimG7XwSMGAD+Z2w5out9tnorZwKOftGC1LC8DqRc3HdexFL8+niBODanqeP4OHAQVcxmAIJ1rG95JonKjFQdCx0OYW3KA0T+4Sz496CU6UhUtWHVUWAgSXY4bT8FvjbD3Lft+/4Nu1J0zDVtmwBNehQcGXBQrCqxJUSyCzHYX22F+P7NrpTFwRkaa/eg3oSg1kdc4wEYN4q36klT8fi4BaXpda++7MOg33+CJ3dGe6M4rwb1HvP3vQvPt47AJ2piY9x8+15bPm66xV/+pIC55yeOJ9qzw+OWJ9uVDU/Cr4j2X1EPekhr4DV5UBmkv6y5LN29nGaT7MAfH9bk8ipOYUobmxHzxx8BvNX/YFYdIgnjoY2trK/541bb4aXNHFAreZ8GuUEenZUvlCOn5xDvA2FQHAZtYT/i8CoNy6krcaOEIGuYKOhBh5Cs+WTUJPyLSyyx5uZXEsUBQ5G2MALgahb53h4nQSSPpfzRCo9RTWalCakHq10aOf2MeCjcybyPZ+X7w1jSyFrX2xAHCmWZRFLRcOY9ZGCeKsq1jT4GwpgqHd4IoSS6GVSWdDt0vqKjNW4DmWciaQgfK49kAiixriJT4sD6gwyAfqfF1XiDmas+tB+xQ4tk2ellw4TsqpYNgNE9303x8uec4DtlxWTzNs9i3XZ9I5BnauyH6/pEGvWaS5xGCxKyhA6Sx7ilBRGWgzLlTZaKdD+cNTNPxnj1FGeJLrYQKJe2lY+JVUgOpQ99vpjXx3L5UDBNkGKoIgVlF4C3j1ALBybJ0GIuOG9Kp/M1JVw66BgG+eZtq1nDKMVi+WiSO79HRnjCzSZoVJ3vapX5jXPNDSokJsUnQkQoUOiAiLuRYX2uECHiqTEPyVdNAsy0lS5MG4DvMNmtqewppZBGFAU7yvGiJwMTSli9FoZ91lkR1ff+EWTnXkBlTAkXinKsgUKVYCXvUqmQE7bbBDwRPODXtadz+XhW5YcEX52KfTRqwx6FTI8SrqmBQafghDW3l9HXcdqpRBTXTQbe7FAjYymYQDGc5Oxmk1JxDbVRW6hGplcZJfJrNP6CD5/YomkBIKKXn7CBJicvRQPqQYvtvVeCHdWP8Oq3Ur1uWjBuGnyIajf9qHQZ+WVso8ywlqYzVtcSmdgldz1NzVpGEbuUbclhVkSW2Xc91bMyrwmTVNWtjIE3h+3HTRbBH/nTET8eaiYChZuQCBOhc/5AhIQOnlgSqcNpNsoYUM0/EqMPEtJ2nxIah9jZzdwCjAfHQMdP1KB+0PQUGd9jESdxuDdjIaQmgWVKWaYY07W7y4GkeexZ2Cb0Zp8ftXOnFelxUeCpLJo/IGgSynxKaCbn+d/DgGe4gFLcB2JefQ087ALykmjwDg4KbpUbZxi6etutBbhtRAk8zaWiswrX/RpWeKWKCDR6bQ3Rw5yAs2ZmkQL756PAR987lo7E2ttR6k8ZjiT4j6hv3HyMY43v0KVZ4jGno2baFlKhqOS7wnTUwj1ktiCncNNK2B9dzozOEGArRyXUhMRco83AtkMuGzOl16CKmrimVmbbSCpG4GZFFYEMW4SjR9qCLMdXyYB5Zd4BdOS22W01PFhKRSz2deiLU9yYrwQCZdhp9UwZDFAyVAYmrUszB8NMVld1gdsBzdYw6FXy0J1Gpx7JSK40c3xW7eLtvH/y+508f+41Q/4zPqQd8R3zSP21e+n/W+VNrOTpqXMKvr9uXnE4oOWMuMyciH8jXQbRUjqtP1DmGDs+w+wUVd6eh7qdyJYan7fkq46LDU2U4dPvD71viGK2Ubyo8KJ7kaehgl7AQBH6cpwfl6JKpiQq4JNdDlIeX7GCaouNC0KerMYItHwd99LRoD3xld2rIstjxthmgcZZQytMZ1HVzqG1a7+X+VJawLk47YLQx0cCcyS1hSdUmf4ckzCjJbhZRVkkUKXTwwVbMSHWjUSqEJMze1KNexyVDyiCyWiajL5uWviQNcVVTRCxKCZJ0LciuxJrPDRjq+hzzU1m3oAbAR71goWwjldLWx3rBROSQsm50dYtepYEtQ9dU5Mw4mFVomk+yC5AMvrm4MwlcgypE7ZaS51lRO9ayeGTwOMBn9vIWOmGcjJTkzNDin9sPn7FVRDQSPy5QT+TpIEo0kRJoxVGI2jTL4YG4iuvahShbu687uGgymlTj/573wv563VnvHcAFvph1dIAC2FUu4yRChqAVikjsWdv/u2waweLCFC4ag6lEyc5/sdZKW9sGoITOgENl5EgwwDhjP/YsecnpPn8insywoQ6kKLrJubN/C/eFL5xodeOGZw4cqQ0TLTFyR56Ch4PkQXwnJZxUTYOGO2Woxl58GFnMo8HgbY9SzMkv9UxWapVboLZ6hZvdJWOw+2AJC52I4bkJj9Rt97jZ34HNRwfOy8mLzfcONxBo4gYGxzZab+B/A33RpibbqfT85JWM2ycb6BgzjJzjkRm4N9MBra8GBsh+392iD3buXwZOBrSR/Kbr5ny0JfNdwyydLQGG7Kmn3053fD8N1znzGeGr7xbw7nyYYFkPcx4sCl7SKbNYBgKyI1GLpapKoacXJakUBSGcHJmz44EOKtYqEkBGLaGsmxiLllKedDaEng27iaoOte/GpmaNCKNxmxtsNntnlo4p9SOMTKMuTinhaPebeCRLRSbmlXkVas8ofZIHD6cXnXODorQdL0hnq3Cdt+/G0xXEzPED+LjhEsF3n/LDh5eJKKUZtK0ZPHh2qQHyJklkeHqyCfIvVWf92qp0a/lu/S55t0oEmBOdz51lKcWddggkB47Q0X7DliWrjugsl/tOg9oLeGqLfd2N1l29urPiu17vbubD8PkQCsYM3UoS6nsEITtKk7Rs21ZR0T/YuwpZLGUlA/JbggFKamHS4xaVcbKtuOn7zqvEszSRjD1yezMi390VXZ0DxyTGQPi2IeT5oWUy+Ut5C62IIKuSADKGdMQh++tezsBG/kdHb29i7e3NDXvx8r/0I2NK00U0EZj0AAG+aWCdzbezq9sMok45xgzI2HGn24qI/Q3yq9bhs7WnD295h3rxR7N21dBWWBJdYCnJ54QuL0l2O8ovcN+XfE5H5Vv635735kPsnQIDFXtPBmVMQf5gxp7KhpKXOmr/M+pI/lbpYxbSx1yHBcnfU5VKvQEkn9OBvMRtrqj9OroAJV7QS5KDA2pL/VjP0xu45mwABMvOS0pDArRZeTbUk7EUTQiZnx/1ckQYpW7aBr5hqEs1fcKfPLtvL0lB3c8Hw33PewcMPOuzlMOEsHBMiTqXhLgxxhH99QPf99IQtSXjCKLniRKptIvRk7pSzCUDC1hC6kBCEpFIiTJg4Fd9Tq8ZHlySyXIKMbUp/vSM6v39enZ0I06Wy0QSJ+eIDBXCuU+TJxEIJaryjxOXyn0dPb0+Ci8TyVi5ALHneXKlA4+U+j7lwxAegp6fpFLhSHQ/nIUGkonsqwc1kMrkk2eDgiRPlJ3vzd8nF7vyiUoCek8AUhj6Pvt3oTZgUQq6n1rgs2PVs4Pq6pVSAGWhdAQIGJsmXpn9YORSFcfpjEP0q3ERNP+gGtLNNAkmhve4fZkKG50w3aQbolCNM5KD/lKAaSxpHwmUGTQW48PL+X4fspOUpN/Rb0225cMgsICpY5NmN+GBMkzJjGTRqNvia/6eIsL9kp9EK4bEYCxWYARTNV0FBuRBU4kSKltQHiLmiBVhvvsy16EkVfWgHHyhie33XhLEADQwsVk28fQ+8Oxq6gL2mXoHheicXa71Reub7Tv4IO4zdNEPIobHCEr3D1hEHtIHB/tjVm8hCAcSzgDslnNWT0dh/RkUg7C+fUx8eEK/BUd6oGjF0mMmjWOY9gLelHl/z80P7dXt5YpjW99U3w3Z80ia9yUHeHrlqd2/NqX+3nK5c/GcD3Ccn1gMdsYQUVWVtfJJBAmyu0aF3FMZn4yk6W4CTd2c9Gwkb2tCbdVPTzUq89ksR2aLUnVx/2DvJ3yBgCDvoUM9QPTFNImnE203wZhOpkOMyweFn48IQrcC/GSgX+bJ5eKFC99vIc2/8JV83cvyuD3PK1EYwPNEqlB5QyiuC2mSUL1o15uR8QU8W3wqXOm+INhQhsG9jSpFggsgoLKytrFhvqMX16EkXxF69gbfa3v6la59W3H1BjWlPRfEILoLGNezEJITO+SWwWHMOaAcD441HO47ip57+78///ovqEhJRBTSDhWtbjMxBBQmjzsppXrofpoE/zBuj9o4ozj2HidQSoihSFXVm9SUT4XkyEiyuOVhhEZVhyI8ZFsFiflC0iSQevRuGo1x8sxBl8c8li9GzgcjvKj6qPTjbALWU9ixw0Yh95yQe/457xPK54LFAhasn1GLC5o2NnTTNoI0T9MoaeY8PIGeuoaGHZO6fYVZitY9b8WB6jgI9dd+OmXl1qZMSQKmMj4fLGc9I7Tqvb5abW8znwuRLihnAS1Jwja3d4GsY5qsnfli7CWdgOymISNtpMlS0tPgbURfCzUG8JYUVvthTAZYKUGGeCSW5xPfU2o+LXevcqeaGehMHEA1RMSuGhbF3AIGPP32i8oIt4IwKlBn2nHr0OWwNr8azgxhdOBWh8SoZrnh9js1nnDns3dX3rXwEqSTzLVqChqneVVNtlaIJpQGw5VYICTdAiEb23VPSttJHvsmGnkQU4MCzTgEsZo8B9r3Z2XtdgP+K0H14cHx8Xia5yUGVfEd5Q2BOy0LHhkNtRVXiWZRdpOVs0srP2bu7d0V+mHDDra2av72Z+4V/DoRV71xxJHWOjCgtjmpmRLFcME42YhItK7vO9fUHgKPBdZ3cYYHG+dFWeQHZQG+k3AiRzFclunyZfnDLEg/Bl98PFocskhDjlZCDjvn+NPHVOj7qExT9ylI4tC/QpJm6EdcyqKndJ5GIi/6nOsahxFNEFPUFXK293val2LeBsRYMdmSWn5KkWXmE3V8P93LvmSstDifUze8zLZNcw7mPMi4ICwk7XQNJqlKZ/NS17iKENctHv8OIfuEnZaIU1vSoRtkXKj/TCEJLs9eii+Twwud54lh9ox7UhZmxzgpVPzKvId6fcXZsryyvWT3SeQRLPXFbGN+eIXWpvmYqRu5M0gv5OPaLm/XBDYZi7waxkgOIqmi1PTzFi6aehbPg9pTMTtnSHgZ8VdxHZfL7W1+Up5cr26hb6fRXnwuT6pnBn2s0i45vMhSkldD/9L14R6tqksY+s7EJOjbMteL43EcVFg6LD326/FsrSzTOD54JneOpXzP0TpVeFVV5XmqwCMWORWVaJhnx0eDTpJXzc7OKJ6Pq00oJCGvydSxGlvxy3Yfu9oxU5Wk2H88Ld2FnfkNtZuJBYHLDMzjQ9UZeGV7bJ1VuruqNXLbpZtH3UtQKbVl8/01LdI4DH70WUila/qDo6ckxJK3at1K0q8jA4IMl473qXOF0SjqNuCE1nNiCKd3y9ZYDsykVczuSWZONFjYwINBE+RA5f468lqe55O9UqTDFRJ6aEMXpNJ7SIlm2sJ7rlf7ifx04RCqC7vP+gx3iQRWfX9htFrt7PCj49HR7uhcWFblEVWd+Lz2iEHmfLneO7o5CvP5LoGdnW19J6XHJ+igysAwqFe85+U58TXB0SKA5rOBJEa7PVr5FaJhecWO3HoKXMj22OcJIjfR/7wdNTun9iqN8ZhJexJ1TCwRkiZhfNSPd6sTuNSiUaLA3hfawewCvOySMHAbsefLFAGA2jSQerC0JgqH24A3TvPF9G6J6FsYqgpwfirHW6udaGN0/s/FJm4Qx99/63IjT1nnmgoummZ6fr1czhveWDWznZX8QvrHbaflDKKoDYSMP3xMeXJVa0bjUgQ1w9xQF/MNxF057ezooGF/wiHXaNz2BOo0TVWdL+sCpKqqJFH1viShGgFNvkDObaFNmo1Vtm1ZqdltjzXJ4OtKfHmx1WIxn7+dFVAWOOHHDXtT1ZRupUmwjoBpjfkwhOHdEQnduH6yayjIMZILwckMZBfV1cw64Ut1RSUcZ53wGd/M7nyTVe65FLfhcDFMskNge2rc3jxSlC81einsVaeN75dH0ABUDyeWjBveFT+FVSQNuaJ50KDT1QpqdmwN2xIRy/EQ0kUL+sNQV5TXQyZH4todeMcb9cNK22map/X+9dPCFbcLpwycIm0FJWMmg/8Ki/Ka2LqL2szG6xsLQ/rSuytUEDRSht3dE7ScpCav0CIo6UdSocGqy99GaL6ULjvN3A7H4EC2RSRHQH9j2vS4lqlEe9duL7lWvYkdF9ZqWuT5o78UrUHeea4KR0Q44KLbjlPbMZUKlRNdK2y95UdnmY9I65AGPldgNfsVbYOOYaEaETIpPB3FkMMYIZtGGTIR42W1zyNLjYkizcIwEqOB4vKyQUNq4W0sXZVBpsSJInqqdFvFd9Mlz8SP55MslQlKwHTUExK1nKahcfy0rjvp3GXiOELGaT3E7LjP8sNau962rDf6pV+4RSftQOp+s0D8KaeiivU+UYu5T1mv5nWWhAF13Z//1PzUJ1gN0a9HZ4L6ggVfZ3K3nU4nLaaa9v7VTFqA7W+slbYUiR42aF4RZO8C93FSiB57Zx9blHuYVyIi3ghfiTvDWtRnadceUvt51N2ykg8NMx9xyYJCWi5Zv01XuoyRcpvksbZunZ03MFCDCUiSvAnwpuNH1VR72sbHW7/cSJo2SbNqBdZWr0VzKavaUHIX7LlhvEmMvwsFUOGS7MSwHHXDe64CVgSTCwmcVuQXXthjgOESPyS+J65v+KpN4kKNzMRw+ICRETAyO8b+lo0DTDDicpdMEqEEjCbjYugGnapyls0Zf0o0er03si4K+gQZcFuvKmeVm7GnVJAjhazwEk213ddD6RzEu9ezI5qNsZWSLtbTm21Cy1LpsHWKRtMEa4DqCKLYC3rNNeswFFdOIN8Xg++3AnfgeyqRwwDuI6B8J8jIiUVNrEPGrDs0h+eqF+3Zn2Ng38kAGzeWk72LadB+L0PQNGXJ2Gc49La36tjptlBRkFkOcDh5dpJrsZTvlDYC9gAPRX/HobgAttk4CPSOxF4llRC5e9AkJIl91/fGi33yD/Y2s8lyb1HnVc8LO4wtua4auqx8lLWx/w68PjwYHB7PynySOySe/+oLyoIw3+dx3XaxopX26GH++0GjZBupwEK98VFtnUZoTrAZSW8J5ozZ1VYVKxXt0faG1OfbYHyOOL+7wwqW+hhzxjvKvlbuey+gDDhxNi4GtFPgVA4l5qNLXAu4LlVkTteZ4VSTIALqXThP6TttvTe8B9yNx/FdI2YzN8+8cEK4QN3LxnBuUsbTkhccOZFlv98eBnHd4RzvLrNQiehfTiGwGQjrhV9mqOToY64ExB9rhXvWgUvci4C2QR5C76EkC2x3HCzAOMZ6g67G65AoCaRkNnqAOP8JxF43Pf+6+/D8cbdrP++7APcGh0nJ1xnLgej6FmyWvrK1GAegZVLhsS5Pzzc4zzUp7opDvuTAETp6fMpWJbfUkSRs31P/vB0RbT8WntqHTs/nlHcUqIPVn0f5OVz741LLrt0Bf4wFXXMg6FjDAsYfC1MGxZdP4FgRjH+9nc+LZsA0PMeL4jkmiqM722R0z9SvNnPo+TBJuRXbK51or/58bFh3nNN+93WSo+9KPeo4yLgIszfhaJi3dl5twcXNrj4W1/nouvijhWhJyJOY9+/u4byPQ/JGYNzvYIEtrfmIzryDmb7OUudCxskQ7ZXdhrZlvY0Es94GmSzfNrq3q7t0QarYtr2UPZy2a4x3smn3Ne1kOSXDSXkH9/GNajUHv8T9p/0v0wL2NMcioYyVbLiGC2m1satTMv7Ou1zOZ/UfCn4R5NWgHfQ45pUsSgS3noQJTjp5RcJwH0mdq9qOwuOBJBJnvpd+nJZGnMlpStQoNr5a9iWGeSyTnGawNIytvN/rcWesSOPnPHb0Vv/NtFZ6vLu9MSM7qKUXOXZZwQLcd1NGsGF6WmnOnQ15ejruwwJtxLivkdFA7I+K1q8qVOfzq30XOV8ntDmvT+kz6a9evTvvjGVUe+HWJW+I+o2WnAdUyS1vlqAm2FkQTGfLwMOeqRB2VARFc3UAaW9pbu5x8pDLZQWzRz9Jt85ShUIuYjGfm52lg47LXu3MnSiZo7EOO7vZGRV8Rb8SIzcFpqJ5toc/7l1oB0k3bVGdJHrExJZ9vm7ACKYmXuZkZuecL3JpCbZh1gg2xAzFzbOtNFNB62IBg+z+AlTjFora4dIME8nShywwxplp+TAoO0zfUu6g4zY40Nw8fevX3arbwP3GhkHz3cl2SHRTeee05ujz2GUlenpKVdSks3i9iNvl8bmKauqqysqKSmtb6EThMU4aat2+XPVtPNGDVBa48RE23ASKXq+bOFcwIaG02DgJ3MagvQWzBEI6WTvzoeqimBTnZnSe+4IBHx9W2sDF5Zpp1MQW67K0apUmS2V0e+wQZDA7/XRqyvi7+HVxnZzi1htk5csmTXUQ4+Gc2u9HSLcnJdW2J3/C9U4CROqNqPFPpE64EVHF6L1ojN8zhnhQQm2KfDvRAVshmwMKlFeWhEL+YFktFyIoP+2O/1pBHcT40f8BXVtbVdWAtlLVKmKVQtILGVSdSiflekMnN54rZyiuirroXDkDXJUDlM7SNcxiMHVpFgrU+ZlMdg3ndsDfA9YDlyNwiBPfkIryEIqqZYpboDx4POkkdmcyn85hPShYsZLOmqAqTPpD6UzhDvwiAzGn8tQTnUc8KWXkx5U7u7ZtddrqSHTgatBi/VWJRdQy4oMiga1JUucb2B9Cza3/6n5o1j5qf07u7jbvd4H73Pt6ANO5uA6zLvq2FvExj5lZ+VH/fvuDfOiaTWfA7PH1JWmiQXMqK+zR5P4sI/r5T2QjqNiePP2iO29QE+jJNEHkSaBZv9v2YOeRFeh3lyC4cCEDLWL5frB/NAsb1DZ6J70waQnPnF0YS4Z2qn0bPyAX9Y9ROyt98csFTyuqJvt6A5R+yMmS610Ur/3TkmW09Qd5O9OjHhn1xNvkuVzvWOT8slmd5wRH1IrT0ucJgnPfutRr0FxOS4IW59kCV3t250xLT7uereGSLdiUaMFzgpr1z5Fo1pt8TahrapuZ8J4wJVEIc4OCheLEr3CHwhcLq+HZjbn1gsLxRsaadGfOd6Z+rV0Io5gY+sbeGQuu956EFp6UW0dNRiPz7aPPfTLXOChiHQ4WAByVZLQcXZ9wmBMubv1SyrS8yA4MB/tHd1b19my+t14vM3kzmc3Y++XAPJM+heAFEc0EigKPrh9fnrCbR2epOWpEfZ6++3Kw7MGACXLe7i26Ufc+n7HHXV7wc48BuDxv2z2bXZpDw94fw2XQT7e9d8O2Jjvhf/7ZnikGXctZiY2Dva3NJo2AX/QO6l9NL2766E2/kQQEqzLwAndtAT8kjgmWccrWJYgKii8N5QXHy3m8aDsWpoCPBFPLUuMeMl9IT4Sc++0JIl/yRaG3xlzrRe3liZyHwpNC6ziGLE5S5FwZGykKSI/osmvc5QtOV/iVODEvcskE8crcxqS+uzy2/zTqvt8H0Ws895DE8eCKDGs9u5PGvVGfr572OWYtFDuV471H7kZSPryzJ0nG0GmhtJ7oKaaOnTrbglnFZT9fSoD0H4bB2ewiOnsx3E3WgbATodO2wfty1lxP7pyqzi5snh32VLj5WcldxawC9HqIw5VLzDWrEnM6qCRI7PdEEF6aQ8WOzdsSPG5obplp3CQ3pk1W/qEycOrOTLA0mNTgxArbLCEKzgyXhCaJbA1+0DCL3qdnTQ5uaeSYuhnkxWyN16yAI/zu9YTn28JL8ZLFNj/dx8uGkp7vK0Q6mE0n45QVQWHK6Q2C9oOiCPWe9Qo1HzUem8vtxWZTJCHxHJfikk/nk18e95p5ge+P3zQvirJuqiIbJyn8mKfZ0aFuZSEtat91fRqXE1rFpK0hBboeT3Yhp8qsgTWX6MiPlzJXQssPYXhMYtqBf7x0TebF4jRMRomudYNzPNkJlzF6B0kQJ2Ry3xlClgWB2egTWjbKsbAQfiHtOI3q5LXpJZaV+pkjO2nasj5yS+PINJzG614ndrcR0CTNizyfLiZzrp7Ot1CDXFVg4bpNNK5hJdT6MYgoK8LYBENalu2q6erznD+YNQ2cNEaQB9rWcOPrsoU1fkaKVGMhVUog1p6Vc8pmgeyVMNY+iTXl7ksrjEKHUnJXwvUWROQed2ebnIz4ZOlZfR7MQF1aWcqbU4zIv4P4Kt9L2ob1+K/MyfsAn5UXjPUvO9IbtiDLudLZaiNiQEEU6csdXrTYPfEm+qaak7ReVtTz9mbe6qbqLKcqrynq9iLFk4ilqhHchjdJkQUSW8rBrCifNyxnlDCysVdt3zZk5epsSgqzjM6iPVFODVm2WBSR4Fy2Py15/UdVbbXC3CwyQlcG6rkCtz1wut/Fvf3jcnud3gn6alAaVszpJebtcl86neU+vVl38DjDae0zw3Sur1KTQ3vo1cxH5cnBQuDpkvADTYFEKExDVeO4JSgF9dXA2K2i7FnOYvTL1ln5kNyJJOsDmNMczFzuR4/cC1KLJypQEp1LsjSL7aFUHgKBo/qe5mNao2lKhlCYc+hKH5ggxpgr/J+yoiJqNumqrN08tIBbhckfzTECkXTYXnDCOU9x/fbaWqMyAYXhqH7wsGERfp6HN2yHFrxrY6uqSq7SYEAL1Gz1R4kqgh3BjWJyK0Q65uuXWxEdxIPZbT4ZNzYtA4A3JsbXM0IbTwIM+2dSsqopBAI143oSqN1cVpxy16mFiRz5MLoH2Ywb9AXB9+7elMiaxtiIbl/TrahqldZHmKYa6c4RigNb170S4xNRGUFhuugYF2frigV5n5Yq2wIbNXgIAmsR8NKSaxmdnS/pqtlYWbo4d3cYMBjEn2ZfS2IWrzGCBbVERD8jES/BT668/2LD0pOtXH/7j+MrWSXXPWlrKBfn7LvSN7vuvO0PaMtGMj/Kc6LSJETAshYoErpSxe5aS7UWh3/ooAGNT/2SR0/eIBwHRe8VQ1VzXySv3kgc1hfCloGnt9Pg58nh+r45B3PjngBlXMlz+Gb44bVPeY6udGz7cLHzfD+l4LREUPq6ntO17I3cicpj5CVqkUeMIQnm8BOsJfTZPyGDKNTx1tIB8TCmX/I50LAzqsBHJxg0PlotBCn7cT8L+Zi8MRrB95MXqEIUxaRZurgxpnSwIEOZbffflzNahVfGA6VbqHkxzR2xpAhIzx/M86VFvmYr1SShTEeDomi7BQxrJfFewuSyrPB9Qhy9YdZksBQNIf+sZHHoD+gnFsPAUWqRL/HmEkY111blVB01CJEF7pW6jkZt/7+aQ78vAmeXpLLfOG3FaQSOpvxw1FjsWpnP0/YgQ9g2kbHv04AD1m6ksUAogYs5kihWDct1PBJIsJVIoSCCuG4LSAkE8l5Us0UmZDZAPpPaGBvusQt28lwUgtVaImyQD6glOBeyVJSJSgrOeLMLqfDGoFZcFeZuYQsqWnpeEApnPm3Tt0ylEvnvZhAlpsieTbChheNUHHM/VVm8zudl1Sg2mM3zSEpXdZkum+fmo+U6Bmu2M9TBPEwPHmLFIvKLvgdEuaXv5cJhGuxdXO7VHrPvOb+++TvLisXSUyv+yYsvnb+rgaixi518nrwsJ37W0DnjPpxx/ur/Vc2vx6opD5THwuttOFxST1LC4K4aVijOFWy0jzVZGIudDeYNq8tyfpcdTu7loNoIyZOJGOIKdamGLz2pa62tX2n3QERYRUi3sBVPEbV5nI6pdxDfSR+ANkEuIRtUI3J0aeONFOB/Q9f0Qh6tfOIrPwy1MGwHZ5T3kHdgzQ1HES9txmNtnkF5UB8v6ra6nddFDisG0NSoDOKqLBELmnIUBYqjNbNn+NLpV1Y92369su2pqixIfFnBiklZiasgwrsPUkZVJZDsYcl95uP2XFa+yE5vgrod2vfb7B6dyCWX17uFEzItDAePoy71aAy2V8LdPVE6W2/421R/4O5T7qHdzgqMJtiNspF98iT5STxMIDEyy2wGnc57GLfYrO6x4/nDijSbUbGnS3bTFyy7ulAe5CkxESKhbXqk2QNNrYM8iGu6bhZCpuHY9i1yj4I29VzoMPSVT7nk3hX27fdGuBFFXaYkY8ISCX80+co3KoMbUGLSLM7bWUxs2dhARVlAoR71batNLaXnu91BYDZDsEpZ10JeSakvcr/Ihd4sw8N00b20kCphwXaIYNGQebpjzQvE4041KWxEFla3P3bZcFimU7lB68maBrb5qahBcex8vL4uQZQ8lOBd0b0V7u/JZTzAKrmg3Wc7sACNBtgU3UpODSp7+VkoTM/sk4v63ewq5vGTftef9Xd3UYYNfvt0y6AKMZfO2FPhyiv0eVqui8nc5RmcjgyAeLCB+O+5QTUnDG+CNy7g8B48qpeE71wELP1I908+ZdGYXCwAHoiOS/RRv+QOJdmg/jepyJIYmqbXj856IpRHRjEuCMoiwE2NqTn5rBElZXTBG3UsS9MxT/3sQTOwfH4uRDIb+hEJwhANshhLFAmDwF+a9nkY1mzvEdxVmaRtSpKhmP/0r+chkHkqxFbbGCkJpawoLqPutPURiZT2CH+t2VGSMKmci5SIZJAoiYpM7MY+lS0BymMtBhEH4iqCKkTf8NemhBsdx+epSUiCQb0n04CEBuRsqRCgXTieU6wjWSspyRWudVoInqcLf+eEpqpOeKE8xNI72yaJfqeYdT1iLg+6MR4Rxj44lQ95j/39YoO1g5Opbqvw9Ke+gC4xa+2ZI62HjjHm2wtvrsoP0A+HD9c/G7L5hyA49F78+M+pT5u2caDFS3+KzqbFw4Y8uynWE2YJCBYKjR4+DD30QzDYWpzgYiJYp66sHJ8Twrp1WAYBmSUA1m4FPDWhurQ9v1k3/SdVBismGh5/tSfk7n9ZW6xWuX6m3e01DfcT+ioMYVk8Cf3X4+E6EVes4Z9xPsieh00o8t7yT+sCMSkjrF0Hy7dOTqVG4Djr9SOxCcGWCTzklK0Js/4I/SLyJ/7Sc1nJl3nI/CHvbsRWPOEmQui2FUPia7Jc5Dgh/x9rMFq0DGw0ki5fI1Lph0mmt1QlKQQXa3IRiHEf40iUz5IaTReiWIHUnHAOGAGXg6MixVF4kqNEzhIHcEGhlADE/tOiR2fXdzpnUaTxHEZPBnqbtEVAnbp45nqmyaPQRz14xFC4K69lCS2bGxFMZ22tXLXq4frbWBiLWqm8i7ouegKBnS7yLJUjdS/S2ZQ+rlurJRAFj0t+v5tGBZ0OsUD4gPeYau+sVmKUpky3MrztB/bUun2eNK44cwxb7/o1nipd8VGXDN35UlasrMWj4BFFxTLIH7EbN0J07182eHZDRCJtd/VgZnrDvySCUcZDIl/NxefA5wj+4D+dXG1r3Fgaqe4N0ASLw7r2LNsohLKgTHr4TMXLzeaspo5DG0Rp4GfTzfh89h4GUUndLtlWLEjtKEnrGgIkk1awYR6qKuniwYhWq67ch5AdclqUjdIlH6ymirknsQD7O9OCQ6SBjvbgW1AS7M/DrtewSRVKVSRxjFFU2SyOE4+ykzaWW3DpD9DHlF8icbekC2ntvPQeLv2ErfI9EAmaSDxiMZoTciFKQCMwZG7rTSxiItii3daHTCCyI1gN4lAa3IzYLEUQ4Z3g+QCiDscMYtvqZdz9SAOEnXcJknz1BkSEQpAQnhbjnrVcZMx1eBqU7csYTjxYG07cMla6ljh+/2uiYkTIkROp0iMb9Y/pb7oj59t12YIAVtXNHx41IUfD1geP7j9CfC4zOvfZP1KccDxlF9e6xqppaAPuqqE8XKlkumaYiDuqSRE5YEhVV2JAxJizU9DC1+WCGuVGlulgtw3xg78cm//3h97kzdn+7jLuHi/8//NoUy86dphwlpiebyl+1u9aVXe0IKE9gsKcX7NYg1mzYWtG4jd5xqcXMek+gDN+q2LLBAWEmc6cR2NPCZW23rj1WoW8sFfjfvU1adyd+lXhjJOYpNx6sbAXIo82o4h4ZbWDPK4hTZagWwliV2IqMUwDSYOS3RG6Icyei8LzdP5a/B8Q4uf+1UhBognZIJguq5T12Mdo4Q9pl9z3SM3iBjYNNPToC9XGLFgNSY86Q72Eo4WN+zjOL60Qh6lm2B42xca79QlXZGdfNHxAM4B/1KcCmrU5Uz9F3uN1y72LZ3HwckdYGW8Tfn4yHAQngiDJIne5FVjeWzsILHRz526V8X4AES2flti/f8MnDwYXIS3y/Svc3L2JxWNaCOzrVEB7D/3AoyfeibVt+QhI0cjXp2GjDUR9RqPBIrCsRTm9d/nG5buoPzj6crzwpY+QJm75zkM63n3jNMxntEZ8TODHmhQt9XnhlyfDazTnsLNcztz+s0Mt3R38UpxSbejGsFs16+lI0fOOWinU6/cDOLkFVYFrZQJxvJ+pviEvJ5YXI6Irlypow8bbYYjwWSJUTVO/XQq4nQ86XD3/Jjn3I1LRWhejj/ThhhYWDw0ptzAaqWekhhr8VQU4bBFJ+SwPJDC/hi0RRqIAKyLCj2pmCyR3MNKX2bRohYJ62Ph+Yp8mRdM925Rj2DLP4ulR6aYfJkxHdK7U1SD0Wy04q8uU6kVZca7RMS9K3TkFN32k0NUNJawkmzylokSI+qmn938PAhLhh5cBUQvVjG2k0Fo31neKcikiEYLtksSbGNVxpRhqv4t+pW6PgjgIENz8z/QZnzRwffGekwAhASOV1hj6pJezgvqe70I3HPixShTk3FIg5Q4oDfzOOGCgYfmGF56L6qczLudSce6KMa3ZcgXT4vJHPAa9zdIHmqbC5ptsY3rfnKNoPoaQqlbnmWJ6InqFVB/Jzdp50qWajeU4iirldu3Fkf4jh177JIK8ZBzLNGfVzGVTRmqwwOXQuugwALZ/ReCJhuuomhInsBAEY82HwNklZt3honY4mHVJxlQOgrqpbXAH2vflU1f9fLRT5CC9vS1QOXDLTN7ZDheky1mnLG0xf4IkootJWFW2JGcvDyHLs0CVitoTKh+r1ATuvUUAtnYbtHa3sjVPNbOt5cHFR79NUZf5+FR7gmq8HYmK7AGhJ8IWzB7Bifxh3Yc6rafj9p0q214+OCJOhAyJwwBBFE/1OAfkaOjf1D/T3ZweCztwC+xoUb92JQDfv3R4/4REIS+FWx7EpYO0vl9Htf1W+PFC6OmvmT2+6DvWG5blcHhQbaNY1JxQKKbqsmmmy4MrfC/G7el0fXipXFnjCgb/lugsC3F2NHbcTTBUxTKJKCrw8LiIeD2iAXG8MEqSvCmyX1W6cP0YCF2eT+7dil3gIyzOfgzzd0B+vKZyxMQh6umCzwbL+18dPDsbhzwOOZmC9f+HgMBWmE+r+TH8nUuEf0supeA5yLGIe+vb+tZRzOFUZmDZE6d/3Vm5OsxKmBR03hTefA37Sv56kOTu41zxxgtWRT6Fow4YTmsLZK0VAJUCAY2WEfvtlcjjK207Xa7Xq626KNrVxRps4ClJSgWpNsDcd+ElTRQJhkNnp/9JJJ4X0iBw3YgSNwgT8qspX9qGCh0u6sY6JWbsENPoU6RL3rjrHN/42JY/3TxpL9+M3r0UnrX5awCb9QfXi3WI9a/YSF8iYtR4OAx/K+5I/p5LAAT5udY2gtDokBxg4+82I65ppb4D3S9xVOMe06079S3uV81LL5fyWG4Op65aPy8dvaALwC8aQFj9AdQn/vOj79inP+sS3be7Afjw4sUfAIDPt4Ued+9wh5zd+QYIMQAEQeP/fwTCHSrwnlAM+QOyA3ptSYMtpXd70tWWYxuLalqbL7HlYa2KWtFxJsS8bVMbe6gocxD51zYyt4x7Ds0tKl9+mpZjnz7+CS20MW/tbl19fXfEEmvy75qddzHU2WFt54XgnNZQjGbmUEaky+erqVV5YKtppb9VsUzL2da6FN+a8vPMXzhjqztGl3XH0wvzBMD2j4od/pne9gzhFf6CiE2hTwgXr2kVLW9KYRaWASk9LfJen9Z4dyujl1gQXjTf5tR/rOSlaPk+50vrV/LM8tZlYqBpcb45HFVI2Nj16CzMog3EMqJFjrOUyyNYk8HqYENpXMmDc2gTrLVPa+kgnlWlnisU9jQuPunjtYQwze52nANfsatVtrJtC1uiq+hVFOqOzzQzr75YVPa3CHpJ4zlxOihzjO5ETrNbxNADqVR2kp7cM822J86aJDWBhuyQksAAbVKPCEj0ovKrNgqtV7SoSzkikbKZ6HJGCwksG4IFa5W1WzFrXdAGi/vA1nPbbGi4XiVcvjGsMHVjVRN6Gwufh1jjRomdE6GVjERfRP+vH5Q2pnCW0XvQPwqj6bX//9z2gX8bis6bGhOFAmvRItZ2VdM6b9SIv9eoH9N6n0pxCqXkNUUkQFooEXqYFqYHWNEz0a+TyUD5uNY9SMAAXfO+CUhi9zghqMcw0o6qAJ1qMe1C/XK63bMo3TOchFFlPdxbYy29OtrExV6dwx3OB/F6pNB8G6NdsS4vNJ6KJdXtfkfcQvJlgdi2yhJyMnoVsQ0H4HPwAw58BmtgG7hFV4bakvEMcAI2uIAr0J4qzoiBJczRTOLPlrdvBPC5QQUCCMeXrl6HdBfkqTUsvTDXW5HDra89+75Fqi0GQVI8PlFL5/vx4g+91piwaZmVSy2vK8H5pMN9N6CKnLIvZi7EyNmCcq6gDhR4oGWN6WCJSWRgtGuqWhpdEWf87TiMlqUlaoa6hbHWeXIUhpqy+7SpJrl5gfoEVtG3653W9uk8629Z7rvcFW3h7RTlGrfNpO0hEoBNEAyRQIMNEOiEAPxhh7NVQhAE+BubjEMuAK08UQVy0PbJV85en03+RvJPtpD8BykyQFO2kgzs75/9SdF8onlmDiJQtESgByHYjkHWC/koFjeMH28mn37Ckau4eJCn/sopyJy2nkFcpZO5PNfPKZ+OB54JnCwynCmsD158sqO/2pM9LUZODhjJclJISzTLBDnNxckio5WbvF9KgYKbnhwSp+vkiJQO/PprH0VHFuSwFCeIHPAdATEmHm/eNmGKIrAfU5C9DhA5jClyEkmV3GfMBjimrMBhiaO35DhkxVKu7GarH/87B5qLj4nHtc/iUCFC7+x+a3N2L9HavDpg88pF7BiI72Yy+d/yWlxrdtbblvP2vxAlxBbjFp/+vladiMmjL0xrNNphwnWuuiBRHH5Ecit25SzXpvXm8vj4bxD/5rIqlF+thfArtv2LTXDAMYeMgEMy0Hc6YRLBlZ9ob7KSGMr1i0tejwcAAA=="

CSS = """
@font-face { font-family:"Cairo"; src:url(data:font/woff2;base64,@@FONTREF@@) format("woff2");
  font-weight:400 700; font-style:normal; font-display:swap; }
:root { color-scheme:dark; --bg:#0d0d10; --card:#15151a; --ink:#ecebf0; --muted:#9d9ca6; --line:#27272f;
  --brand:#b5003c; --accent:#ff4f86; --good:#4fd18b; --good-bg:#0e2519; --mid:#f2b04a; --mid-bg:#2b210f;
  --bad:#ff6b6b; --bad-bg:#34111a; --hl:#25111a; --chip:#23232b; }
* { box-sizing:border-box; }
html[lang="ar"] .en, html[lang="en"] .ar { display:none !important; }
body { margin:0; color:var(--ink); font:16px/1.8 "Cairo","Segoe UI",Tahoma,system-ui,sans-serif;
  background:radial-gradient(1100px 420px at 50% -160px, #3a0b1d 0%, rgba(13,13,16,0) 72%) no-repeat, var(--bg); }
html[lang="en"] body { line-height:1.65; }
.brand { background:linear-gradient(90deg, #09090c 0%, #1b0711 100%); border-bottom:2px solid var(--brand); }
.brand .bar { max-width:1080px; margin:0 auto; padding:12px 16px; display:flex; align-items:center; gap:16px; }
.brand .logo { height:48px; width:auto; display:block; }
.brand .tool { color:#e6e6e6; font:700 17px/1 "Cairo",sans-serif; letter-spacing:.3px; }
#lang { margin-inline-start:auto; background:transparent; color:#fff; border:1px solid var(--brand); border-radius:999px;
  padding:5px 18px; cursor:pointer; font:600 14px/1.6 "Cairo",system-ui,sans-serif; }
#lang:hover, #lang:focus-visible { background:var(--brand); outline:none; }
@media (max-width:560px) { .brand .logo { height:36px; } .brand .tool { display:none; } }
main { max-width:1080px; margin:0 auto; padding:26px 16px 60px; }
h1 { font-size:1.75rem; font-weight:700; margin:0 0 4px; }
h2 { font-size:1.2rem; font-weight:700; margin:0 0 12px; }
h2::before { content:""; display:inline-block; width:4px; height:1.05em; border-radius:2px; background:var(--brand);
  vertical-align:-0.18em; margin-inline-end:10px; }
h3 { font-size:1rem; font-weight:600; margin:0 0 6px; }
section { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:18px 20px; margin:16px 0; }
.muted { color:var(--muted); } .small { font-size:.86rem; } .warn { color:var(--mid); } .good-txt { color:var(--good); }
.verdict { border-width:2px; } .verdict h2::before { display:none; }
.verdict.good { background:var(--good-bg); border-color:var(--good); } .verdict.mid { background:var(--mid-bg); border-color:var(--mid); }
.verdict.bad { background:var(--bad-bg); border-color:var(--bad); }
.verdict h2 { font-size:1.35rem; } .verdict.good h2 { color:var(--good); } .verdict.mid h2 { color:var(--mid); } .verdict.bad h2 { color:var(--bad); }
.facts { display:flex; flex-wrap:wrap; gap:8px 24px; margin-top:8px; } .facts b { font-weight:600; color:var(--ink); }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px 28px; }
.grid ul { margin:0; padding-inline-start:18px; }
.scroll { overflow-x:auto; } table { width:100%; min-width:900px; border-collapse:collapse; font-size:.93rem; }
th, td { text-align:start; vertical-align:top; padding:9px 10px; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:600; white-space:nowrap; } tr.hl td { background:var(--hl); }
td.ltrcell { text-align:left; }
code { font-family:"Cascadia Mono",Consolas,ui-monospace,Menlo,monospace; font-size:.88em; overflow-wrap:break-word; }
pre { background:#0b0b0e; border:1px solid var(--line); border-radius:8px; padding:8px 12px; overflow-x:auto;
  direction:ltr; text-align:left; margin:6px 0; font-family:"Cascadia Mono",Consolas,ui-monospace,Menlo,monospace; }
.chips { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:12px; }
.chip { display:inline-block; background:var(--chip); border-radius:8px; padding:1px 10px; margin:2px; font-size:.84rem; }
.lvl-critical, .lvl-high { background:var(--bad-bg); color:var(--bad); } .lvl-medium { background:var(--mid-bg); color:var(--mid); }
details summary { cursor:pointer; margin:10px 0; font-weight:600; }
ol li, ul.steps li { margin-bottom:8px; } a { color:var(--accent); }
ul.cols { columns:3 220px; }
.credit { text-align:center; padding:18px 16px 30px; border-top:1px solid var(--line); color:var(--muted);
  font:500 15px/1.6 "Cairo",system-ui,sans-serif; letter-spacing:.3px; }
.credit b { color:#fff; font-weight:700; background:linear-gradient(90deg,#d61a5c,#b5003c); padding:1px 10px; border-radius:6px; }
.callout { border-inline-start:4px solid var(--brand); padding:8px 12px; background:#1d1016; border-radius:6px; margin:10px 0; }
"""

LANG_JS = """
(function () {
  var KEY = "phonehackscan-lang", root = document.documentElement;
  function set(l) {
    root.lang = l; root.dir = (l === "ar") ? "rtl" : "ltr";
    document.title = root.getAttribute("data-title-" + l);
    try { localStorage.setItem(KEY, l); } catch (e) {}
  }
  var l = "ar";
  try { l = localStorage.getItem(KEY) || "ar"; } catch (e) {}
  set(l === "en" ? "en" : "ar");
  document.getElementById("lang").addEventListener("click", function () { set(root.lang === "ar" ? "en" : "ar"); });
})();
"""


def _load(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


def L(ar, en):
    """Bilingual text: both languages are in the page, CSS shows the selected one."""
    return f'<span class="ar">{ar}</span><span class="en">{en}</span>'


def _e(s):
    return html.escape(str(s))


def _ltr(s):
    return f'<bdi dir="ltr"><code>{_e(s)}</code></bdi>'


def _tool_cmd():
    return "phonehackscan.cmd" if IS_WIN else "python3 phonehackscan.py"


def _page(title_ar, title_en, body):
    return f"""<!doctype html>
<html lang="ar" dir="rtl" data-title-ar="{_e(title_ar)}" data-title-en="{_e(title_en)}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="dark">
<title>{_e(title_ar)}</title><style>{CSS.replace("@@FONTREF@@", CAIRO_WOFF2)}</style></head><body>
<header class="brand"><div class="bar">
  <img class="logo" alt="UCYBERS" src="data:image/png;base64,{UCYBERS_LOGO_PNG}">
  <span class="tool">PhoneHackScan</span>
  <button id="lang" type="button" title="Language / اللغة">{L("English", "العربية")}</button>
</div></header>
<main>
{body}
</main>
<footer class="credit" dir="ltr">PhoneHackScan &middot; powered by <b>UCYBERS</b></footer>
<script>{LANG_JS}</script>
</body></html>"""


def _alert_tables(alerts, counts):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    main = sorted((a for a in alerts if a.get("level") in order), key=lambda a: order[a["level"]])
    minor = [a for a in alerts if a.get("level") not in order]

    def rows(lst):
        out = []
        for a in lst:
            lvl = a.get("level", "")
            ar, en = LEVELS.get(lvl, (lvl, lvl))
            ind = (a.get("matched_indicator") or {}).get("name", "")
            out.append(f'<tr><td><span class="chip lvl-{_e(lvl.lower())}">{L(ar, en)}</span></td>'
                       f'<td dir="ltr" class="ltrcell">{_e(a.get("message", ""))}</td>'
                       f'<td dir="ltr" class="ltrcell">{_e(ind)}</td></tr>')
        return "".join(out)

    def table(lst):
        return ('<div class="scroll"><table><thead><tr>'
                f'<th>{L("المستوى", "Level")}</th><th>{L("الرسالة", "Message")}</th>'
                f'<th>{L("المؤشر المطابق", "Matched indicator")}</th></tr></thead>'
                f'<tbody>{rows(lst)}</tbody></table></div>')

    chips = "".join(f'<span class="chip lvl-{k.lower()}">{L(*LEVELS[k])}: {counts.get(k, 0)}</span>'
                    for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])
    out = f'<div class="chips">{chips}</div>'
    out += table(main) if main else f'<p class="muted">{L("لا تنبيهات بمستوى متوسط أو أعلى.", "No medium or higher alerts.")}</p>'
    if minor:
        out += (f'<details><summary>{L(f"تنبيهات منخفضة ومعلوماتية ({len(minor)})", f"Low and informational alerts ({len(minor)})")}'
                f'</summary>{table(minor)}</details>')
    return out


HELP_LINKS = ('<a href="https://www.accessnow.org/help/">Access Now Digital Security Helpline</a>',
              '<a href="https://securitylab.amnesty.org/get-help/">Amnesty Security Lab</a>',
              '<a href="https://stopstalkerware.org">Coalition Against Stalkerware</a>')


def make_report(run, mode):
    tool = _tool_cmd()
    q = _load(run / "quick" / "quick.json", {})
    has_quick = bool(q)
    mvt_dir = run / "mvt"
    mvt_ran = (mvt_dir / "info.json").exists()
    alerts = _load(mvt_dir / "alerts.json", [])
    dev = q.get("device", {})
    apps = q.get("apps", [])
    review = [a for a in apps if a.get("review")]
    apps_ok = q.get("apps_ok", True)
    owners_detail = q.get("owners_detail") or [{"user": 0, "package": p_, "kind": "device"} for p_ in q.get("owners", [])]
    device_owners = [o for o in owners_detail if o["kind"] == "device"]
    vt = _load(run / "virustotal.json", {})
    vt_results = vt.get("results", [])
    vt_checked = len(vt_results)
    vt_flagged = sorted((r for r in vt_results if r.get("malicious")), key=lambda r: -r["malicious"])
    vt_strong = [r for r in vt_flagged if r["malicious"] >= 5]
    vt_unknown = [r for r in vt_results if r.get("status") == "unknown"]

    counts = {}
    for a in alerts:
        counts[a.get("level", "")] = counts.get(a.get("level", ""), 0) + 1
    serious = counts.get("CRITICAL", 0) + counts.get("HIGH", 0) + len(vt_strong)

    # Security patch age and Advanced Protection support
    patch_note, patch_date = "", None
    try:
        patch_date = datetime.date.fromisoformat(dev.get("patch", ""))
        months = (datetime.date.today() - patch_date).days // 30
        if months >= 6:
            patch_note = '<p class="warn">' + L(
                f"آخر تحديث أمني منذ نحو {months} شهراً. حدّث النظام من الإعدادات ← تحديث البرامج، فالتحديثات تغلق الثغرات التي تستغلها برامج التجسس.",
                f"The last security update is about {months} months old. Update the phone in Settings > Software update: updates close the holes spyware uses.") + "</p>"
    except Exception:
        pass
    try:
        sdk = int(dev.get("sdk") or 0)
    except ValueError:
        sdk = 0
    if not has_quick:
        ap_status = ""
    elif sdk >= 36 and patch_date and patch_date >= datetime.date(2025, 12, 1):
        ap_status = '<p class="good-txt">' + L(
            "هاتفك يعمل بأندرويد 16 مع تحديث أمني حديث، فهو يدعم على الأرجح «الحماية المتقدمة» و«سجل التسلل» إن وفّرتهما الشركة المصنّعة.",
            "Your phone runs Android 16 with a recent security update, so it most likely supports Advanced Protection and Intrusion Logging, if the maker provides them.") + "</p>"
    elif sdk >= 36:
        ap_status = '<p class="warn">' + L(
            "هاتفك يعمل بأندرويد 16. «الحماية المتقدمة» متاحة على الأرجح، أما «سجل التسلل» فيحتاج تحديث ديسمبر 2025 أو أحدث، فحدّث الهاتف أولاً.",
            "Your phone runs Android 16. Advanced Protection is most likely available; Intrusion Logging needs the December 2025 update or later, so update first.") + "</p>"
    else:
        v = _e(dev.get("android", "?"))
        ap_status = '<p class="warn">' + L(
            f"هاتفك يعمل بأندرويد {v}. «الحماية المتقدمة» تحتاج أندرويد 16، فإن لم يصل هاتفك تحديثه فاعتمد على بقية النصائح في هذا القسم.",
            f"Your phone runs Android {v}. Advanced Protection needs Android 16; if your phone cannot get it, rely on the other tips in this section.") + "</p>"

    # Verdict
    if (mvt_ran or vt_strong) and serious:
        vclass = "bad"
        vtitle = L("تطابق مع مؤشرات برامج تجسس أو برمجيات خبيثة", "Matches known spyware or malware indicators")
        vtext = L("وجد MVT آثاراً تطابق مؤشرات اختراق منشورة، أو صنّف VirusTotal تطبيقاً على أنه خبيث. هذا يستدعي مراجعة جدية، ويُفضّل أن يراجعها مختص قبل أي تصرف. اقرأ قسم «ماذا أفعل الآن؟» في الأسفل.",
                  "MVT found traces that match published indicators of compromise, or VirusTotal flagged an app as malicious. Take this seriously and, ideally, have an expert review it before you act. Read “What should I do now?” below.")
    elif device_owners:
        vclass = "mid"
        vtitle = L("جهة ما تدير هاتفك بالكامل", "Someone manages your whole phone")
        vtext = L("في الهاتف «مالك جهاز» (Device Owner) يستطيع التحكم بالهاتف كله: تثبيت التطبيقات وحذفها، وقفل الهاتف أو مسحه، وقد يرى الموقع. هذا طبيعي فقط إن كان الهاتف من جهة عملك أو دراستك. إن لم يكن كذلك، فهذا أهم ما في الفحص.",
                  "A “device owner” controls the whole phone: it can install and remove apps, lock or wipe the phone, and may see its location. This is normal only if the phone came from your employer or school. If not, this is the most important finding.")
    elif review:
        vclass = "mid"
        vtitle = L("تطبيقات تستحق المراجعة", "Apps worth reviewing")
        vtext = L(("لم يجد MVT أي تطابق مع مؤشرات معروفة، " if mvt_ran else "") +
                  "لكن بعض التطبيقات تجمع صلاحيات قوية مع صفات يشيع وجودها في برامج التجسس. هذا ليس دليلاً على وجود برنامج تجسس، فكثير من التطبيقات السليمة تبدو كذلك، لكن راجع كل تطبيق في القائمة وتأكد أنك تعرفه.",
                  ("MVT found no match with known indicators, but " if mvt_ran else "") +
                  "some apps combine powerful permissions with traits common in spyware. That is not proof of spyware — many legitimate apps look like this — but check each app in the list and make sure you recognise it.")
    else:
        vclass = "good"
        vtitle = L("لم يُعثر على مؤشرات معروفة", "No known indicators found")
        vtext = L("لم يظهر أي تطابق مع مؤشرات برامج التجسس المنشورة" + ("، ولا تطبيقات بصفات مريبة واضحة" if has_quick and apps_ok else "") +
                  ". تذكّر أن هذا لا يثبت خلوّ الجهاز تماماً، فالفحص لا يكشف إلا ما هو معروف.",
                  "No match with published spyware indicators" + (", and no clearly suspicious apps" if has_quick and apps_ok else "") +
                  ". Remember this does not prove the phone is clean: a scan only finds what is already known.")
    if has_quick and not apps_ok:
        vtext += L(" (تنبيه: تعذّرت قراءة قائمة التطبيقات في الفحص السريع، فلم تُفحص صفات التطبيقات.)",
                   " (Note: the quick check could not read the app list, so app traits were not checked.)")
    if mode == "logs":
        vtext = L("تحليل «سجل التسلل» الذي نزّلته من الهاتف. ", "Analysis of the Intrusion Logging files you downloaded from the phone. ") + vtext
    elif not mvt_ran and mode == "full":
        vtext += L(" (لم يكتمل تحليل MVT، فالنتيجة مبنية على الفحص السريع فقط.)",
                   " (The MVT analysis did not complete, so this result is based on the quick check only.)")
    elif mode == "quick":
        vtext += L(" (هذا فحص سريع فقط. للفحص الكامل بمؤشرات MVT شغّل الأداة دون --quick.)",
                   " (Quick check only. For the full check against MVT indicators, run the tool without --quick.)")

    def li_list(items, empty=None):
        if not items:
            return f'<p class="muted">{empty or L("لا شيء", "None")}</p>'
        return "<ul>" + "".join(f"<li>{_ltr(i)}</li>" for i in items) + "</ul>"

    # MVT + VirusTotal
    if mode == "quick":
        mvt_html = f'<p class="muted">{L("لم يُشغَّل (فحص سريع).", "Not run (quick check).")}</p>'
    elif not mvt_ran:
        mvt_html = f'<p class="warn">{L("لم يكتمل تحليل MVT. راجع رسائل نافذة الأوامر.", "The MVT analysis did not complete. Check the messages in the terminal window.")}</p>'
    else:
        mvt_html = _alert_tables(alerts, counts)
        mvt_html += '<p class="muted small">' + L(
            "تنبيه «متوسط» عن تطبيق «مثبّت من خارج المتجر» لا يعني أنه ضار، بل أنه لم يأتِ من متجر رسمي. التنبيه «حرج» يعني تطابقاً مع مؤشر اختراق منشور. وتنبيه VirusTotal بكشف أو كشفين فقط من نحو 70 محركاً كثيراً ما يكون إنذاراً كاذباً (تصنيفات مثل adware أو riskware)، أما خمسة كشوف فأكثر فتستحق الاهتمام.",
            "A “medium” alert about an app “installed from outside a store” does not mean it is harmful, only that it did not come from an official store. A “critical” alert means a match with a published indicator of compromise. A VirusTotal result of one or two detections out of about 70 engines is often a false alarm (labels such as adware or riskware); five or more deserve attention.") + "</p>"
    if vt_checked:
        def vt_row(r):
            names = "، ".join(sorted({a["package"] for a in r["apps"]}))
            cls = "lvl-critical" if r["malicious"] >= 5 else "lvl-medium"
            return (f'<tr><td><span class="chip {cls}">{r["malicious"]}/{r.get("engines", "?")}</span></td>'
                    f'<td>{_ltr(names)}</td><td dir="ltr" class="ltrcell">{_e(r.get("label", ""))}</td></tr>')
        total = vt.get("total", vt_checked)
        vt_html = "<p>" + L(f"فحص VirusTotal لتطبيقاتك فقط: {vt_checked} ملف من أصل {total}. صنّف محرك واحد على الأقل {len(vt_flagged)} منها على أنه خبيث، و{len(vt_unknown)} لم يرها VirusTotal من قبل.",
                            f"VirusTotal check of your own apps: {vt_checked} of {total} files. At least one engine flagged {len(vt_flagged)}; {len(vt_unknown)} were never seen by VirusTotal before.") + "</p>"
        if vt_flagged:
            vt_html += ('<div class="scroll"><table><thead><tr>'
                        f'<th>{L("عدد المحركات", "Engines")}</th><th>{L("التطبيق", "App")}</th><th>{L("التصنيف", "Label")}</th></tr></thead>'
                        f'<tbody>{"".join(vt_row(r) for r in vt_flagged)}</tbody></table></div>')
        if vt_unknown:
            names = ", ".join(_ltr(n) for n in sorted({a["package"] for r in vt_unknown for a in r["apps"]}))
            vt_html += '<p class="muted small">' + L(
                f"ملفات لم يرها VirusTotal من قبل: {names}. هذا طبيعي للتطبيقات المحلية أو النادرة، لكنه يستحق نظرة إن كان التطبيق مثبّتاً من خارج المتجر.",
                f"Files VirusTotal has never seen: {names}. Normal for local or rare apps, but worth a look if the app came from outside a store.") + "</p>"
    elif mode == "full":
        why = {
            "off": (f"شغّلت الفحص مع {_ltr('--no-vt')}.", f"The scan was run with {_ltr('--no-vt')}."),
            "skipped": ("لم يُدخَل مفتاح VirusTotal.", "No VirusTotal key was entered."),
            "rejected": (f"رفض VirusTotal المفتاح المحفوظ. احذف ملف {_ltr('.vt_api_key')} من مجلد النتائج وأدخل المفتاح من جديد.",
                         f"VirusTotal rejected the saved key. Delete {_ltr('.vt_api_key')} from the results folder and enter the key again."),
            "quota": ("استُهلك الحد اليومي المجاني للمفتاح (500 استعلام). أعد المحاولة غداً.",
                      "The free daily limit of the key (500 lookups) is used up. Try again tomorrow."),
            "unreachable": ("تعذّر الاتصال بموقع VirusTotal.", "VirusTotal could not be reached."),
            "stopped": ("أوقفته بـ Ctrl+C قبل أن يكتمل أي استعلام.", "It was stopped with Ctrl+C before any lookup finished."),
            "no_data": ("لم يجمع androidqf بيانات التطبيقات.", "androidqf collected no app data."),
            "no_list": ("تعذّر تمييز تطبيقاتك عن تطبيقات النظام.", "Your apps could not be told apart from system apps."),
            "no_hashes": ("لم يسجّل androidqf بصمات ملفات التطبيقات.", "androidqf did not record app file hashes."),
        }.get(vt.get("status", ""), ("", ""))
        vt_html = '<p class="muted small">' + L("لم يُستخدم VirusTotal في هذا الفحص. " + why[0], "VirusTotal was not used in this scan. " + why[1]) + "</p>"
    else:
        vt_html = ""

    # Apps
    def app_rows(lst):
        out = []
        for a in lst:
            flags = "".join(f'<span class="chip flag">{L(*FLAGS.get(f, (f, f)))}</span>' for f in a["flags"])
            perms_ar = "، ".join(PERMS.get(p, (p, p))[0] for p in a.get("permissions", []))
            perms_en = ", ".join(PERMS.get(p, (p, p))[1] for p in a.get("permissions", []))
            perms = L(perms_ar, perms_en) if perms_ar else "—"
            cls = "hl" if a.get("review") else ""
            out.append(f'<tr class="{cls}"><td>{_ltr(a["package"])}<div class="muted small">{_e(a.get("version", ""))}</div></td>'
                       f'<td>{flags}</td><td>{perms}</td><td>{_ltr(a.get("installer", ""))}</td>'
                       f'<td dir="ltr" class="ltrcell small">{_e(a.get("installed", ""))}</td></tr>')
        return "".join(out)

    if not apps_ok:
        msg = _ltr(q.get("apps_error", ""))
        apps_table = '<p class="warn">' + L(f"تعذّرت قراءة قائمة التطبيقات من الهاتف، فهذا القسم فارغ لهذا السبب وليس لأن الهاتف خالٍ من التطبيقات. رسالة الهاتف: {msg}",
                                            f"The app list could not be read from the phone, so this section is empty for that reason — not because the phone has no apps. Phone message: {msg}") + "</p>"
    elif apps:
        apps_table = ('<div class="scroll"><table><thead><tr>'
                      f'<th>{L("التطبيق (اسم الحزمة)", "App (package name)")}</th><th>{L("الصفات", "Traits")}</th>'
                      f'<th>{L("صلاحيات حساسة ممنوحة", "Sensitive permissions")}</th><th>{L("مصدر التثبيت", "Installed by")}</th>'
                      f'<th>{L("تاريخ التثبيت", "Installed on")}</th></tr></thead><tbody>{app_rows(apps)}</tbody></table></div>')
    else:
        apps_table = f'<p class="muted">{L("لا توجد تطبيقات بصفات تستحق الذكر.", "No apps with notable traits.")}</p>'

    def owner_li(o):
        u = _e(o.get("user"))
        pk = _ltr(o["package"])
        if o["kind"] == "device":
            return '<li class="warn">' + L(f"<b>يدير الهاتف كله (Device Owner):</b> {pk}. طبيعي فقط إن كان الهاتف من جهة عمل أو دراسة.",
                                           f"<b>Controls the whole phone (Device Owner):</b> {pk}. Normal only if the phone came from an employer or school.") + "</li>"
        if o["kind"] == "work":
            return "<li>" + L(f"<b>ملف عمل</b> (المستخدم {u}) تديره {pk}. الجهة ترى ما داخل ملف العمل فقط وتستطيع مسحه، لا تطبيقاتك الشخصية ولا رسائلك وصورك. يظهر عادة بعد إضافة حساب عمل أو دراسة.",
                              f"<b>Work profile</b> (user {u}) managed by {pk}. The organisation sees only what is inside the work profile and can wipe it — not your personal apps, messages or photos. It usually appears after adding a work or school account.") + "</li>"
        if o["kind"] == "securefolder":
            return "<li>" + L(f"<b>المجلد الآمن</b> من سامسونج (المستخدم {u}). طبيعي إن كنت أنشأته.",
                              f"<b>Samsung Secure Folder</b> (user {u}). Normal if you created it.") + "</li>"
        return "<li>" + L(f"ملف منفصل (المستخدم {u}) يديره {pk}.", f"Separate profile (user {u}) managed by {pk}.") + "</li>"

    owners_html = ("<ul>" + "".join(owner_li(o) for o in owners_detail) + "</ul>") if owners_detail else \
        f'<p class="muted">{L("لا أحد — هذا هو الطبيعي للهاتف الشخصي.", "Nobody — this is normal for a personal phone.")}</p>'
    vpn_txt = _ltr(q.get("always_on_vpn")) if q.get("always_on_vpn") else L("لا", "none")
    proxy_txt = _ltr(q.get("http_proxy")) if q.get("http_proxy") else L("لا", "none")
    settings_html = f"""
<div class="grid">
  <div><h3>{L("من يدير الهاتف", "Who manages the phone")}</h3>{owners_html}</div>
  <div><h3>{L("تطبيقات مسؤول الجهاز (Device admin)", "Device admin apps")}</h3>{li_list(q.get("admins", []))}
       <p class="muted small">{L("وجود <code>com.google.android.gms</code> هنا طبيعي (خدمة «العثور على جهازي»).", "<code>com.google.android.gms</code> here is normal (Find My Device).")}</p></div>
  <div><h3>{L("خدمات إمكانية الوصول المفعّلة", "Enabled accessibility services")}</h3>{li_list(q.get("accessibility", []))}</div>
  <div><h3>{L("تطبيقات تقرأ الإشعارات", "Apps that read notifications")}</h3>{li_list(q.get("notification_listeners", []))}</div>
  <div><h3>{L("لوحات المفاتيح المفعّلة", "Enabled keyboards")}</h3>{li_list(q.get("keyboards", []))}</div>
  <div><h3>{L("الشبكة", "Network")}</h3><p>{L("VPN دائم التشغيل:", "Always-on VPN:")} {vpn_txt}</p>
       <p>{L("وكيل HTTP عام (Proxy):", "Global HTTP proxy:")} {proxy_txt}</p>
       <p class="muted small">{L("شهادات CA التي أضافها المستخدم لا تُقرأ دون صلاحيات root، فافحصها يدوياً: الإعدادات ← الأمان ← التشفير وبيانات الاعتماد ← بيانات اعتماد المستخدم.",
                                  "User-added CA certificates cannot be read without root; check them by hand: Settings > Security > Encryption & credentials > User credentials.")}</p></div>
</div>"""

    hidden_note = "" if q.get("launcher_check", True) else \
        f'<p class="muted small">{L("لم يدعم هذا الهاتف فحص الأيقونات المخفية، فتم تخطيه.", "This phone does not support the hidden-icon check, so it was skipped.")}</p>'
    quick_sections = f"""
<section><h2>{L(f"تطبيقات تستحق نظرة ({len(review)} للمراجعة أولاً، {len(apps)} إجمالاً)", f"Apps worth a look ({len(review)} to review first, {len(apps)} in total)")}</h2>
<p class="muted small">{L("الصفوف المظللة هي الأولى بالمراجعة. ابحث عن اسم أي حزمة لا تعرفها، وتأكد أنك ثبّتها بنفسك وتحتاج صلاحياتها.",
                          "Highlighted rows come first. Look up any package name you don't recognise, and make sure you installed it yourself and need its permissions.")}</p>
{hidden_note}{apps_table}</section>
<section><h2>{L("إعدادات الهاتف الحساسة", "Sensitive phone settings")}</h2>{settings_html}</section>""" if has_quick else ""

    # Beginner guide: removing an app
    examples = review or [a for a in apps if a["flags"] != ["profile_manager"]][:1]
    open_cmds = "".join(f"<pre>{_e(tool)} --open-app {_e(a['package'])}</pre>" for a in (examples[:5] or [{"package": "com.example.app"}]))
    remove_html = f"""
<section><h2>{L("كيف أحذف تطبيقاً لا أعرفه؟ (دليل المبتدئ)", "How do I remove an app I don't recognise? (beginner's guide)")}</h2>
<div class="callout">{L("<b>قبل أن تحذف:</b> إن كنت تشك أن شخصاً قريباً منك ثبّت التطبيق، فحذفه قد ينبّهه. احتفظ بهذا التقرير، وفكّر في سلامتك أولاً، واطلب المساعدة من " + HELP_LINKS[2] + ".",
                       "<b>Before you remove anything:</b> if you think someone close to you installed the app, removing it may alert them. Keep this report, think about your safety first, and get help from " + HELP_LINKS[2] + ".")}</div>
<ol>
<li>{L("<b>افتح صفحة التطبيق على الهاتف.</b> الهاتف يعرض أسماء التطبيقات لا أسماء الحزم (مثل com.company.app)، فأسهل طريقة: صِل الهاتف بالكابل وشغّل الأمر التالي، فتُفتح صفحة «معلومات التطبيق» على الهاتف مباشرة:",
       "<b>Open the app's page on the phone.</b> The phone shows app names, not package names (like com.company.app), so the easiest way is to connect the phone and run the command below: the app's “App info” page opens on the phone.")}
{open_cmds}
<span class="muted small">{L("أو يدوياً: الإعدادات ← التطبيقات، ثم من القائمة (⋮) اختر «إظهار تطبيقات النظام» وابحث عن التطبيق.", "Or by hand: Settings > Apps, then in the menu (⋮) choose “Show system apps” and find the app.")}</span></li>
<li>{L("<b>أوقف صلاحياته الخطرة أولاً.</b> إن كان يملك «إمكانية الوصول» فأوقفها من: الإعدادات ← إمكانية الوصول ← التطبيقات المثبّتة. وإن كان يقرأ الإشعارات فابحث في الإعدادات (🔍) عن «الوصول إلى الإشعارات» وأوقفه.",
       "<b>Turn off its dangerous access first.</b> If it has Accessibility, turn it off in Settings > Accessibility > Installed apps. If it reads notifications, search Settings (🔍) for “Notification access” and turn it off.")}</li>
<li>{L("<b>إن كان زر «إلغاء التثبيت» رمادياً</b> فالتطبيق «مسؤول جهاز»: ابحث في الإعدادات عن «تطبيقات مسؤول الجهاز» (Device admin apps)، وأوقف التطبيق هناك، ثم ارجع إلى صفحته.",
       "<b>If “Uninstall” is greyed out,</b> the app is a device admin: search Settings for “Device admin apps”, switch the app off there, then go back to its page.")}</li>
<li>{L("<b>اضغط «إلغاء التثبيت» ثم «موافق».</b>", "<b>Tap “Uninstall”, then “OK”.</b>")}</li>
<li>{L("<b>إن لم يُحذف أو عاد من جديد،</b> فقد يكون جزءاً من إدارة الجهاز أو مثبّتاً في النظام: اطلب المساعدة من الجهات في الأسفل، والحل الأخير «إعادة ضبط المصنع الآمنة».",
       "<b>If it will not go away or comes back,</b> it may be part of device management or built into the system: ask the helplines below; the last resort is the “safe factory reset”.")}</li>
<li>{L("<b>بعد الحذف:</b> غيّر كلمة مرور حساب Google من جهاز آخر، ثم أعد الفحص.", "<b>Afterwards:</b> change your Google password from another device, then scan again.")}</li>
</ol></section>"""

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    if has_quick:
        facts = f"""<div class="facts muted">
  <span><b>{L("الجهاز:", "Device:")}</b> <bdi>{_e(dev.get("manufacturer", ""))} {_e(dev.get("model", ""))}</bdi></span>
  <span><b>{L("أندرويد:", "Android:")}</b> {_e(dev.get("android", ""))}</span>
  <span><b>{L("التحديث الأمني:", "Security patch:")}</b> <bdi>{_e(dev.get("patch", ""))}</bdi></span>
  <span><b>{L("تطبيقات مثبّتة من المستخدم:", "User-installed apps:")}</b> {q.get("third_party_count", 0)}</span>
  <span><b>{L("تاريخ الفحص:", "Scanned:")}</b> <bdi>{now}</bdi></span>
</div>"""
    else:
        facts = f'<div class="facts muted"><span><b>{L("تاريخ التحليل:", "Analysed:")}</b> <bdi>{now}</bdi></span></div>'

    if mode == "logs":
        title = ("تقرير تحليل سجل التسلل", "Intrusion Logging analysis report")
    else:
        title = ("تقرير فحص جهاز أندرويد", "Android phone scan report")
    vt_in_title = L("، وVirusTotal", ", and VirusTotal") if vt_checked else ""

    body = f"""<h1>{L(*title)}</h1>
{facts}

<section class="verdict {vclass}"><h2>{vtitle}</h2><p>{vtext}</p>{patch_note}</section>

<section><h2>{L("نتيجة MVT (مقارنة بمؤشرات برامج التجسس المنشورة", "MVT result (comparison with published spyware indicators")}{vt_in_title})</h2>{vt_html}{mvt_html}</section>
{quick_sections}
{remove_html if has_quick else ""}

<section><h2>{L("ماذا أفعل الآن؟", "What should I do now?")}</h2><ol>
<li>{L("<b>أمّن حسابك:</b> غيّر كلمة مرور حساب Google من جهاز آخر نظيف، وفعّل التحقق بخطوتين، وراجع الأجهزة المتصلة في <a href='https://myaccount.google.com/device-activity'>myaccount.google.com/device-activity</a>.",
       "<b>Secure your account:</b> change your Google password from another, clean device, turn on 2-step verification, and review signed-in devices at <a href='https://myaccount.google.com/device-activity'>myaccount.google.com/device-activity</a>.")}</li>
<li>{L(f"<b>إن ظهر تنبيه «حرج» أو «مرتفع»</b> أو كنت صحفياً أو ناشطاً: اطلب مراجعة مختص مجاناً من {HELP_LINKS[0]} أو {HELP_LINKS[1]}. جهّز لهم حزمة الفحص بالأمر:",
       f"<b>If there is a “critical” or “high” alert,</b> or you are a journalist or activist: ask for a free expert review from {HELP_LINKS[0]} or {HELP_LINKS[1]}. Prepare the scan package with:")}
<pre>{_e(tool)} --package age1...</pre>
<span class="muted small">{L("اطلب منهم مفتاح age العام (يبدأ بـ age1) لتُشفَّر الحزمة فلا يفتحها غيرهم.", "Ask them for their age public key (it starts with age1) so the package is encrypted for them only.")}</span></li>
<li>{L("<b>بعد الانتهاء:</b> أوقف «تصحيح USB» وأوقف «خيارات المطوّر»، واضغط «إلغاء تفويضات تصحيح USB».",
       "<b>When you are done:</b> turn off “USB debugging” and “Developer options”, and tap “Revoke USB debugging authorizations”.")}</li>
</ol></section>

<section><h2>{L("تحصين الهاتف", "Harden the phone")}</h2>
{ap_status}
<ul class="steps">
<li>{L("<b>الحماية المتقدمة (Advanced Protection):</b> ابحث في الإعدادات عن «Advanced Protection» أو «الحماية المتقدمة» وفعّلها. تمنع تثبيت التطبيقات من خارج المتجر، وتوقف شبكات 2G، وتحمي منفذ USB والهاتف مقفل، وتشدّد إعدادات الحماية الأخرى. قد تقيّد بعض الميزات التي تستخدمها.",
       "<b>Advanced Protection:</b> search Settings for “Advanced Protection” and turn it on. It blocks installing apps from outside the store, turns off 2G, protects the USB port while the phone is locked, and tightens other protections. It may limit some features you use.")}</li>
<li>{L(f"<b>سجل التسلل (Intrusion Logging):</b> من داخل «الحماية المتقدمة» فعّل «Intrusion Logging». يحفظ الهاتف لمدة 12 شهراً، بتشفير لا يفتحه غيرك، سجلاً بتثبيت التطبيقات واستعلامات DNS وعناوين IP وتغييرات الشهادات. لتحليله بنفسك: نزّل السجلات من «Intrusion Logging ← Access logs»، ثم:",
       "<b>Intrusion Logging:</b> inside Advanced Protection, turn on “Intrusion Logging”. For 12 months the phone keeps an encrypted log, readable only by you, of app installs, DNS lookups, IP addresses and certificate changes. To analyse it yourself, download the logs from “Intrusion Logging > Access logs”, then:")}
<pre>{_e(tool)} --intrusion-logs intrusion-logs.zip</pre></li>
<li>{L("<b>أعد تشغيل الهاتف يومياً:</b> كثير من برامج التجسس الحكومية لا تبقى بعد إعادة التشغيل. في هواتف سامسونج ابحث في الإعدادات عن «إعادة التشغيل التلقائي» (Auto restart).",
       "<b>Restart the phone every day:</b> much government spyware does not survive a restart. On Samsung phones, search Settings for “Auto restart”.")}</li>
<li>{L("<b>حدّث فور صدور التحديث:</b> نظام التشغيل، ومتجر Play، وتطبيقات المراسلة والمتصفح.", "<b>Update as soon as updates appear:</b> the system, Google Play, messaging apps and the browser.")}</li>
<li>{L("<b>افحص من جهة الشبكة أيضاً:</b> شغّل <code>spyguard-setup.sh</code> على جهاز Raspberry Pi أو جهاز Linux احتياطي، ثم صِل الهاتف بشبكة Wi-Fi التي ينشئها لمدة 30 دقيقة على الأقل.",
       "<b>Check from the network side too:</b> run <code>spyguard-setup.sh</code> on a Raspberry Pi or spare Linux machine, then connect the phone to the Wi-Fi it creates for at least 30 minutes.")}</li>
</ul></section>

<section><h2>{L("إعادة ضبط المصنع الآمنة (عند الشك الجدي)", "Safe factory reset (when you have serious doubts)")}</h2>
<details><summary>{L("الخطوات بالترتيب", "Steps, in order")}</summary><ol>
<li>{L("<b>احفظ الدليل أولاً:</b> احتفظ بمجلد الفحص وبهذا التقرير، وأنشئ حزمة للمختص إن لزم.", "<b>Keep the evidence first:</b> keep the scan folder and this report, and make an expert package if needed.")}</li>
<li>{L("<b>خطّط لسلامتك</b> إن كنت تشك في شخص بعينه، فاختفاء برنامجه قد ينبّهه.", "<b>Plan for your safety</b> if you suspect a specific person: their app disappearing may alert them.")}</li>
<li>{L("<b>من جهاز آخر نظيف:</b> غيّر كلمة مرور Google، وفعّل التحقق بخطوتين بتطبيق مصادقة أو مفتاح مرور بدل الرسائل القصيرة، وسجّل الخروج من كل جهاز لا تعرفه. ثم غيّر كلمات مرور البريد ووسائل التواصل والبنك.",
       "<b>From another, clean device:</b> change your Google password, use an authenticator app or passkey instead of SMS for 2-step verification, and sign out every device you don't recognise. Then change your email, social media and bank passwords.")}</li>
<li>{L("<b>تذكّر كلمة المرور الجديدة جيداً:</b> سيطلبها الهاتف بعد الضبط (حماية FRP).", "<b>Remember the new password well:</b> the phone asks for it after the reset (FRP protection).")}</li>
<li>{L("<b>امسح الهاتف:</b> الإعدادات ← الإدارة العامة أو النظام ← إعادة الضبط ← محو كل البيانات.", "<b>Wipe the phone:</b> Settings > General management or System > Reset > Erase all data.")}</li>
<li>{L("<b>لا تسترجع نسخة التطبيقات الاحتياطية.</b> ثبّت تطبيقاتك يدوياً من متجر Play فقط، ولا تثبّت ما لا تعرفه.", "<b>Do not restore the app backup.</b> Reinstall your apps by hand from Google Play only, and nothing you don't recognise.")}</li>
<li>{L("<b>بعد الإعداد:</b> حدّث النظام، وفعّل «الحماية المتقدمة» و«سجل التسلل» إن توفرا، وضع قفل شاشة قوياً لا يعرفه أحد.", "<b>After setup:</b> update the system, turn on Advanced Protection and Intrusion Logging if available, and set a strong screen lock nobody else knows.")}</li>
<li>{L("<b>أعد الفحص بعد أسبوع.</b>", "<b>Scan again a week later.</b>")}</li>
</ol></details></section>

<p class="muted small">{L(f"أُنشئ هذا التقرير بأداة PhoneHackScan. ملفات الفحص محفوظة على جهاز الكمبيوتر فقط في: {_ltr(run)}. إن نسخت الرسائل احتياطياً فهي ضمن هذه الملفات، فاحذفها حين تنتهي إن لم تعد تحتاجها.",
                         f"Made with PhoneHackScan. The scan files are kept only on this computer, in: {_ltr(run)}. If you backed up SMS, they are among these files: delete them when you no longer need them.")}</p>"""

    (run / "report.html").write_text(_page(*title, body), encoding="utf-8")
    summary = ", ".join(f"{k} {v}" for k, v in counts.items()) if counts else ("none" if mvt_ran else "not run")
    info(f"MVT alerts: {summary}")
    return run / "report.html"


def make_report_iphone(run):
    tool = _tool_cmd()
    ip = _load(run / "iphone.json", {})
    mvt_dir = run / "mvt"
    mvt_ran = (mvt_dir / "info.json").exists()
    alerts = _load(mvt_dir / "alerts.json", [])
    profiles = _load(mvt_dir / "configuration_profiles.json", [])
    apps = ip.get("apps") or _load(mvt_dir / "backup_info.json", {}).get("Installed Applications") or []
    lockdown = any("Lockdown mode enabled" in a.get("message", "") for a in alerts)
    counts = {}
    for a in alerts:
        counts[a.get("level", "")] = counts.get(a.get("level", ""), 0) + 1
    serious = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)

    if not mvt_ran:
        vclass, vtitle = "mid", L("لم يكتمل التحليل", "The analysis did not complete")
        vtext = L("لم يكتمل تحليل MVT. راجع رسائل نافذة الأوامر.", "The MVT analysis did not complete. Check the messages in the terminal window.")
    elif serious:
        vclass, vtitle = "bad", L("تطابق مع مؤشرات برامج تجسس معروفة", "Matches known spyware indicators")
        vtext = L("وجد MVT في النسخة الاحتياطية آثاراً تطابق مؤشرات اختراق منشورة. هذا يستدعي مراجعة جدية، ويُفضّل أن يراجعها مختص قبل أي تصرف. اقرأ قسم «ماذا أفعل الآن؟» في الأسفل.",
                  "MVT found traces in the backup that match published indicators of compromise. Take this seriously and, ideally, have an expert review it before you act. Read “What should I do now?” below.")
    elif profiles:
        vclass, vtitle = "mid", L("في الآيفون ملفات تعريف تتحكم بإعداداته", "The iPhone has configuration profiles")
        vtext = L("لم يظهر تطابق مع مؤشرات برامج التجسس، لكن في الهاتف ملف تعريف واحد على الأقل. هذه الملفات قد تفرض شهادات أو VPN أو إدارة عن بُعد. طبيعية إن كانت من جهة عملك أو دراستك، وإلا فهي أهم ما في الفحص.",
                  "No match with spyware indicators, but the phone has at least one configuration profile. Profiles can impose certificates, a VPN or remote management. They are normal if they come from your employer or school; otherwise they are the most important finding.")
    elif not ip.get("encrypted", True):
        vclass, vtitle = "mid", L("الفحص ناقص: النسخة الاحتياطية غير مشفّرة", "Incomplete: the backup is not encrypted")
        vtext = L("لم يظهر تطابق مع مؤشرات معروفة، لكن النسخة غير المشفّرة لا تتضمن كثيراً مما يفحصه MVT، مثل سجل المكالمات وتاريخ Safari. فعّل «تشفير النسخة الاحتياطية المحلية» وأعد الفحص.",
                  "No match with known indicators, but an unencrypted backup leaves out much of what MVT checks, such as call history and Safari history. Turn on “Encrypt local backup” and scan again.")
    else:
        vclass, vtitle = "good", L("لم يُعثر على مؤشرات معروفة", "No known indicators found")
        vtext = L("لم يظهر أي تطابق مع مؤشرات برامج التجسس المنشورة. تذكّر أن هذا لا يثبت خلوّ الجهاز تماماً، فالفحص لا يكشف إلا ما هو معروف، وبعض برامج التجسس الحكومية لا تترك أثراً بعد إعادة التشغيل.",
                  "No match with published spyware indicators. Remember this does not prove the phone is clean: a scan only finds what is already known, and some government spyware leaves no trace after a restart.")

    if mvt_ran:
        mvt_html = _alert_tables(alerts, counts) + '<p class="muted small">' + L(
            "التنبيه «حرج» يعني تطابقاً مع مؤشر اختراق منشور. التنبيهات المنخفضة (مثل «Missing process» في بيانات استهلاك الشبكة) شائعة وغالباً لا تعني شيئاً وحدها.",
            "A “critical” alert means a match with a published indicator of compromise. Low alerts (such as “Missing process” in network usage data) are common and usually mean nothing on their own.") + "</p>"
    else:
        mvt_html = f'<p class="warn">{L("لم يكتمل تحليل MVT.", "The MVT analysis did not complete.")}</p>'

    if profiles:
        items = []
        for p in profiles:
            pl = p.get("plist") or {}
            types = ", ".join(sorted({c.get("PayloadType", "") for c in pl.get("PayloadContent") or [] if isinstance(c, dict)}))
            name = _e(pl.get("PayloadDisplayName") or "—")
            items.append(f'<li><b>{name}</b> {_ltr(pl.get("PayloadIdentifier", ""))}<div class="muted small">'
                         f'{_e(pl.get("PayloadOrganization", ""))} {_e(pl.get("PayloadDescription", ""))}</div>'
                         + (f'<div class="small">{L("يفرض:", "Imposes:")} {_ltr(types)}</div>' if types else "") + "</li>")
        profiles_html = "<ul>" + "".join(items) + "</ul>"
    else:
        profiles_html = f'<p class="muted">{L("لا يوجد. هذا هو الطبيعي للهاتف الشخصي.", "None. This is normal for a personal phone.")}</p>'

    if apps:
        apps_html = (f'<details><summary>{L(f"{len(apps)} تطبيقاً مثبّتاً", f"{len(apps)} installed apps")}</summary><ul class="cols">'
                     + "".join(f"<li>{_ltr(a)}</li>" for a in apps) + "</ul></details>"
                     + '<p class="muted small">' + L(
                         "في الآيفون، برامج «التجسس التجاري» نادراً ما تكون تطبيقاً مثبّتاً، فأغلبها يعمل عبر سرقة كلمة مرور حساب Apple والدخول إلى نسخ iCloud، أو عبر ملف تعريف. لذلك قسم «ماذا أفعل الآن؟» مهم حتى لو كانت النتيجة نظيفة.",
                         "On iPhone, commercial “stalkerware” is rarely an installed app: most of it works by stealing the Apple Account password to read iCloud backups, or through a configuration profile. That is why “What should I do now?” matters even when the result is clean.") + "</p>")
    else:
        apps_html = f'<p class="muted">{L("لم تتضمن النسخة قائمة التطبيقات.", "The backup did not include the app list.")}</p>'

    remove_html = f"""
<section><h2>{L("كيف أحذف تطبيقاً أو ملف تعريف لا أعرفه؟ (دليل المبتدئ)", "How do I remove an app or profile I don't recognise? (beginner's guide)")}</h2>
<div class="callout">{L("<b>قبل أن تحذف:</b> إن كنت تشك أن شخصاً قريباً منك وراء ذلك، فالحذف قد ينبّهه. احتفظ بهذا التقرير وفكّر في سلامتك أولاً، واطلب المساعدة من " + HELP_LINKS[2] + ".",
                       "<b>Before you remove anything:</b> if you think someone close to you is behind it, removing it may alert them. Keep this report, think about your safety first, and get help from " + HELP_LINKS[2] + ".")}</div>
<ol>
<li>{L("<b>ملف تعريف:</b> الإعدادات ← عام ← «VPN وإدارة الأجهزة» ← اضغط الملف ← «إزالة الملف»، ثم أدخل رمز الهاتف. لا تحذف ملف جهة عملك دون الرجوع إليها.",
       "<b>A profile:</b> Settings > General > “VPN & Device Management” > tap the profile > “Remove Profile”, then enter the passcode. Don't remove your employer's profile without asking them.")}</li>
<li>{L("<b>تطبيق:</b> اضغط مطولاً على أيقونته ← «إزالة التطبيق» ← «حذف التطبيق». إن لم تجد أيقونته: الإعدادات ← عام ← «تخزين iPhone» ← اختر التطبيق ← «حذف التطبيق».",
       "<b>An app:</b> touch and hold its icon > “Remove App” > “Delete App”. If you can't find the icon: Settings > General > “iPhone Storage” > choose the app > “Delete App”.")}</li>
<li>{L("<b>بعد الحذف:</b> غيّر كلمة مرور حساب Apple من جهاز آخر، ثم أعد الفحص بنسخة احتياطية جديدة.",
       "<b>Afterwards:</b> change your Apple Account password from another device, then scan again with a new backup.")}</li>
</ol></section>"""

    backup_date = (ip.get("date") or "")[:16].replace("T", " ")
    facts = f"""<div class="facts muted">
  <span><b>{L("الجهاز:", "Device:")}</b> <bdi>{_e(ip.get("name", ""))}</bdi> <bdi dir="ltr">({_e(ip.get("model", ""))})</bdi></span>
  <span><b>iOS:</b> {_e(ip.get("ios", ""))}</span>
  <span><b>{L("تاريخ النسخة:", "Backup date:")}</b> <bdi>{_e(backup_date)}</bdi></span>
  <span><b>{L("النسخة مشفّرة:", "Encrypted backup:")}</b> {L("نعم", "yes") if ip.get("encrypted") else L("لا", "no")}</span>
  <span><b>{L("وضع المنع (Lockdown Mode):", "Lockdown Mode:")}</b> {L("مفعّل", "on") if lockdown else L("غير مفعّل", "off")}</span>
</div>"""

    title = ("تقرير فحص الآيفون", "iPhone scan report")
    body = f"""<h1>{L(*title)}</h1>
{facts}

<section class="verdict {vclass}"><h2>{vtitle}</h2><p>{vtext}</p></section>

<section><h2>{L("نتيجة MVT (مقارنة بمؤشرات برامج التجسس المنشورة)", "MVT result (comparison with published spyware indicators)")}</h2>{mvt_html}</section>

<section><h2>{L("ملفات التعريف وإدارة الجهاز", "Configuration profiles and device management")}</h2>{profiles_html}</section>

<section><h2>{L("التطبيقات", "Apps")}</h2>{apps_html}</section>
{remove_html}

<section><h2>{L("ماذا أفعل الآن؟", "What should I do now?")}</h2><ol>
<li>{L("<b>أمّن حساب Apple:</b> من جهاز آخر نظيف غيّر كلمة مرور حساب Apple وتأكد أن المصادقة بخطوتين مفعّلة. ثم في الآيفون: الإعدادات ← اسمك، وانزل إلى قائمة الأجهزة واحذف أي جهاز لا تعرفه.",
       "<b>Secure your Apple Account:</b> from another, clean device change the Apple Account password and make sure two-factor authentication is on. Then on the iPhone: Settings > your name, scroll to the device list and remove any device you don't recognise.")}</li>
<li>{L("<b>فحص الأمان (Safety Check):</b> الإعدادات ← الخصوصية والأمن ← فحص الأمان. يعرض من تشارك معه موقعك وصورك وبياناتك، ويوقف المشاركة بضغطة.",
       "<b>Safety Check:</b> Settings > Privacy & Security > Safety Check. It shows who you share your location, photos and data with, and stops sharing in one tap.")}</li>
<li>{L(f"<b>إن ظهر تنبيه «حرج» أو «مرتفع»</b> أو كنت صحفياً أو ناشطاً: اطلب مراجعة مختص مجاناً من {HELP_LINKS[0]} أو {HELP_LINKS[1]}. جهّز لهم حزمة الفحص بالأمر:",
       f"<b>If there is a “critical” or “high” alert,</b> or you are a journalist or activist: ask for a free expert review from {HELP_LINKS[0]} or {HELP_LINKS[1]}. Prepare the scan package with:")}
<pre>{_e(tool)} --package age1...</pre></li>
</ol></section>

<section><h2>{L("تحصين الآيفون", "Harden the iPhone")}</h2><ul class="steps">
<li>{L("<b>وضع المنع (Lockdown Mode):</b> الإعدادات ← الخصوصية والأمن ← وضع المنع. صمّمته Apple لمن قد يُستهدفون ببرامج تجسس حكومية مثل Pegasus. يقيّد بعض الميزات.",
       "<b>Lockdown Mode:</b> Settings > Privacy & Security > Lockdown Mode. Apple built it for people who may be targeted by government spyware such as Pegasus. It limits some features.")}</li>
<li>{L("<b>حدّث iOS فور صدور التحديث:</b> الإعدادات ← عام ← تحديث البرامج، وفعّل التحديث التلقائي.", "<b>Update iOS as soon as updates appear:</b> Settings > General > Software Update, and turn on automatic updates.")}</li>
<li>{L("<b>أعد تشغيل الهاتف يومياً:</b> كثير من برامج التجسس الحكومية لا تبقى بعد إعادة التشغيل.", "<b>Restart the phone every day:</b> much government spyware does not survive a restart.")}</li>
<li>{L("<b>حماية الجهاز المسروق (Stolen Device Protection):</b> الإعدادات ← Face ID ورمز الدخول. تمنع من عرف رمزك من تغيير كلمة مرور حساب Apple مباشرة.",
       "<b>Stolen Device Protection:</b> Settings > Face ID & Passcode. It stops someone who knows your passcode from changing your Apple Account password straight away.")}</li>
<li>{L("<b>شفّر نسخك الاحتياطية دائماً،</b> وأعد هذا الفحص كل بضعة أشهر أو عند الشك.", "<b>Always encrypt your backups,</b> and repeat this scan every few months or whenever in doubt.")}</li>
</ul></section>

<p class="muted small">{L(f"أُنشئ هذا التقرير بأداة PhoneHackScan. نتائج الفحص محفوظة على جهاز الكمبيوتر فقط في: {_ltr(run)}. النسخة الاحتياطية نفسها تبقى في مكانها لدى تطبيق Apple.",
                         f"Made with PhoneHackScan. The results are kept only on this computer, in: {_ltr(run)}. The backup itself stays where the Apple app keeps it.")}</p>"""

    (run / "report.html").write_text(_page(*title, body), encoding="utf-8")
    summary = ", ".join(f"{k} {v}" for k, v in counts.items()) if counts else ("none" if mvt_ran else "not run")
    info(f"MVT alerts: {summary}")
    return run / "report.html"


def open_report(path):
    ok(f"Report: {path}")
    try:
        webbrowser.open(path.resolve().as_uri())
    except Exception:
        pass


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
PHONE_STEPS = """    On the phone:
      a) Settings > About phone > tap "Build number" 7 times  (enables Developer options)
         Samsung: Settings > About phone > Software information > Build number
      b) Settings > System > Developer options > turn on "USB debugging"
      c) Connect it with a USB data cable and keep the screen unlocked"""


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Android & iPhone spyware / stalkerware check (Windows, macOS, Linux).")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--quick", action="store_true", help="quick check only (about one minute)")
    g.add_argument("--intrusion-logs", metavar="PATH", help="analyse Intrusion Logging files (.zip or folder)")
    g.add_argument("--iphone", nargs="?", const="", metavar="FOLDER",
                   help="analyse an encrypted iPhone backup (found automatically, or give its folder)")
    g.add_argument("--open-app", metavar="PACKAGE",
                   help="open the App info page of an app on the connected Android phone (to review or uninstall it)")
    g.add_argument("--package", nargs="?", const="", metavar="AGE_KEY",
                   help="bundle the latest scan for an expert; with an age1... key it is encrypted")
    ap.add_argument("--no-vt", action="store_true", help="do not use VirusTotal")
    return ap.parse_args(argv)


# Logo: figlet "slant" font, kept as plain text so anyone reviewing the tool can read it.
BANNER = r"""
    ____  __                     __  __           __   _____
   / __ \/ /_  ____  ____  ___  / / / /___ ______/ /__/ ___/_________ _____
  / /_/ / __ \/ __ \/ __ \/ _ \/ /_/ / __ `/ ___/ //_/\__ \/ ___/ __ `/ __ \
 / ____/ / / / /_/ / / / /  __/ __  / /_/ / /__/ ,<  ___/ / /__/ /_/ / / / /
/_/   /_/ /_/\____/_/ /_/\___/_/ /_/\__,_/\___/_/|_|/____/\___/\__,_/_/ /_/
"""
TAGLINE = "Android & iPhone intrusion check"
POWERED = "powered by"
BRAND = "UCYBERS"
PAD = " " * 8          # keeps the logo off the window edge
TAG_INDENT = 7         # tagline starts a little to the right, not under the "P"
# Gradient through #b5003c, like the UCYBERS shield: deep crimson -> #b5003c -> bright pink-red
GRADIENT = [(0x8f, 0x0d, 0x39), (0xb5, 0x00, 0x3c), (0xff, 0x4a, 0x80)]


def _truecolor():
    return IS_WIN or "WT_SESSION" in os.environ or os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")


def _xterm256(rgb):
    """Nearest colour of the 256-colour palette, for terminals without 24-bit colour."""
    levels = [0, 95, 135, 175, 215, 255]
    idx = [min(range(6), key=lambda i: abs(levels[i] - c)) for c in rgb]
    cube = tuple(levels[i] for i in idx)
    grey = min(range(24), key=lambda i: abs(8 + 10 * i - sum(rgb) / 3))
    gv = 8 + 10 * grey
    dist = lambda a: sum((x - y) ** 2 for x, y in zip(a, rgb))
    return 16 + 36 * idx[0] + 6 * idx[1] + idx[2] if dist(cube) <= dist((gv, gv, gv)) else 232 + grey


def _grad(t):
    a, b, u = (GRADIENT[0], GRADIENT[1], t * 2) if t < 0.5 else (GRADIENT[1], GRADIENT[2], (t - 0.5) * 2)
    return tuple(round(x + (y - x) * u) for x, y in zip(a, b))


def _paint(rgb, text, bold=True):
    if not _COLOR:
        return text
    color = "38;2;%d;%d;%d" % rgb if _truecolor() else f"38;5;{_xterm256(rgb)}"
    return f"\033[{'1;' if bold else ''}{color}m{text}\033[0m"


def print_banner():
    lines = BANNER.strip("\n").splitlines()
    width = max(len(l) for l in lines)
    credit = _c("90", POWERED) + " " + _paint(GRADIENT[1], BRAND)
    if len(PAD) + width > shutil.get_terminal_size((120, 30)).columns:   # narrow window: name only
        print("\n" + PAD + _paint(GRADIENT[1], "PhoneHackScan") + " - " + TAGLINE + "  " + credit + "\n", flush=True)
        return
    print()
    span = width + 2 * len(lines)
    for row, line in enumerate(lines):
        # diagonal gradient: left to right, drifting slightly with each row
        out = "".join(ch if ch == " " else _paint(_grad((col + 2 * row) / span), ch) for col, ch in enumerate(line))
        print(PAD + out)
    gap = max(2, width - TAG_INDENT - len(TAGLINE) - len(POWERED) - 1 - len(BRAND))
    print()   # empty line between the logo and the texts
    print(" " * (len(PAD) + TAG_INDENT) + _c("37", TAGLINE) + " " * gap + credit + "\n", flush=True)
    if sys.stdout.isatty():
        sys.stdout.write("\033]0;PhoneHackScan\007")


MENU = """    What do you want to check?
      1) Android phone (USB cable)            [default]
      2) iPhone (from an encrypted computer backup)
      3) Android quick check only (about one minute)"""


def main(argv=None):
    print_banner()
    if argv is None and len(sys.argv) == 1 and interactive():
        print(MENU)
        try:
            choice = input("    Choice [1]: ").strip()
        except EOFError:
            choice = ""
        argv = {"2": ["--iphone"], "3": ["--quick"]}.get(choice, [])
    args = parse_args(argv)
    if args.package is not None:
        mode = "package"
        if args.package and not args.package.startswith("age1"):
            die("An age public key starts with age1.")
    elif args.open_app:
        mode = "openapp"
    elif args.intrusion_logs:
        mode = "logs"
    elif args.iphone is not None:
        mode = "iphone"
    elif args.quick:
        mode = "quick"
    else:
        mode = "full"

    plat = Plat()
    tools = Tools(plat)
    info(f"mode: {mode} | {plat.system} | results: {BASE}")
    TOOLS.mkdir(parents=True, exist_ok=True)

    if mode == "package":
        step("Expert package")
        make_package(tools, args.package)
        return 0

    if mode == "openapp":   # no scan folder needed
        step("Open an app's page on the phone")
        tools.ensure_adb()
        serial = wait_for_device(tools.adb, plat)
        open_app_page(tools.adb, serial, args.open_app)
        return 0

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run, n = BASE / f"scan-{stamp}", 1
    while run.exists():  # two runs in the same second
        n += 1
        run = BASE / f"scan-{stamp}-{n}"
    run.mkdir(parents=True)

    if mode == "iphone":
        scan_iphone(tools, plat, args.iphone, run)
        step("Report")
        open_report(make_report_iphone(run))
        return 0

    if mode == "logs":
        step("1. Preparing tools")
        tools.ensure_mvt()
        step("2. Analysing Intrusion Logging files with MVT")
        run_intrusion_logs(tools, plat, args.intrusion_logs, run)
        step("Report")
        open_report(make_report(run, mode))
        return 0

    step("1. Preparing tools")
    tools.ensure_adb()
    vt_key = ""
    if mode == "full":
        tools.ensure_androidqf()
        tools.ensure_mvt()
        vt_key = setup_vt(not args.no_vt)
        if not vt_key:
            (run / "virustotal.json").write_text(json.dumps({"checked": 0, "results": [], "status": VT_STATUS[0]}),
                                                 encoding="utf-8")

    step("2. Connect the phone")
    print(PHONE_STEPS, flush=True)
    serial = wait_for_device(tools.adb, plat)

    step("3. Quick check (read-only)")
    try:
        quick_check(tools.adb, serial, run / "quick")
    except Exception as ex:
        warn(f"Quick check did not finish: {ex}")

    if mode == "full":
        step("4. Full collection with androidqf")
        aqf_out = run_androidqf(tools.aqf, serial, run, tools.adb)
        step("5. Analysis with MVT")
        run_mvt(tools, plat, aqf_out, run)
        if vt_key:
            step("6. VirusTotal (your apps only)")
            run_virustotal(run, aqf_out, vt_key)

    step("Report")
    open_report(make_report(run, mode))
    offer_open_review_apps(tools.adb, serial, run)
    print("\n" + _c("1", "When you are done:") +
          ' turn OFF "USB debugging" on the phone and tap "Revoke USB debugging authorizations".')
    return 0


def _hold_window():
    """On Windows, a double-clicked .py closes its window at once; keep it open so
    the result or error can be read. phonehackscan.cmd has its own pause."""
    if IS_WIN and interactive() and os.environ.get("ANDROID_SCAN_LAUNCHER") != "cmd":
        try:
            input("\nPress Enter to close this window...")
        except (EOFError, KeyboardInterrupt):
            pass


if __name__ == "__main__":
    code = 0
    try:
        code = main()
    except Fatal as ex:
        print("\n" + _c("31", f"ERROR: {ex}"), file=sys.stderr)
        code = 1
    except KeyboardInterrupt:
        print("\nStopped.")
        code = 130
    _hold_window()
    sys.exit(code)


# --------------------------------------------------------------------------- #
# Licence of the embedded Cairo font (CAIRO_WOFF2)
# --------------------------------------------------------------------------- #
# Copyright 2009 The Cairo Project Authors (https://github.com/Gue3bara/Cairo)
#
# This Font Software is licensed under the SIL Open Font License, Version 1.1.
# This license is copied below, and is also available with a FAQ at:
# http://scripts.sil.org/OFL
#
#
# -----------------------------------------------------------
# SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
# -----------------------------------------------------------
#
# PREAMBLE
# The goals of the Open Font License (OFL) are to stimulate worldwide
# development of collaborative font projects, to support the font creation
# efforts of academic and linguistic communities, and to provide a free and
# open framework in which fonts may be shared and improved in partnership
# with others.
#
# The OFL allows the licensed fonts to be used, studied, modified and
# redistributed freely as long as they are not sold by themselves. The
# fonts, including any derivative works, can be bundled, embedded,
# redistributed and/or sold with any software provided that any reserved
# names are not used by derivative works. The fonts and derivatives,
# however, cannot be released under any other type of license. The
# requirement for fonts to remain under this license does not apply
# to any document created using the fonts or their derivatives.
#
# DEFINITIONS
# "Font Software" refers to the set of files released by the Copyright
# Holder(s) under this license and clearly marked as such. This may
# include source files, build scripts and documentation.
#
# "Reserved Font Name" refers to any names specified as such after the
# copyright statement(s).
#
# "Original Version" refers to the collection of Font Software components as
# distributed by the Copyright Holder(s).
#
# "Modified Version" refers to any derivative made by adding to, deleting,
# or substituting -- in part or in whole -- any of the components of the
# Original Version, by changing formats or by porting the Font Software to a
# new environment.
#
# "Author" refers to any designer, engineer, programmer, technical
# writer or other person who contributed to the Font Software.
#
# PERMISSION & CONDITIONS
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of the Font Software, to use, study, copy, merge, embed, modify,
# redistribute, and sell modified and unmodified copies of the Font
# Software, subject to the following conditions:
#
# 1) Neither the Font Software nor any of its individual components,
# in Original or Modified Versions, may be sold by itself.
#
# 2) Original or Modified Versions of the Font Software may be bundled,
# redistributed and/or sold with any software, provided that each copy
# contains the above copyright notice and this license. These can be
# included either as stand-alone text files, human-readable headers or
# in the appropriate machine-readable metadata fields within text or
# binary files as long as those fields can be easily viewed by the user.
#
# 3) No Modified Version of the Font Software may use the Reserved Font
# Name(s) unless explicit written permission is granted by the corresponding
# Copyright Holder. This restriction only applies to the primary font name as
# presented to the users.
#
# 4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
# Software shall not be used to promote, endorse or advertise any
# Modified Version, except to acknowledge the contribution(s) of the
# Copyright Holder(s) and the Author(s) or with their explicit written
# permission.
#
# 5) The Font Software, modified or unmodified, in part or in whole,
# must be distributed entirely under this license, and must not be
# distributed under any other license. The requirement for fonts to
# remain under this license does not apply to any document created
# using the Font Software.
#
# TERMINATION
# This license becomes null and void if any of the above conditions are
# not met.
#
# DISCLAIMER
# THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
# OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
# DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
# OTHER DEALINGS IN THE FONT SOFTWARE.
