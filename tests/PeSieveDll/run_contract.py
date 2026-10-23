import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct
import time


ROOT = Path(__file__).resolve().parents[2]


def run(command, directory, log, env=None):
    result = subprocess.run(command, cwd=directory, capture_output=True, timeout=120, env=env)
    log.write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}: {log}")
    return result


def wait_for_dll(path, seconds):
    deadline = time.monotonic() + seconds
    previous = None
    while True:
        try:
            state = (path.stat().st_size, path.stat().st_mtime_ns)
            evidence = json.loads(path.with_name(path.name + ".exports.json").read_text(encoding="utf-8"))
            if evidence["sha256"] != hashlib.sha256(path.read_bytes()).hexdigest():
                state = None
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            state = None
        if state and (state == previous or seconds == 0):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"DLL fehlt oder wird noch geschrieben: {path}")
        previous = state
        time.sleep(2)


def verify(architecture, args, output):
    platform = {"x64": "Win64", "x86": "Win32"}[architecture]
    dll = args.dll or ROOT / "bin" / platform / args.config / "pe-sieve.dll"
    consumer = ROOT / "parity-work" / f"dll-contract-build-{architecture}" / "Debug" / "NativeMirrorDllContract.exe"
    wait_for_dll(dll, args.wait)
    evidence = output / architecture
    evidence.mkdir()
    run([str(consumer), str(dll)], evidence, evidence / "abi.log")
    linked = consumer.with_name("NativeMirrorDllImportContract.exe")
    environment = dict(os.environ)
    environment["PATH"] = str(dll.parent) + os.pathsep + environment.get("PATH", "")
    run([str(linked)], evidence, evidence / "imports.log", env=environment)
    result = {"dll": str(dll), "sha256": hashlib.sha256(dll.read_bytes()).hexdigest(), "abi": "passed", "scenarios": []}
    target = ROOT / "bin" / "Win64" / args.config / ("NativeMirrorTestTarget.exe" if architecture == "x64" else "NativeMirrorTestTarget32.exe")
    if not target.exists() and architecture == "x86":
        target = ROOT / "bin" / "Win32" / args.config / "NativeMirrorTestTarget32.exe"
    scanner = ROOT / "bin" / platform / args.config / "NativeMirrorScan.exe"
    for scenario in ("Clean", "HeaderPatch", "PrivatePe"):
        directory = evidence / scenario
        directory.mkdir()
        status = directory / "target.json"
        stdout = (directory / "target.stdout").open("wb")
        stderr = (directory / "target.stderr").open("wb")
        child = subprocess.Popen([str(target), f"/scenario:{scenario}", f"/status:{status}"], cwd=directory, stdout=stdout, stderr=stderr)
        try:
            deadline = time.monotonic() + 15
            while not status.exists():
                if child.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f"fixture startup: {scenario}")
                time.sleep(0.1)
            time.sleep(0.2)
            report_path = directory / "dll-report.json"
            run([str(consumer), str(dll), str(child.pid), str(report_path)], directory, directory / "contract.log")
            dll_report = json.loads(report_path.read_text(encoding="utf-8"))["scan_report"]
            values = struct.unpack("<I4B13I", report_path.with_name(report_path.name + ".summary").read_bytes())
            totals = dll_report["scanned"]
            if scenario == "Clean" and totals["modified"]["total"] != 0:
                raise RuntimeError(f"false positives on clean control: {directory}")
            modified = totals["modified"]
            expected = (child.pid, dll_report["is_managed"], dll_report["is_64_bit"],
                        dll_report["used_reflection"], 0, totals["total"], modified["total"],
                        modified["replaced"], modified["hdr_modified"], modified["unreachable_file"],
                        modified["patched"], modified["iat_hooked"],
                        modified["implanted_pe"] + modified["implanted_shc"],
                        modified["implanted_pe"], modified["implanted_shc"], modified["other"],
                        totals["skipped"], totals["errors"])
            if values != expected:
                raise RuntimeError(f"C summary/JSON differs: {directory}: {values} != {expected}")
            command = [str(scanner), "/pid", str(child.pid), "/quiet", "/ofilter", "2", "/json", "/report", "7"]
            cli = subprocess.run(command, cwd=directory, capture_output=True, timeout=120)
            (directory / "cli.stdout").write_bytes(cli.stdout)
            (directory / "cli.stderr").write_bytes(cli.stderr)
            if cli.returncode not in (1, 2):
                raise RuntimeError(f"CLI exit {cli.returncode}: {scenario}")
            cli_report = json.loads(cli.stdout.decode("utf-8"))["scan_report"]
            if dll_report != cli_report:
                raise RuntimeError(f"DLL/CLI JSON differs: {directory}")
            result["scenarios"].append({"scenario": scenario, "json": "equal", "pid": child.pid})
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
            stdout.close()
            stderr.close()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("x64", "x86", "both"), default="x64")
    parser.add_argument("--config", default="Debug")
    parser.add_argument("--dll", type=lambda value: Path(value).resolve())
    parser.add_argument("--wait", type=int, default=0)
    args = parser.parse_args()
    if args.dll and args.arch == "both":
        parser.error("--dll requires --arch x64 or x86")
    output = ROOT / "parity-work" / ("dll-runtime-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    output.mkdir()
    summary = {"status": "running", "architectures": []}
    try:
        for architecture in (("x64", "x86") if args.arch == "both" else (args.arch,)):
            summary["architectures"].append(verify(architecture, args, output))
        summary["status"] = "passed"
    except Exception as error:
        summary["status"] = "failed"
        summary["error"] = str(error)
        raise
    finally:
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(output, flush=True)


if __name__ == "__main__":
    main()
