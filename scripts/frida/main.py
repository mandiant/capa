import sys
import time
import shutil
import argparse
import subprocess
from pathlib import Path

import frida
from hook_builder import build_frida_script
from apk_meta_extractor import extract_apk_metadata


def on_diagnostics(diag):
    print("diag", diag)


def on_message(message, data):
    print(message)


def print_success(message):
    print(f"✓ {message}")


def check_device_connection():
    if not shutil.which("adb"):
        print("ADB not found. Install Android SDK platform-tools")
        return False
    if not shutil.which("npm"):
        print("NPM not found. Install Nodejs npm")
        return False

    result = subprocess.run(["adb", "devices"], capture_output=True, text=True, check=True)

    lines = result.stdout.strip().split("\n")[1:]
    connected_devices = [line for line in lines if line.strip() and "device" in line]

    if not connected_devices:
        print("Found no devices. Make sure Android emulator is running")
        return False

    if len(connected_devices) > 1:
        print("Multiple devices found. Please keep only one device")
        return False

    result = subprocess.run(["adb", "shell", "whoami"], capture_output=True, text=True)

    if result.stdout.strip() != "root":
        print(f"Device not rooted. Current user: {result.stdout.strip()}")
        return False

    print_success("Dependencies and device verified")
    return True


def prepare_device_output():
    """Make sure Android device for Frida analysis output with permission"""

    subprocess.run(["adb", "root"], capture_output=True, check=True)
    time.sleep(1)  # wait adb daemon to restart
    print_success("Root access obtained")

    result = subprocess.run(
        ["adb", "shell", "ls", "/data/local/tmp/frida_outputs"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        subprocess.run(
            ["adb", "shell", "su", "-c", "mkdir -p /data/local/tmp/frida_outputs"],
            capture_output=True,
            check=True,
        )

    subprocess.run(
        ["adb", "shell", "su", "-c", "chmod -R 777 /data/local/tmp/frida_outputs"],
        capture_output=True,
        check=True,
    )

    subprocess.run(["adb", "shell", "su", "-c", "setenforce 0"], capture_output=True, check=True)
    print_success("SELinux enforcement disabled")

    print_success("Output directory ready")

    print_success("Device environment prepared")


def install_apk_if_provided(apk_path: str):
    """Install APK to the connected emulator if APK path is provided"""
    apk_file = Path(apk_path)
    if not apk_file.exists():
        print(f"APK file not found: {apk_path}")
        return False

    subprocess.run(
        ["adb", "install", "-r", str(apk_file)],
        capture_output=True,
        text=True,
        check=True,
    )
    print_success(f"APK installed to device: {apk_file.name}")
    return True


def setup_agent_environment():
    """One-time setup of Frida TypeScript compilation environment"""
    base_dir = Path(__file__).parent
    agent_dir = base_dir / "agent"

    if not agent_dir.exists():
        agent_dir.mkdir(exist_ok=True)
        subprocess.run(
            ["frida-create", "-t", "agent"],
            cwd=agent_dir,
            capture_output=True,
            text=True,
            check=True,
        )

        subprocess.run(["npm", "install"], cwd=agent_dir, check=True)
        subprocess.run(["npm", "install", "frida-java-bridge"], cwd=agent_dir, check=True)

    print_success("Agent environment ready for frida-compile")


def prepare_for_frida_compiler(source_script: Path) -> Path:
    """Inject Java bridge import for Frida 17.x compatibility"""
    base_dir = Path(__file__).parent
    agent_dir = base_dir / "agent"

    prepared_filename = source_script.name.replace(".ts", "_prepared.ts")
    prepared_file = agent_dir / prepared_filename

    content = source_script.read_text(encoding="utf-8")
    lines = content.splitlines(True)

    # Inject import after the first line (@ts-nocheck)
    new_lines = lines[:1] + ['import Java from "frida-java-bridge";\n'] + lines[1:]

    # TODO: Could be created in /tmp folder, it is not neccesary to be shown
    prepared_file.write_text("".join(new_lines), encoding="utf-8")

    print_success(f"Prepared file for compilation: {prepared_filename}")
    return prepared_file


def compile_typescript_to_bundle(prepared_script: Path) -> Path:
    """Compile TypeScript to executable JavaScript bundle using frida-compile"""
    base_dir = Path(__file__).parent
    agent_dir = base_dir / "agent"
    bundle_file = agent_dir / "compiled_bundle.js"

    compiler = frida.Compiler()
    compiler.on("diagnostics", on_diagnostics)

    bundle_content = compiler.build(str(prepared_script), project_root=str(agent_dir))

    with open(bundle_file, "w", encoding="utf-8") as f:
        f.write(bundle_content)

    print_success(f"Compiled TypeScript to JavaScript bundle: {bundle_file}")

    return bundle_file


def run_frida_with_bundle(package_name: str, bundle_file: Path):
    """Run Frida analysis using compiled agent"""
    session = None
    try:
        with open(bundle_file, "r", encoding="utf-8") as f:
            bundle_content = f.read()

        device = frida.get_usb_device()
        pid = device.spawn([package_name])
        session = device.attach(pid)

        # Load compiled JavaScript bundle as Frida script
        script = session.create_script(bundle_content)

        script.on("message", on_message)
        script.load()
        device.resume(pid)

        time.sleep(1)
        print("\nTo stop monitoring: Press Ctrl+D(Unix/Mac) or Ctrl+Z+Enter(Windows)\n")

        sys.stdin.read()

        return True

    except KeyboardInterrupt:
        print("\nAutomated analysis interrupted by user")
        return False
    finally:
        if session:
            session.detach()


def retrieve_results(output_file: str):
    """Use adb to pull results from device and analyze them"""
    local_output_dir = Path("frida_outputs")
    local_output_dir.mkdir(exist_ok=True)
    local_output_file = local_output_dir / output_file

    device_output_file = f"/data/local/tmp/frida_outputs/{output_file}"

    subprocess.run(
        [
            "adb",
            "pull",
            device_output_file,
            str(local_output_file),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    # And analyze results for debuging
    with open(local_output_file, "r") as f:
        lines = f.readlines()

    java_calls = sum(1 for line in lines if '"java_api"' in line)
    native_calls = sum(1 for line in lines if '"native_api"' in line)
    metadata_records = sum(1 for line in lines if '"metadata"' in line)

    print_success(
        f"Retrieved {len(lines)} records. Metadata: {metadata_records}, Java: {java_calls}, Native: {native_calls}"
    )


def main():
    parser = argparse.ArgumentParser(description="Automated Frida analysis for Android applications")

    parser.add_argument("--package", required=True, help="Android package name")
    parser.add_argument("--apk", help="Local APK file path(optional)")
    parser.add_argument("--apis", default="frida_apis.json", help="API configuration file")
    parser.add_argument("--script", default="frida_monitor.ts", help="Output script filename")
    parser.add_argument("--output", default="api_calls.jsonl", help="Output JSONL filename")
    args = parser.parse_args()

    try:
        if not check_device_connection():
            return 1

        # Next step: Install APK if provided
        if args.apk:
            if not install_apk_if_provided(args.apk):
                return 1

        # Next Step: Prepare device environment
        prepare_device_output()

        # Next Step: Setup frida-compile environment with agent (one-time)
        setup_agent_environment()

        # Next step: Calculate APK hashes
        extract_apk_metadata(args.package, args.apk)

        base_dir = Path(__file__).parent
        source_script = base_dir / "frida_scripts" / args.script
        apis_file = base_dir / "frida_apis" / args.apis

        # Next step: Generate script from templates
        build_frida_script(apis_file, source_script, args.output)

        # Next Step: Inject imports for frida-compile
        prepared_script = prepare_for_frida_compiler(source_script)

        # Next Step: Compile TypeScript to JavaScript bundle
        bundle_file = compile_typescript_to_bundle(prepared_script)

        # Next Step: Execute frida analysis with Python API
        if not run_frida_with_bundle(args.package, bundle_file):
            return 1

        # Next Step: Retrieve and analyze results
        retrieve_results(args.output)

        print_success("Frida Analysis Completed!")
        print("Final step - Analyze with capa:")
        print(f"cd ../../ && source ~/capa-env/bin/activate && python capa/main.py -d frida_outputs/{args.output}")

        return 0

    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
