import sys
import time
import shutil
import logging
import argparse
import subprocess
from pathlib import Path

import frida
from hook_builder import build_frida_script
from emulator_creator import create_frida_emulator, setup_android_sdk_path
from apk_meta_extractor import extract_apk_metadata

logger = logging.getLogger(__name__)


def on_detached():
    logger.debug("Frida session detached")


def on_detached_with_reason(reason):
    if reason == "application-requested":
        logger.debug("Application terminated normally")
    else:
        logger.warning(f"Frida session detached: {reason}")


def on_detached_with_varargs(*args):
    logger.debug("on_detached_with_varargs:", args)


def on_diagnostics(diag):
    logger.debug("diag", diag)


def on_message(message, data):
    # TODO: Too many API call messages. Consider adding debug flag for full output.
    # TODO: Other console.log calls could use `send` and `error` types for better control.
    if message.get("type") == "send":
        payload = message.get("payload", {})
        logger.info(payload["message"])


def check_prerequisites():
    if not shutil.which("adb"):
        raise FileNotFoundError("ADB not found. Install Android SDK Platform-Tools and add to system Path")

    if not shutil.which("aapt"):
        raise FileNotFoundError("aapt not found. Install Android SDK Build-Tools and add to system Path")

    if not shutil.which("npm"):
        raise FileNotFoundError("NPM not found. Install Nodejs npm")


def has_connected_device():
    # Verify device connection
    result = subprocess.run(["adb", "devices"], capture_output=True, text=True, check=True)

    lines = result.stdout.strip().split("\n")[1:]
    connected_devices = [line for line in lines if line.strip() and "device" in line]

    if len(connected_devices) > 1:
        raise ValueError("Multiple devices found. Please keep only one device")

    if not connected_devices:
        return False

    logger.info("Connected to target device")
    return True


def verify_root_access():
    # Verify root access
    subprocess.run(["adb", "root"], capture_output=True, check=True)
    time.sleep(1)

    result = subprocess.run(["adb", "shell", "whoami"], capture_output=True, text=True)

    if result.stdout.strip() != "root":
        raise PermissionError(f"Device not rooted. Current user: {result.stdout.strip()}")

    logger.info("Root access obtained")


def prepare_device_output():
    """Make sure Android device for Frida analysis output with permission"""
    result = subprocess.run(["adb", "shell", "ls", "/data/local/tmp/frida_outputs"], capture_output=True, text=True)

    if result.returncode != 0:
        subprocess.run(["adb", "shell", "mkdir -p /data/local/tmp/frida_outputs"], capture_output=True, check=True)

    subprocess.run(["adb", "shell", "chmod -R 777 /data/local/tmp/frida_outputs"], capture_output=True, check=True)

    subprocess.run(["adb", "shell", "setenforce 0"], capture_output=True, check=True)
    logger.debug("SELinux enforcement disabled")

    logger.info("Device output directory ready")


def install_apk_if_provided(apk_path: Path):
    """Install APK to the connected emulator if APK path is provided"""
    if not apk_path.exists():
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    subprocess.run(["adb", "install", "-r", str(apk_path)], capture_output=True, text=True, check=True)
    logger.info(f"APK installed to device: {apk_path.name}")


def setup_agent_environment():
    """One-time setup of Frida TypeScript compilation environment"""
    base_dir = Path(__file__).parent
    agent_dir = base_dir / "agent"

    try:
        if not agent_dir.exists():
            agent_dir.mkdir(exist_ok=True)
            subprocess.run(["frida-create", "-t", "agent"], cwd=agent_dir, capture_output=True, text=True, check=True)

            subprocess.run(["npm", "install"], cwd=agent_dir, check=True)
            subprocess.run(["npm", "install", "frida-java-bridge"], cwd=agent_dir, check=True)

        logger.info("Agent environment ready for frida-compile")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to setup agent environment: {e}") from e


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

    logger.debug(f"Prepared file for compilation: {prepared_filename}")
    return prepared_file


def compile_typescript_to_bundle(prepared_script: Path) -> Path:
    """Compile TypeScript to executable JavaScript bundle using frida-compile"""
    base_dir = Path(__file__).parent
    agent_dir = base_dir / "agent"
    bundle_file = agent_dir / "compiled_bundle.js"

    try:
        compiler = frida.Compiler()  # type: ignore
        compiler.on("diagnostics", on_diagnostics)

        bundle_content = compiler.build(str(prepared_script), project_root=str(agent_dir))

        with open(bundle_file, "w", encoding="utf-8") as f:
            f.write(bundle_content)

        logger.info(f"Compiled TypeScript to JavaScript bundle: {bundle_file}")

        return bundle_file

    except Exception as e:
        raise RuntimeError(f"Failed to compile TypeScript: {e}") from e


def run_frida_with_bundle(package_name: str, bundle_file: Path):
    """Run Frida analysis using compiled agent"""
    session = None
    try:
        with open(bundle_file, "r", encoding="utf-8") as f:
            bundle_content = f.read()

        device = frida.get_usb_device()  # type: ignore
        pid = device.spawn([package_name])
        session = device.attach(pid)

        session.on("detached", on_detached)
        session.on("detached", on_detached_with_reason)
        session.on("detached", on_detached_with_varargs)

        # Load compiled JavaScript bundle as Frida script
        script = session.create_script(bundle_content)

        script.on("message", on_message)
        script.load()
        device.resume(pid)

        time.sleep(1)
        logger.info("\nTo stop monitoring: Press Ctrl+D(Unix/Mac) or Ctrl+Z+Enter(Windows)\n")

        sys.stdin.read()

        return True

    except KeyboardInterrupt:
        logger.info("Automated analysis interrupted by user")
        return False
    except Exception as e:
        raise RuntimeError(f"Failed to run Frida analysis: {e}") from e
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
        ["adb", "pull", device_output_file, str(local_output_file)], capture_output=True, text=True, check=True
    )

    # And analyze results for debuging
    with open(local_output_file, "r") as f:
        lines = f.readlines()

    java_calls = sum(1 for line in lines if '"java_api"' in line)
    native_calls = sum(1 for line in lines if '"native_api"' in line)
    metadata_records = sum(1 for line in lines if '"metadata"' in line)

    logger.info(
        f"Retrieved {len(lines)} records. Metadata: {metadata_records}, Java: {java_calls}, Native: {native_calls}"
    )

    logger.info(f"Results saved to: {local_output_file}")


def main():
    parser = argparse.ArgumentParser(description="Automated Frida analysis for Android applications")

    parser.add_argument("--package", default=None, help="Android package name")
    parser.add_argument("--apk", default=None, type=Path, help="Local APK file path(optional)")
    parser.add_argument("--apis", default="frida_apis.json", help="API configuration file")
    parser.add_argument("--script", default="frida_monitor.ts", help="Output script filename")
    parser.add_argument("--output", default="api_calls.jsonl", help="Output JSONL filename")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    base_dir = Path(__file__).resolve().parent
    scripts_dir = base_dir / "frida_scripts"
    outputs_dir = base_dir / "frida_outputs"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    try:
        setup_android_sdk_path()

        check_prerequisites()

        if not has_connected_device():
            logger.info("Found no devices. Make sure emulator is running")
            response = input("Auto-create an emulator? (y/n): ")
            if response == "y":
                create_frida_emulator()
            else:
                logger.error("Please start your Android device/emulator manually")
                return 1

        verify_root_access()

        # Next step: Install APK if provided
        if args.apk:
            install_apk_if_provided(args.apk)

        # Next Step: Prepare device environment
        prepare_device_output()

        # Next Step: Setup frida-compile environment with agent (one-time)
        setup_agent_environment()

        # Next step: Calculate APK hashes and get package name
        _, package_name = extract_apk_metadata(args.package, args.apk)

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
        if not run_frida_with_bundle(package_name, bundle_file):
            return 1

        # Next Step: Retrieve and analyze results
        retrieve_results(args.output)

        logger.info("Frida Analysis Completed!")
        logger.info("Final step: Run capa to analyze the output file.")
        return 0

    except RuntimeError as e:
        logger.error(f"Error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.debug("interrupted")
        sys.exit(1)
