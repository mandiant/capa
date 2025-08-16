import sys
import time
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


def setup_agent_environment():
    """One-time setup of agent environment for frida-compile"""
    base_dir = Path(__file__).parent
    agent_dir = base_dir / "agent"

    try:
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

        print_success("Agent environment setup complete")
        return True

    except subprocess.CalledProcessError as e:
        print(f"Agent setup failed: {e}")
        return False


def prepare_for_frida_compiler(source_script: Path) -> Path:
    """Inject imports needed for frida-compile compatibility"""
    try:
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

    except Exception as e:
        print(f"Failed to prepare TypeScript for compilation: {e}")
        raise


def compile_typescript_to_bundle(prepared_script: Path):
    """Compile TypeScript to executable JavaScript bundle using frida-compile"""
    try:
        base_dir = Path(__file__).parent
        agent_dir = base_dir / "agent"

        compiler = frida.Compiler()
        compiler.on("diagnostics", on_diagnostics)

        bundle = compiler.build(str(prepared_script), project_root=str(agent_dir))

        print_success("Compiled TypeScript to JavaScript bundle")

        return bundle

    except Exception as e:
        print(f"frida.Compiler failed: {e}")
        raise


def run_frida_with_bundle(package_name: str, bundle: str) -> bool:
    """Run Frida analysis using compiled agent"""
    try:
        device = frida.get_usb_device()
        pid = device.spawn([package_name])
        process = device.attach(pid)

        # Load compiled JavaScript bundle as Frida script
        script = process.create_script(bundle)

        script.on("message", on_message)
        script.load()
        device.resume(pid)

        time.sleep(1)
        print("\nTo stop monitoring: Press Ctrl+D(Unix/Mac) or Ctrl+Z+Enter(Windows)\n")
        sys.stdin.read()

        return True

    except Exception as e:
        print(f"Frida execution failed: {e}")
        return False


def retrieve_results(output_file: str):
    """Use adb to pull results from device and analyze them"""
    try:
        output_dir = Path("frida_outputs")
        output_dir.mkdir(exist_ok=True)

        subprocess.run(
            [
                "adb",
                "pull",
                f"/data/local/tmp/frida_outputs/{output_file}",
                f"./frida_outputs/{output_file}",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        # And analyze results for debuging
        output_path = output_dir / output_file
        with open(output_path, "r") as f:
            lines = f.readlines()

        java_calls = sum(1 for line in lines if '"java_api"' in line)
        native_calls = sum(1 for line in lines if '"native_api"' in line)
        metadata_records = sum(1 for line in lines if '"metadata"' in line)

        print_success(
            f"Retrieved {len(lines)} records. Metadata: {metadata_records}, Java: {java_calls}, Native: {native_calls}"
        )

        return True

    except Exception as e:
        print(f"Failed to retrieve results: {e}")
        return False


def main():
    """
    Automated Frida dynamic analysis workflow:
    1. Setup frida-compile environment
    2. Extract APK metadata and hashes
    3. Generate TypeScript monitoring script
    4. Inject imports for compilation
    5. Compile to JavaScript bundle
    6. Execute dynamic analysis
    7. Retrieve and analyze results
    """
    parser = argparse.ArgumentParser(description="Auto Frida Analysis with frida-compile support")

    parser.add_argument("--package", required=True, help="Android package name")
    parser.add_argument("--apk", help="Local APK file path(optional)")
    parser.add_argument("--apis", default="frida_apis.json", help="API configuration file")
    parser.add_argument("--script", default="frida_monitor.ts", help="Output script filename")
    parser.add_argument("--output", default="api_calls.jsonl", help="Output JSONL filename")
    args = parser.parse_args()

    try:
        # First Step: Setup frida-compile environment with agent (one-time)
        if not setup_agent_environment():
            return 1

        # Next step: Calculate APK hashes
        extract_apk_metadata(args.package, args.apk)

        # Next step: Generate script from templates
        base_dir = Path(__file__).parent
        if args.script:
            source_script = base_dir / "frida_scripts" / args.script

        build_frida_script(base_dir / "frida_apis" / args.apis, source_script, args.output)

        # Next Step: Inject imports for frida-compile
        prepared_script = prepare_for_frida_compiler(source_script)

        # Next Step: Compile TypeScript to JavaScript bundle
        js_bundle = compile_typescript_to_bundle(prepared_script)

        # Next Step: Execute frida analysis with Python API
        if not run_frida_with_bundle(args.package, js_bundle):
            return 1

        # Next Step: Retrieve and analyze results
        if not retrieve_results(args.output):
            return 1

        print_success("Frida Analysis Completed!")
        print("Final step - Analyze with capa:")
        print(f"cd ../../ && source ~/capa-env/bin/activate && python capa/main.py -d frida_outputs/{args.output}")

        return 0

    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
