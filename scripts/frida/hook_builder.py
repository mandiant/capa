import sys
import json
import logging
import argparse
from pathlib import Path

from jinja2 import Environment, StrictUndefined, FileSystemLoader
from frida_api_models import FridaApiSpec
from apk_meta_extractor import load_apk_metadata

logger = logging.getLogger(__name__)


def load_template(templates_dir, template_name):
    try:
        env = Environment(loader=FileSystemLoader(str(templates_dir)), undefined=StrictUndefined)
        template = env.get_template(template_name)
        return template
    except OSError as e:
        raise OSError(f"cannot read template file {template_name}: {e}")


def generate_java_constructor_hook(template, method_info):
    return template.render(
        CLASS_NAME=f"{method_info.package}.{method_info.class_name}",
        VAR_NAME=method_info.class_name,
        capture_args=method_info.arguments,
    )


def generate_java_instance_hook(template, method_info):
    return template.render(
        CLASS_NAME=f"{method_info.package}.{method_info.class_name}",
        VAR_NAME=method_info.class_name,
        METHOD_NAME=method_info.method,
        capture_args=method_info.arguments,
        is_static=method_info.static,
        is_native=method_info.native,
    )


def generate_java_hooks(java_apis, templates_dir):
    if not java_apis or not java_apis.methods:
        logger.info("No Java APIs to generate")
        return ""

    all_java_hooks = []
    method_template = load_template(templates_dir, "java_method.template")
    ctor_template = load_template(templates_dir, "java_constructor.template")

    # Generate Java method hooks
    for method_info in java_apis.methods:
        if method_info.ctor:
            hook = generate_java_constructor_hook(ctor_template, method_info)
        else:
            hook = generate_java_instance_hook(method_template, method_info)

        all_java_hooks.append(hook)

    logger.info(f"Successfully generated {len(java_apis.methods)} Java hooks")
    return "\n\n".join(all_java_hooks)


def generate_native_hook(template, native_info):
    var_name = native_info.library.replace(".", "_").replace("-", "_")
    return template.render(
        LIBRARY_NAME=native_info.library,
        VAR_NAME=var_name,
        FUNCTION_NAME=native_info.function,
        capture_args=native_info.arguments,
        argument_types=native_info.argument_types,
    )


def generate_native_hooks(native_apis, templates_dir):
    if not native_apis or not native_apis.methods:
        logger.info("No Native APIs to generate")
        return ""

    all_native_hooks = []
    native_template = load_template(templates_dir, "native_method.template")

    for native_info in native_apis.methods:
        hook = generate_native_hook(native_template, native_info)
        all_native_hooks.append(hook)

    logger.info(f"Successfully generated {len(native_apis.methods)} Native hooks")
    return "\n\n".join(all_native_hooks)


def build_frida_script(api_file_path: Path, script_file_path: Path, jsonl_filename: str):
    """Main entry point for building Frida monitoring script"""
    base_dir = Path(__file__).resolve().parent
    hook_templates_dir = base_dir / "frida_templates" / "hook_templates"
    main_templates_dir = base_dir / "frida_templates"

    if not hook_templates_dir.exists():
        raise ValueError(f"Hook templates directory not found: {hook_templates_dir}")
    if not main_templates_dir.exists():
        raise ValueError(f"Main templates directory not found: {main_templates_dir}")

    # Load API specs
    frida_apis = FridaApiSpec.from_json_file(api_file_path)

    # Generate hooks
    java_content = generate_java_hooks(frida_apis.java, hook_templates_dir)
    native_content = generate_native_hooks(frida_apis.native, hook_templates_dir)

    apk_meta = load_apk_metadata()

    hashes = apk_meta.get("hashes")
    package_name = apk_meta.get("package_name")

    base_template = load_template(main_templates_dir, "main_template.ts")
    main_script = base_template.render(
        jsonl_filename=jsonl_filename,  # Output JSONL filename
        java_hooks_content=java_content,
        native_hooks_content=native_content,
        hashes=json.dumps(hashes),
        package_name=package_name,
    )

    with open(script_file_path, "w") as f:
        f.write(main_script)

    logger.info(f"Generated Frida script to {script_file_path}")
    return script_file_path


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Generate Frida API call monitoring script")
    parser.add_argument(
        "--apis",
        type=str,
        default="frida_apis.json",
        help="Name of the JSON file used to generate hooks",
    )
    parser.add_argument(
        "--script",
        type=str,
        default="frida_monitor.ts",
        help="Name of generated complete main script file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="api_calls.jsonl",
        help="Name of output file in emulator that record API calls",
    )

    args = parser.parse_args(args=argv)

    logging.basicConfig(level=logging.INFO)

    base_dir = Path(__file__).resolve().parent
    apis_dir = base_dir / "frida_apis"
    scripts_dir = base_dir / "frida_scripts"
    outputs_dir = base_dir / "frida_outputs"

    scripts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    api_file_path = apis_dir / args.apis
    script_file_path = scripts_dir / args.script

    if not api_file_path.exists():
        logger.error(f"APIs file not found: {api_file_path}")
        logger.info("Available files:")
        for f in apis_dir.glob("*.json"):
            logger.info(f"   - {f.name}")
        return 1

    try:
        build_frida_script(api_file_path, script_file_path, args.output)
        logger.info("Hook generation completed successfully")
        return 0
    except Exception as e:
        logger.error(f"error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
