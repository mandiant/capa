import sys
import logging
import argparse
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from frida_api_models import FridaApiSpec

logger = logging.getLogger(__name__)


def load_template(template_dir, template_name):
    try:
        env = Environment(loader=FileSystemLoader(str(template_dir)))
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


def generate_java_method_hook(template, method_info):
    return template.render(
        CLASS_NAME=f"{method_info.package}.{method_info.class_name}",
        VAR_NAME=method_info.class_name,
        METHOD_NAME=method_info.method,
        capture_args=method_info.arguments,
        is_static=method_info.static,
        is_native=method_info.native,
    )


def generate_java_hooks_file(java_apis, template_dir, output_file_path):
    """Generate a Java hooks file, main entry point for Java API hooks"""
    all_java_hooks = []
    method_template = load_template(template_dir, "java_method.template")
    ctor_template = load_template(template_dir, "java_constructor.template")

    # Generate Java method hooks
    for method_info in java_apis.methods:
        if method_info.ctor:
            hook = generate_java_constructor_hook(ctor_template, method_info)
        else:
            hook = generate_java_method_hook(method_template, method_info)

        all_java_hooks.append(hook)

    # Write to output file
    with open(output_file_path, "w") as f:
        f.write("\n\n".join(all_java_hooks))

    print(f"Successfully generated Java hooks to {output_file_path}")


def generate_native_hook(template, native_info):
    var_name = native_info.library.replace(".", "_").replace("-", "_")
    return template.render(
        LIBRARY_NAME=native_info.library,
        VAR_NAME=var_name,
        FUNCTION_NAME=native_info.function,
        capture_args=native_info.arguments,
        argument_types=native_info.argument_types,
    )


def generate_native_hooks_file(native_apis, template_dir, output_file_path):
    all_native_hooks = []
    native_template = load_template(template_dir, "native_method.template")

    for i, native_info in enumerate(native_apis.methods):
        hook = generate_native_hook(native_template, native_info)
        all_native_hooks.append(hook)

    # Write to output file
    with open(output_file_path, "w") as f:
        f.write("\n\n".join(all_native_hooks))

    print(f"Successfully generated Native hooks to {output_file_path}")


def generate_complete_frida_script(template_dir, output_file_path):
    # TODO: Will implement after every hooks are finalized
    pass


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    default_samples_dir = str(Path(__file__).resolve().parent / "frida_hooks")

    parser = argparse.ArgumentParser(description="Generate Frida hooks")
    parser.add_argument("apis_file_path", type=Path, help="Path to APIs JSON file")
    parser.add_argument("templates_dir", type=Path, help="Path to templates directory")
    parser.add_argument("--output-dir", type=Path, default=default_samples_dir, help="Output directory")

    args = parser.parse_args(args=argv)

    logging.basicConfig(level=logging.INFO)

    apis_file = args.apis_file_path
    template_dir = args.templates_dir
    output_dir = args.output_dir

    if not apis_file.exists():
        raise FileNotFoundError(f"APIs file not found: {apis_file}")

    if not template_dir.exists():
        raise FileNotFoundError(f"Templates directory not found: {template_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    frida_apis = FridaApiSpec.from_json_file(apis_file)

    # Java hooks
    if frida_apis.java and frida_apis.java.methods:
        java_output_file_path = output_dir / "java_hooks.js"
        generate_java_hooks_file(frida_apis.java, template_dir, java_output_file_path)

    # Native hooks
    if frida_apis.native and frida_apis.native.methods:
        native_output = output_dir / "native_hooks.js"
        generate_native_hooks_file(frida_apis.native, template_dir, native_output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
