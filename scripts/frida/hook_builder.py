import yaml, json
import sys
from pathlib import Path


def load_template(template_dir, template_name):
    template_path = template_dir / template_name
    
    if not template_path.exists():
        raise FileNotFoundError(f"Template file not found: {template_path}")
    
    with open(template_path, 'r') as f:
        return f.read()

def generate_java_method_hook(template_dir, package, class_name, method_name, capture_args=True):
    # TODO: If Jinja is required, I'll identify which templates need merging later
    # Currently using string replacement
    full_class_name = f"{package}.{class_name}"
    var_name = class_name
    
    template = load_template(template_dir, "java_method.template")
    return (template.replace('{{CLASS_NAME}}', full_class_name)
                    .replace('{{VAR_NAME}}', var_name)
                    .replace('{{METHOD_NAME}}', method_name))

def generate_java_constructor_hook(template_dir, package, class_name, capture_args=True):
    full_class_name = f"{package}.{class_name}"
    var_name = class_name
    
    template = load_template(template_dir, "java_constructor.template")
    return (template.replace('{{CLASS_NAME}}', full_class_name)
                    .replace('{{VAR_NAME}}', var_name))

def generate_java_hooks_file(java_apis, template_dir, output_file_path):
    """Generate a Java hooks file, main entry point for Java API hooks"""
    all_java_hooks = []
    # Generate Java method hooks
    for method_info in java_apis.get('methods', []):
        package = method_info.get('package')
        class_name = method_info.get('class')
        method_name = method_info.get('method')
        hook = generate_java_method_hook(template_dir, package, class_name, method_name)
        all_java_hooks.append(hook)
    
    # Generate Java constructor hooks  
    for ctor_info in java_apis.get('ctors', []):
        package = ctor_info.get('package')
        class_name = ctor_info.get('class')
        hook = generate_java_constructor_hook(template_dir, package, class_name)
        all_java_hooks.append(hook)

    # Write to output file
    with open(output_file_path, 'w') as f:
        f.write("\n\n".join(all_java_hooks))

def generate_jni_hooks_file(jni_apis, template_dir, output_file_path):
    # TODO: generate_jni_hooks
    pass

def generate_native_hooks_file(native_apis, template_dir, output_file_path):
    # TODO: generate_native_hooks
    pass

def generate_complete_frida_script(template_dir, output_file_path):
    # TODO: Will implement after every hooks are finalized
    pass

def main():
    if len(sys.argv) != 3: 
        print("Example: python hook_builder.py <apis_file_path> <templates_path>")
        sys.exit(1)
        
    apis_file = Path(sys.argv[1])
    template_dir = Path(sys.argv[2])

    output_dir = Path("frida_hooks") 
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(apis_file, 'r') as f:
        frida_apis = json.load(f)

    # Java hooks
    if 'java' in frida_apis: 
        java_apis = frida_apis['java']
        java_output_file_path = output_dir / "java_hooks.js"
        generate_java_hooks_file(java_apis, template_dir, java_output_file_path) 
    
    # JNI hooks
    if 'jni' in frida_apis:
        jni_apis = frida_apis['jni']
        jni_output = output_dir / "jni_hooks.js"
    
    # Native hooks
    if 'native' in frida_apis:
        native_apis = frida_apis['native']
        native_output = output_dir / "native_hooks.js"
    
if __name__ == "__main__":
    main()
    