import yaml, json
import sys
from pathlib import Path
from collections import defaultdict


def classify_api_type(api_name):
    # TODO：Need to find a completely accurate classification method
    if '.' in api_name:
        return 'java'
    return 'java'

def add_api_to_map(api_full_name, categorized_apis):
    # categorized_apis structure is like
    # {"java": {"java.io.File": {"exists", "delete", "<init>"}}}
    api_type = classify_api_type(api_full_name)
    
    if api_type == 'java':
        # Java APIs are structured as "packageName.className.methodName",
        # so the class and method names are separated by the last dot.
        last_dot_index = api_full_name.rfind('.')
        class_name = api_full_name[:last_dot_index]
        method_name = api_full_name[last_dot_index + 1:]

        categorized_apis['java'][class_name].add(method_name)

def extract_apis_from_obj(obj, categorized_apis):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == 'api':
                add_api_to_map(value, categorized_apis)
            else:
                extract_apis_from_obj(value, categorized_apis)
    elif isinstance(obj, list):
        for item in obj:
            extract_apis_from_obj(item, categorized_apis)

def load_template(template_folder, template_name):
    template_file = template_folder / template_name
    
    if not template_file.exists():
        raise FileNotFoundError(f"Template file not found: {template_file}")
    
    with open(template_file, 'r') as f:
        return f.read()

def generate_java_method_hook(template_folder, class_name, var_name, method):
    # Compared to a general method, construction function
    # 1. Always exit, no need to check IF the method exit
    # 2. don't have a return value
    # 3. The writing of init: Java hook need $init, Capa-rules matching need <init>. So we can't use METHOD_NAME replace them together.
    # the rest of the templates logic are the same
    # TODO: Are the different types of templates I implemented in the `hook_template/` aligned with your idea?
    if method == "<init>":
        template = load_template(template_folder, "java_constructor.template")
        return (template.replace('{{CLASS_NAME}}', class_name)
                        .replace('{{VAR_NAME}}', var_name))
    else:
        template = load_template(template_folder, "java_method.template")
        return (template.replace('{{CLASS_NAME}}', class_name)
                        .replace('{{VAR_NAME}}', var_name)
                        .replace('{{METHOD_NAME}}', method))

def generate_java_class_hook(template_folder, class_name, methods):
    var_name = class_name.split('.')[-1]
    
    method_hooks = []
    for method in methods:
        method_hook = generate_java_method_hook(template_folder, class_name, var_name, method)
        method_hooks.append(method_hook)
    
    methods_code = "".join(method_hooks)
    
    class_template = load_template(template_folder, "java_class.template")
    return (class_template.replace('{{CLASS_NAME}}', class_name)
                          .replace('{{VAR_NAME}}', var_name)
                          .replace('{{METHODS_HOOKS}}', methods_code))

def generate_java_api_script(java_apis_data, output_file, template_folder):
    with open(output_file, 'w') as f:
        for class_name, methods in java_apis_data.items():
            hook_code = generate_java_class_hook(template_folder, class_name, set(methods))
            f.write(hook_code)
    
    print(f"Generated Java API hook script: {output_file}")

def main():
    if len(sys.argv) != 3: 
        print("Example: python hook_builder.py <rules_path> <templetes_path>")
        sys.exit(1)
        
    rules_dir = Path(sys.argv[1])
    template_folder = Path(sys.argv[2])

    output_dir = rules_dir.parent / "hook_scripts"
    output_dir.mkdir(exist_ok=True)

    java_apis_file = output_dir / "java_apis.json"
    java_scripts_file = output_dir / "java_hook_script.js"

    categorized_apis = {
        'java': defaultdict(set),    # {"class_name": set(method_names)}
    }

    for rule_file in rules_dir.glob("*.yml"):
        with open(rule_file, 'r') as f:
            data = yaml.safe_load(f)
            if 'rule' in data and 'features' in data['rule']:
                extract_apis_from_obj(data['rule']['features'], categorized_apis)
    
    # Convert Java method_name sets to sorted_lists
    java_apis_map = categorized_apis.get('java', defaultdict(set))
    java_apis_data = {}
    for class_name in sorted(java_apis_map.keys()):
        java_apis_data[class_name] = sorted(list(java_apis_map[class_name]))

    generate_java_api_script(java_apis_data, java_scripts_file, template_folder)
    print(f"Finish generating java api script")

    
if __name__ == "__main__":
    main()
    