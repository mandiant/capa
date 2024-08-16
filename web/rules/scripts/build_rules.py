import sys
import yaml
import os
from glob import glob
from datetime import datetime

input_directory = sys.argv[1]
txt_file_path = sys.argv[2]
output_directory = sys.argv[3]

assert os.path.exists(input_directory), "input directory must exist"
assert os.path.exists(txt_file_path), "file-modification txt file must exist"
assert os.path.exists(output_directory), "output directory must exist"

def render_features(features_list, indent=0):
    rendered = ''
    indent_str = ' ' * indent
    if isinstance(features_list, list):
        for item in features_list:
            if isinstance(item, dict):
                for key, value in item.items():
                    if isinstance(value, (dict, list)):
                        rendered += f'{indent_str}- {key}:\n'
                        rendered += render_features(value, indent + 2)
                    else:
                        rendered += f'{indent_str}- {key}: {value}\n'
            elif isinstance(item, list):
                rendered += render_features(item, indent)
            else:
                rendered += f'{indent_str}- {item}\n'
    elif isinstance(features_list, dict):
        for key, value in features_list.items():
            if isinstance(value, (dict, list)):
                rendered += f'{indent_str}- {key}:\n'
                rendered += render_features(value, indent + 2)
            else:
                rendered += f'{indent_str}- {key}: {value}\n'
    else:
        rendered += f'{indent_str}- {features_list}\n'
    return rendered

def render_list_item(key, value, indent=0):
    indent_str = ' ' * indent
    rendered = ''
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                for subkey, subvalue in item.items():
                    rendered += render_list_item(subkey, subvalue, indent)
            else:
                rendered += f'{indent_str}  - {item}\n'
    elif isinstance(value, dict):
        for subkey, subvalue in value.items():
            rendered += render_list_item(subkey, subvalue, indent)
    else:
        rendered += f'{indent_str}- {key}: {value}\n'
    return rendered

def get_last_edited_date(file_path):
    # TODO(williballenthin): use file_modification_dates.txt
    last_modified_date = os.path.getmtime(file_path)
    return datetime.fromtimestamp(last_modified_date)

def convert_yaml_to_html(timestamps, yaml_file, output_dir):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file)

    rule = data.get('rule', {}).get('meta', {})

    namespace = rule.get('namespace', '')
    authors = rule.get('authors', [])
    scope_static = rule.get('scopes', {}).get('static', '')
    scope_dynamic = rule.get('scopes', {}).get('dynamic', '')
    attack = rule.get('att&ck', [])
    mbc = rule.get('mbc', [])
    references = ', '.join(rule.get('references', []))
    examples = rule.get('examples', [])
    features = data.get('rule', {}).get('features', [])

    last_edited_str = timestamps[yaml_file]

    rendered_features = render_features(features)

    name = rule.get('name', 'N/A')
    sanitized_name = name.lower().replace(' ', '-').replace('/', '-').replace('\\', '-')
    html_file_name = f"{sanitized_name}.html"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{name}</title>
        <link rel="icon"       href="./img/favicon.ico" type="image/x-icon">
        <link rel="stylesheet" href="./css/bootstrap-5.3.3.min.css">
        <link rel="stylesheet" href="./pagefind/pagefind-ui.css">
        <link rel="stylesheet" href="./pagefind/pagefind-modular-ui.css">
        <link rel="stylesheet" type="text/css" href="./css/styles.css">
    </head>
    <body>
        <nav class="navbar navbar-light bg-light justify-content-between">
            <a class="navbar-brand" href="#">
                <img src="./img/logo.png" alt="Logo" style="max-height: 65px;">
            </a>
            <div id="search"></div>
        </nav>
        <section id="showcase">
            <div class="container">
                <h1>{name}</h1>
            </div>
        </section>
        <div class="container">
            <div class="buttons">
                <button>Last edited: {last_edited_str}</button>
            </div>
            <div class="card">
                <div><b>Namespace:</b> {namespace}</div>
                <div><b>Authors:</b></div><div class="grey-box">{render_list_item('Authors', authors)}</div>
                <div><b>Scope:</b></div><div class="grey-box"><b>Static:</b> {scope_static}<br><b>Dynamic:</b> {scope_dynamic}</div>
                <div><b>ATT&CK:</b></div><div class="grey-box">{render_list_item('ATT&CK', attack)}</div>
                <div><b>MBC:</b></div><div class="grey-box">{render_list_item('MBC', mbc)}</div>
                <div><b>References:</b> {references}</div>
                <div><b>Examples:</b></div><div class="grey-box">{render_list_item('Examples', examples)}</div>
                <div><b>Features:</b></div><div class="grey-box">{rendered_features}</div>
            </div>
        </div>
        <script src="./js/jquery-3.5.1.slim.min.js"></script>
        <script src="./js/bootstrap-5.3.3.min.js"></script>
        <script src="./pagefind/pagefind-ui.js" type="text/javascript"></script>
        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                new PagefindUI({{
                    element: "#search",
                    showEmptyFilters: false,
                    excerptLength: 15
                }});
            }});
        </script>
    </body>
    </html>
    """

    os.makedirs(output_dir, exist_ok=True)
    output_file_path = os.path.join(output_dir, html_file_name)
    with open(output_file_path, 'w') as html_file:
        html_file.write(html_content)

yaml_files = glob(os.path.join(input_directory, '**/*.yml'), recursive=True)

timestamps = {}
with open(txt_file_path, "rt", encoding="utf-8") as f:
    for line in f.read().split("\n"):
        if not line:
            continue
        if line.startswith("==="):
            continue
        path, _, timestamp = line.partition(" ")
        timestamps[path] = timestamp

for yaml_file in yaml_files:
    convert_yaml_to_html(timestamps, yaml_file, output_directory)
