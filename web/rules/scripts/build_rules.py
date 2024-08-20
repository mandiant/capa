import sys
import yaml
import os
from glob import glob
from datetime import datetime

import pygments
from pygments.lexers import YamlLexer
from pygments.formatters import HtmlFormatter

input_directory = sys.argv[1]
txt_file_path = sys.argv[2]
output_directory = sys.argv[3]

assert os.path.exists(input_directory), "input directory must exist"
assert os.path.exists(txt_file_path), "file-modification txt file must exist"
assert os.path.exists(output_directory), "output directory must exist"


def convert_yaml_to_html(timestamps, yaml_file, output_dir):
    with open(yaml_file, 'rt', encoding="utf-8") as f:
        rule_content = f.read()
        f.seek(0)
        # TODO(wb): load via capa
        data = yaml.safe_load(f)

    rule = data.get('rule', {}).get('meta', {})

    namespace = rule.get('namespace', '')
    
    last_edited_str = timestamps[yaml_file]

    rendered_rule = pygments.highlight(
       rule_content, 
       YamlLexer(), 
       HtmlFormatter(
         style="xcode", 
         noclasses=True,
         wrapcode=True,
         nobackground=True,
       ))

    name = rule['name']
    # TODO(williballenthin): use capa for this
    sanitized_name = name.lower().replace(' ', '-').replace('/', '-').replace('\\', '-')
    html_file_name = f"{sanitized_name}.html"

    # TODO(wb): link to GitHub source
    # TODO(wb): link to ATT&CK
    # TODO(wb): link to MBC
    # TODO(wb): link to VT search
    # TODO(wb): link to capa result examples
    #
    # TODO(wb): link to namespace
    # TODO(wb): link to author
    # TODO(wb): link references
    # TODO(wb): link to examples

    # TODO(wb): use jinja for templating
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{name}</title>
        <link rel="icon"       href="./img/favicon.ico" type="image/x-icon">
        <link rel="stylesheet" href="./css/bootstrap-5.3.3.min.css">
        <link rel="stylesheet" type="text/css" href="./css/styles.css">
        <script src="./js/jquery-3.5.1.slim.min.js"></script>
        <script src="./js/bootstrap-5.3.3.min.js"></script>
    </head>
    <body>
        <nav class="navbar navbar-light bg-light justify-content-between">
            <a class="navbar-brand" href="#">
                <img src="./img/logo.png" alt="Logo" style="max-height: 65px;">
            </a>
        </nav>
        <div class="container d-flex justify-content-center">
            <div style="max-width: 650px;">
                <p class="lead mb-0 text-secondary">{namespace}</p>
                <h1 class="display-6">{name}</h1>
                <div class="mt-4">
                    {rendered_rule}
                </div>
                <p class="text-secondary">last edited: {last_edited_str}</p>
            </div>
        </div>
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
