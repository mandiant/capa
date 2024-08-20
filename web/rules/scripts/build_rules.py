import os
import sys
import urllib.parse
from glob import glob

import pygments
import capa.rules
from pygments.lexers import YamlLexer
from pygments.formatters import HtmlFormatter

input_directory = sys.argv[1]
txt_file_path = sys.argv[2]
output_directory = sys.argv[3]

assert os.path.exists(input_directory), "input directory must exist"
assert os.path.exists(txt_file_path), "file-modification txt file must exist"
assert os.path.exists(output_directory), "output directory must exist"


def convert_yaml_to_html(timestamps, yaml_file, output_dir):
    with open(yaml_file, "rt", encoding="utf-8") as f:
        rule_content = f.read()
        rule = capa.rules.Rule.from_yaml(rule_content, use_ruamel=True)

    filename = os.path.basename(yaml_file).rpartition(".yml")[0]
    namespace = rule.meta.get("namespace", "")
    timestamp = timestamps[yaml_file]

    rendered_rule = pygments.highlight(
        rule_content,
        YamlLexer(),
        HtmlFormatter(
            style="xcode",
            noclasses=True,
            wrapcode=True,
            nobackground=True,
        ),
    )

    # TODO(wb): use jinja for templating

    # TODO(wb): link to ATT&CK
    # TODO(wb): link to MBC
    # TODO(wb): link to capa result examples
    #
    # TODO(wb): link to author search

    # TODO(wb): link references
    # TODO(wb): link to examples

    # TODO(wb): link to match rule names, like `match: enumerate PE sections`

    gh_link = f"https://github.com/mandiant/capa-rules/tree/master/{namespace}/{filename}.yml"
    vt_query = 'behavior_signature:"' + rule.name + '"'
    vt_fragment = urllib.parse.quote(urllib.parse.quote(vt_query))
    vt_link = f"https://www.virustotal.com/gui/search/{vt_fragment}/files"
    ns_query = f'"namespace: {namespace} "'
    ns_link = f"./?{urllib.parse.urlencode({'q': ns_query})}"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{rule.name}</title>
        <link rel="icon"       href="./img/favicon.ico" type="image/x-icon">
        <link rel="stylesheet" href="./css/bootstrap-5.3.3.min.css">
        <link rel="stylesheet" type="text/css" href="./css/styles.css">
        <script src="./js/jquery-3.5.1.slim.min.js"></script>
        <script src="./js/bootstrap-5.3.3.bundle.min.js"></script>
        <script defer src="https://cloud.umami.is/script.js" data-website-id="0bb8ff9e-fbcc-4ee2-9f9f-b337a2e8cc7f"></script>
        <style>
        :root {{
            /* from the icon */
            --capa-blue: #2593d7;
            --capa-blue-darker: #1d74aa;

            --bs-primary: var(--capa-blue);
            --bs-primary-rgb: var(--capa-blue);
        }}

        a:not(.btn) {{
            color: var(--capa-blue);
            text-decoration: none;
        }}

        a:not(.btn):hover {{
            text-decoration: underline;
            text-decoration-color: var(--capa-blue) !important;
        }}

        .rule-content .highlight pre {{
            overflow: visible;
        }}
        </style>
    </head>
    <body>
        <header 
                class="d-flex flex-wrap justify-content-center py-1 mb-4 border-bottom fixed-top"
                style="background-color: rgba(255,255,255,0.95);
                box-shadow: 0 0.5rem 1rem rgba(0,0,0,0.05),inset 0 -1px 0 rgba(0,0,0,0.15);"
            >
            <a href="/" class="d-flex align-items-center mb-3 mb-md-0 me-md-auto">
                <img src="./img/logo.png" height=48 />
            </a>

            <ul class="nav nav-pills">
                <li class="nav-item d-flex align-items-center"><a href="/capa/rules#rules"    class="nav-link text-dark">Rules</a></li>
                <li class="nav-item d-flex align-items-center"><a href="/capa/rules#examples" class="nav-link text-dark">Examples</a></li>
                <li class="nav-item d-flex align-items-center"><a href="/capa/rules#download" class="nav-link text-dark">Download</a></li>
            </ul>
        </header>
        
        <div class="container d-flex justify-content-center" style="margin-top: 4rem !important;">
            <div style="max-width: 650px;">
                <p class="lead mb-0 text-secondary">
                    <a href="{ns_link}" class="text-secondary">
                        {namespace}
                    </a>
                </p>
                <h1 class="display-6">{rule.name}</h1>
                
                <ul style="display: block; position: relative; float: right; height: 0px;" class="mt-4">
                    <li><a href="{gh_link}">edit on GitHub</a></li>
                    <li><a href="{vt_link}">search on VirusTotal</a></li>
                </ul>
                
                <div class="mt-4 rule-content">
                    {rendered_rule}
                </div>
                <p class="text-secondary">last edited: {timestamp}</p>
            </div>
        </div>
    </body>
    </html>
    """

    os.makedirs(output_dir, exist_ok=True)
    output_file_path = os.path.join(output_dir, filename + ".html")
    with open(output_file_path, "wt", encoding="utf-8") as html_file:
        html_file.write(html_content)


yaml_files = glob(os.path.join(input_directory, "**/*.yml"), recursive=True)

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
