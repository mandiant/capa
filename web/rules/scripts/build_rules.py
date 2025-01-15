# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
import sys
import logging
import urllib.parse
from glob import glob
from pathlib import Path

import pygments
from pygments.lexers import YamlLexer
from pygments.formatters import HtmlFormatter

import capa.rules

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

input_directory = Path(sys.argv[1])
txt_file_path = Path(sys.argv[2])
output_directory = Path(sys.argv[3])

assert input_directory.exists(), "input directory must exist"
assert txt_file_path.exists(), "file-modification txt file must exist"
assert output_directory.exists(), "output directory must exist"


def render_rule(timestamps, path: Path) -> str:
    rule_content = path.read_text(encoding="utf-8")
    rule = capa.rules.Rule.from_yaml(rule_content, use_ruamel=True)

    filename = path.with_suffix("").name
    namespace = rule.meta.get("namespace", "")
    timestamp = timestamps[path.as_posix()]

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

    gh_link = f"https://github.com/mandiant/capa-rules/tree/master/{namespace}/{filename}.yml"
    vt_query = 'behavior_signature:"' + rule.name + '"'
    vt_fragment = urllib.parse.quote(urllib.parse.quote(vt_query))
    vt_link = f"https://www.virustotal.com/gui/search/{vt_fragment}/files"
    ns_query = f'"namespace: {namespace} "'
    ns_link = f"../?{urllib.parse.urlencode({'q': ns_query})}"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{rule.name}</title>
        <link rel="icon"       href="../img/favicon.ico" type="image/x-icon">
        <link rel="stylesheet" href="../css/bootstrap-5.3.3.min.css">
        <script src="../js/jquery-3.5.1.slim.min.js"></script>
        <script src="../js/bootstrap-5.3.3.bundle.min.js"></script>
        <script src="https://cloud.umami.is/script.js" defer data-website-id="0bb8ff9e-fbcc-4ee2-9f9f-b337a2e8cc7f"></script>
        <link rel="stylesheet" type="text/css" href="../css/style.css">
        <style>
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
            <a href="/capa/" class="d-flex align-items-center mb-3 mb-md-0 me-md-auto">
                <img src="../img/logo.png" height=48 />
            </a>

            <ul class="nav nav-pills">
                <li class="nav-item d-flex align-items-center"><a href="/capa/#rules"    class="nav-link text-dark">Rules</a></li>
                <li class="nav-item d-flex align-items-center"><a href="/capa/#examples" class="nav-link text-dark">Examples</a></li>
                <li class="nav-item d-flex align-items-center"><a href="/capa/#download" class="nav-link text-dark">Download</a></li>
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

                <div class="mt-4 rule-content" data-pagefind-body>
                    {rendered_rule}
                </div>
                <p class="text-secondary">last edited: {timestamp}</p>
            </div>
        </div>
    </body>
    </html>
    """

    return html_content


yaml_files = glob(os.path.join(input_directory, "**/*.yml"), recursive=True)

timestamps = {}
for line in txt_file_path.read_text(encoding="utf-8").splitlines():
    if not line:
        continue
    if line.startswith("==="):
        continue

    filepath, _, timestamp = line.partition(" ")
    timestamps[filepath] = timestamp


for yaml_file in yaml_files:
    path = Path(yaml_file)
    rule_content = path.read_text(encoding="utf-8")
    html_content = render_rule(timestamps, path)
    rule = capa.rules.Rule.from_yaml(path.read_text(encoding="utf-8"), use_ruamel=True)

    # like: rules/create file/index.html
    #
    # which looks like the URL fragments:
    #
    #     rules/create%20file/index.html
    #     rules/create%20file/
    #     rules/create file/
    html_path = output_directory / rule.name / "index.html"
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(html_content, encoding="utf-8")
    logger.info("wrote: %s", html_path)

    # like: create-file
    rule_id = path.with_suffix("").name
    # like: rules/create-file/index.html
    #
    # which looks like the URL fragments:
    #
    #     rules/create-file/index.html
    #     rules/create-file/
    #
    # and redirects, via meta refresh, to the canonical path above.
    # since we don't control the GH Pages web server, we can't use HTTP redirects.
    id_path = output_directory / rule_id / "index.html"
    id_path.parent.mkdir(parents=True, exist_ok=True)
    redirect = f"""<html><head><meta http-equiv="refresh" content="0; url=../{rule.name}/"></head></html>"""
    id_path.write_text(redirect, encoding="utf-8")
    logger.info("wrote: %s", id_path)
