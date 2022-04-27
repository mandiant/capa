# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os

import setuptools

requirements = [
    "tqdm==4.64.0",
    "pyyaml==6.0",
    "tabulate==0.8.9",
    "colorama==0.4.4",
    "termcolor==1.1.0",
    "wcwidth==0.2.5",
    "ida-settings==2.1.0",
    "viv-utils[flirt]==0.7.1",
    "halo==0.0.31",
    "networkx==2.5.1",
    "ruamel.yaml==0.17.21",
    "vivisect==1.0.7",
    "smda==1.7.1",
    "pefile==2021.9.3",
    "pyelftools==0.28",
    "dnfile==0.10.0",
    "dncil==1.0.0",
]

# this sets __version__
# via: http://stackoverflow.com/a/7071358/87207
# and: http://stackoverflow.com/a/2073599/87207
with open(os.path.join("capa", "version.py"), "r") as f:
    exec(f.read())


# via: https://packaging.python.org/guides/making-a-pypi-friendly-readme/
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, "README.md"), "r") as f:
    long_description = f.read()


setuptools.setup(
    name="flare-capa",
    version=__version__,
    description="The FLARE team's open-source tool to identify capabilities in executable files.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Willi Ballenthin, Moritz Raabe",
    author_email="william.ballenthin@mandiant.com, moritz.raabe@mandiant.com",
    url="https://www.github.com/mandiant/capa",
    project_urls={
        "Documentation": "https://github.com/mandiant/capa/tree/master/doc",
        "Rules": "https://github.com/mandiant/capa-rules",
        "Rules Documentation": "https://github.com/mandiant/capa-rules/tree/master/doc",
    },
    packages=setuptools.find_packages(exclude=["tests"]),
    package_dir={"capa": "capa"},
    entry_points={
        "console_scripts": [
            "capa=capa.main:main",
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest==7.1.2",
            "pytest-sugar==0.9.4",
            "pytest-instafail==0.4.2",
            "pytest-cov==3.0.0",
            "pycodestyle==2.8.0",
            "black==22.3.0",
            "isort==5.10.1",
            "mypy==0.942",
            "psutil==5.9.0",
            "stix2==3.0.1",
            "requests==2.27.1",
            # type stubs for mypy
            "types-backports==0.1.3",
            "types-colorama==0.4.12",
            "types-PyYAML==6.0.7",
            "types-tabulate==0.8.7",
            "types-termcolor==1.1.3",
            "types-psutil==5.8.22",
            "types_requests==2.27.20",
        ],
        "build": [
            "pyinstaller==5.0",
        ],
    },
    zip_safe=False,
    keywords="capa malware analysis capability detection FLARE",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
)
