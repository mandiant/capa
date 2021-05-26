# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os

import setuptools

requirements = [
    "tqdm==4.60.0",
    "pyyaml==5.4.1",
    "tabulate==0.8.9",
    "colorama==0.4.4",
    "termcolor==1.1.0",
    "wcwidth==0.2.5",
    "ida-settings==2.1.0",
    "viv-utils[flirt]==0.6.4",
    "halo==0.0.31",
    "networkx==2.5.1",
    "ruamel.yaml==0.17.4",
    "vivisect==1.0.3",
    "smda==1.5.17",
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
    url="https://www.github.com/fireeye/capa",
    project_urls={
        "Documentation": "https://github.com/fireeye/capa/tree/master/doc",
        "Rules": "https://github.com/fireeye/capa-rules",
        "Rules Documentation": "https://github.com/fireeye/capa-rules/tree/master/doc",
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
            "pytest==6.2.4",
            "pytest-sugar==0.9.4",
            "pytest-instafail==0.4.2",
            "pytest-cov==2.12.0",
            "pycodestyle==2.7.0",
            "black==21.5b1",
            "isort==5.8.0",
        ]
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
    python_requires=">=3.6",
)
