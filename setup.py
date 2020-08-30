# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import sys

import setuptools

# halo==0.0.30 is the last version to support py2.7
requirements = ["six", "tqdm", "pyyaml", "tabulate", "colorama", "termcolor", "ruamel.yaml", "wcwidth", "halo==0.0.30"]

if sys.version_info >= (3, 0):
    # py3
    requirements.append("networkx")
else:
    # py2
    requirements.append("enum34==1.1.6")  # v1.1.6 is needed by halo 0.0.30 / spinners 0.0.24
    requirements.append("vivisect==0.1.0rc3")
    requirements.append("viv-utils")
    requirements.append("networkx==2.2")  # v2.2 is last version supported by Python 2.7
    requirements.append("backports.functools-lru-cache")

# this sets __version__
# via: http://stackoverflow.com/a/7071358/87207
# and: http://stackoverflow.com/a/2073599/87207
with open(os.path.join("capa", "version.py"), "rb") as f:
    exec(f.read())


setuptools.setup(
    name="flare-capa",
    version=__version__,
    description="The FLARE team's open-source tool to identify capabilities in executable files.",
    long_description="",
    author="Willi Ballenthin, Moritz Raabe",
    author_email="william.ballenthin@mandiant.com, moritz.raabe@mandiant.com",
    url="https://www.github.com/fireeye/capa",
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
            "pytest",
            "pytest-sugar",
            "pytest-instafail",
            "pytest-cov",
            "pycodestyle",
            "black ; python_version>'3.0'",
            "isort",
        ]
    },
    zip_safe=False,
    keywords="capa",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
    ],
)
