# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import os
import sys

import setuptools

requirements = ["six", "tqdm", "pyyaml", "tabulate", "colorama", "termcolor", "ruamel.yaml"]

if sys.version_info >= (3, 0):
    # py3
    requirements.append("networkx")
else:
    # py2
    requirements.append("enum34")
    requirements.append("vivisect")
    requirements.append("viv-utils")
    requirements.append("networkx==2.2")  # v2.2 is last version supported by Python 2.7

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
    entry_points={"console_scripts": ["capa=capa.main:main",]},
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
