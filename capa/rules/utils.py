# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys
import shutil
import logging
import subprocess
from typing import List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


def is_dev_environment() -> bool:
    if getattr(sys, "frozen", False):
        # running as a PyInstaller executable
        return False

    if "site-packages" in __file__:
        # running from a site-packages installation
        return False

    capa_root = Path(__file__).resolve().parent.parent.parent
    git_dir = capa_root / ".git"

    if not git_dir.is_dir():
        # .git directory doesn't exist
        return False

    git_exe = shutil.which("git")
    if not git_exe:
        # git is not found in PATH
        return False

    return True


def get_modified_files() -> List[Path]:
    try:
        # use git status to retrieve tracked modified files
        result = subprocess.run(
            ["git", "--no-pager", "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            check=True,
        )

        # retrieve .py source files
        # ' M': the file has staged modifications
        # 'M ': the file has unstaged modifications
        # 'MM': the file has both staged and unstaged modifications
        files: List[Path] = []
        for line in result.stdout.splitlines():
            if line.startswith(("M ", "MM", " M")) and line.endswith(".py"):
                file_path = Path(line[3:])
                files.append(file_path)

        return sorted(files)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def get_git_commit_hash() -> Optional[str]:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        commit_hash = result.stdout.strip()
        logger.debug("git commit hash %s", commit_hash)
        return commit_hash
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
