# Copyright 2023 Google LLC
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

import io
import ssl
import shutil
import logging
import zipfile
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timedelta

import capa.rules.cache

logger = logging.getLogger("capa.rules.download")

RULES_URL_DEFAULT = "https://github.com/mandiant/capa-rules/archive/refs/heads/master.zip"
RULES_CACHE_DIR_NAME = "rules-cache"


def get_rules_cache_dir() -> Path:
    return capa.rules.cache.get_default_cache_directory() / RULES_CACHE_DIR_NAME


def is_cache_fresh(cache_dir: Path) -> bool:
    if not cache_dir.exists():
        return False
    
    # Check if the directory is empty or looks incomplete
    if not any(cache_dir.iterdir()):
        return False

    # Check modification time
    timestamp_file = cache_dir / ".download_timestamp"
    if not timestamp_file.exists():
        return False

    try:
        mtime = timestamp_file.stat().st_mtime
        last_download = datetime.fromtimestamp(mtime)
        return datetime.now() - last_download < timedelta(hours=24)
    except OSError:
        return False


def get_ssl_context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        # Fallback to system default
        return ssl.create_default_context()


def download_rules(url: str, dest: Path) -> Path:
    logger.info("downloading rules from %s", url)
    
    ctx = get_ssl_context()
    extract_root = dest.parent / ("tmp_" + dest.name)

    try:
        with urllib.request.urlopen(url, context=ctx) as response:
            with io.BytesIO(response.read()) as archive:
                 with zipfile.ZipFile(archive, "r") as zip_ref:
                    extract_root.mkdir(parents=True, exist_ok=True)
                    zip_ref.extractall(extract_root)

        entries = list(extract_root.iterdir())
        if len(entries) == 1 and entries[0].is_dir():
            source = entries[0]
        else:
            source = extract_root

        if dest.exists():
            shutil.rmtree(dest)

        shutil.move(str(source), str(dest))

    except urllib.error.URLError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            logger.error(
                "SSL Error: %s. Please ensure you have root certificates installed.",
                e,
            )
        raise

    finally:
        if extract_root.exists():
            shutil.rmtree(extract_root)

    # Touch timestamp file
    (dest / ".download_timestamp").touch()
    
    return dest


def ensure_rules(url: str = RULES_URL_DEFAULT) -> Path:
    cache_dir = get_rules_cache_dir()
    
    if is_cache_fresh(cache_dir):
        logger.debug("using cached rules from %s", cache_dir)
        return cache_dir
    
    logger.info("cache is empty or stale, updating...")
    try:
        download_rules(url, cache_dir)
    except Exception as e:
        logger.error("failed to download rules: %s", e)

        if cache_dir.exists() and any(cache_dir.iterdir()):
            logger.warning(
                "using stale cached rules due to download failure"
            )
            return cache_dir

        raise
            
    return cache_dir
