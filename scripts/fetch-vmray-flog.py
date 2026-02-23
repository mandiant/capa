#!/usr/bin/env python3
# Copyright 2025 Google LLC
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

"""
Fetch the VMRay Function Log (flog.txt) for a sample and optionally run capa against it.

Given a sample SHA-256 hash and VMRay credentials, this script:
  1. Looks up the sample on the VMRay instance.
  2. Finds the most-recent analysis for that sample.
  3. Downloads the flog.txt (Download Function Log) from the analysis archive.
  4. Optionally runs capa against the downloaded file.

Requirements:
  pip install requests

Usage::

    python scripts/fetch-vmray-flog.py \\
        --url  https://your-vmray.example.com \\
        --apikey YOUR_API_KEY \\
        --sha256 d46900384c78863420fb3e297d0a2f743cd2b6b3f7f82bf64059a168e07aceb7 \\
        --output /tmp/sample_flog.txt

    # Fetch and immediately run capa:
    python scripts/fetch-vmray-flog.py \\
        --url  https://your-vmray.example.com \\
        --apikey YOUR_API_KEY \\
        --sha256 d46900384c78863420fb3e297d0a2f743cd2b6b3f7f82bf64059a168e07aceb7 \\
        --run-capa

VMRay API reference:
  https://docs.vmray.com/documents/api-reference/

Note: this script requires a VMRay account.  The flog.txt itself is freely available
("Download Function Log") in the VMRay Threat Feed web UI, but downloading it
programmatically via the REST API requires valid API credentials.
"""

import argparse
import logging
import subprocess
import sys
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# VMRay REST API helpers
# ---------------------------------------------------------------------------

_FLOG_TXT_ARCHIVE_PATH = "logs/flog_txt"


def _session(url: str, apikey: str) -> requests.Session:
    """Return an authenticated requests.Session for the given VMRay instance."""
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"api_key {apikey}",
            "Accept": "application/json",
        }
    )
    s.verify = True  # set to False only when using self-signed certificates
    s.base_url = url.rstrip("/")  # type: ignore[attr-defined]
    return s


def _get(session: requests.Session, path: str, **kwargs) -> dict:
    url = f"{session.base_url}{path}"  # type: ignore[attr-defined]
    resp = session.get(url, **kwargs)
    resp.raise_for_status()
    return resp.json()


def _get_bytes(session: requests.Session, path: str, **kwargs) -> bytes:
    url = f"{session.base_url}{path}"  # type: ignore[attr-defined]
    resp = session.get(url, **kwargs)
    resp.raise_for_status()
    return resp.content


def lookup_sample(session: requests.Session, sha256: str) -> dict:
    """
    Return the VMRay sample record for the given SHA-256.
    Raises ValueError if the sample is not found.
    """
    data = _get(session, f"/rest/sample/sha256/{sha256}")
    if data.get("result") != "ok" or not data.get("data"):
        raise ValueError(f"sample not found on VMRay instance: {sha256}")
    # data["data"] is a list; take the first entry
    return data["data"][0]


def get_latest_analysis(session: requests.Session, sample_id: int) -> dict:
    """
    Return the most-recent finished analysis for the given VMRay sample ID.
    Raises ValueError if no analysis is found.
    """
    data = _get(session, "/rest/analysis", params={"sample_id": sample_id})
    analyses = data.get("data", [])
    if not analyses:
        raise ValueError(f"no analyses found for sample_id={sample_id}")
    # Sort by analysis_id descending (newest first)
    analyses.sort(key=lambda a: a.get("analysis_id", 0), reverse=True)
    return analyses[0]


def download_flog_txt(session: requests.Session, analysis_id: int) -> bytes:
    """
    Download the flog.txt content for the given VMRay analysis ID.

    VMRay exposes the function log via the analysis archive endpoint.
    We request only the flog_txt entry from the archive using the
    ``file_filter`` query parameter.
    """
    # Try the dedicated log endpoint first (VMRay >= 2024.x)
    try:
        content = _get_bytes(
            session,
            f"/rest/analysis/{analysis_id}/export/v2/logs/flog_txt/binary",
        )
        if content:
            return content
    except requests.HTTPError:
        pass

    # Fallback: download via the analysis archive with a file filter
    content = _get_bytes(
        session,
        f"/rest/analysis/{analysis_id}/archive",
        params={"file_filter[]": _FLOG_TXT_ARCHIVE_PATH},
    )
    return content


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Download VMRay flog.txt for a sample hash and (optionally) run capa."
    )
    parser.add_argument(
        "--url",
        required=True,
        metavar="URL",
        help="Base URL of your VMRay instance, e.g. https://cloud.vmray.com",
    )
    parser.add_argument(
        "--apikey",
        required=True,
        metavar="KEY",
        help="VMRay REST API key (Settings → API Keys).",
    )
    parser.add_argument(
        "--sha256",
        required=True,
        metavar="SHA256",
        help="SHA-256 hash of the sample to analyse.",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="Where to save the downloaded flog.txt.  Defaults to <sha256>_flog.txt in the current directory.",
    )
    parser.add_argument(
        "--run-capa",
        action="store_true",
        dest="run_capa",
        help="After downloading, run 'capa <output>' and print the results.",
    )
    parser.add_argument(
        "--capa-args",
        metavar="ARGS",
        default="",
        help="Extra arguments forwarded to capa (only used with --run-capa).",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_false",
        dest="verify_ssl",
        help="Disable SSL certificate verification (useful for on-premise instances with self-signed certs).",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable debug logging."
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    output_path = Path(args.output) if args.output else Path(f"{args.sha256}_flog.txt")

    session = _session(args.url, args.apikey)
    session.verify = args.verify_ssl  # type: ignore[assignment]

    # Step 1 — look up sample
    logger.info("looking up sample %s …", args.sha256)
    try:
        sample = lookup_sample(session, args.sha256)
    except (requests.HTTPError, ValueError) as exc:
        logger.error("failed to find sample: %s", exc)
        return 1

    sample_id: int = sample["sample_id"]
    logger.debug("found sample_id=%d", sample_id)

    # Step 2 — find the latest analysis
    logger.info("fetching analysis list for sample_id=%d …", sample_id)
    try:
        analysis = get_latest_analysis(session, sample_id)
    except (requests.HTTPError, ValueError) as exc:
        logger.error("failed to find analysis: %s", exc)
        return 1

    analysis_id: int = analysis["analysis_id"]
    logger.debug("using analysis_id=%d", analysis_id)

    # Step 3 — download flog.txt
    logger.info("downloading flog.txt for analysis_id=%d …", analysis_id)
    try:
        flog_bytes = download_flog_txt(session, analysis_id)
    except requests.HTTPError as exc:
        logger.error("failed to download flog.txt: %s", exc)
        return 1

    if not flog_bytes:
        logger.error(
            "received empty response — flog.txt may not be available for this analysis"
        )
        return 1

    output_path.write_bytes(flog_bytes)
    logger.info("saved flog.txt → %s (%d bytes)", output_path, len(flog_bytes))

    # Step 4 (optional) — run capa
    if args.run_capa:
        capa_cmd = ["capa", str(output_path)] + (
            args.capa_args.split() if args.capa_args else []
        )
        logger.info("running: %s", " ".join(capa_cmd))
        result = subprocess.run(capa_cmd)
        return result.returncode

    return 0


if __name__ == "__main__":
    sys.exit(main())
