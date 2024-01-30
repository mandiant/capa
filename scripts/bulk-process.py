#!/usr/bin/env python
# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""
bulk-process

Invoke capa recursively against a directory of samples
and emit a JSON document mapping the file paths to their results.

By default, this will use subprocesses for parallelism.
Use `-n/--parallelism` to change the subprocess count from
 the default of current CPU count.
Use `--no-mp` to use threads instead of processes,
 which is probably not useful unless you set `--parallelism=1`.

example:

    $ python scripts/bulk-process /tmp/suspicious
    {
      "/tmp/suspicious/suspicious.dll_": {
        "rules": {
          "encode data using XOR": {
            "matches": {
              "268440358": {
              [...]
      "/tmp/suspicious/1.dll_": { ... }
      "/tmp/suspicious/2.dll_": { ... }
    }


usage:

    usage: bulk-process.py [-h] [-r RULES] [-d] [-q] [-n PARALLELISM] [--no-mp]
                           input_directory

    detect capabilities in programs.

    positional arguments:
      input                 Path to directory of files to recursively analyze

    optional arguments:
      -h, --help            show this help message and exit
      -r RULES, --rules RULES
                            Path to rule file or directory, use embedded rules by
                            default
      -d, --debug           Enable debugging output on STDERR
      -q, --quiet           Disable all output but errors
      -n PARALLELISM, --parallelism PARALLELISM
                            parallelism factor
      --no-mp               disable subprocesses

Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import sys
import json
import logging
import argparse
import multiprocessing
import multiprocessing.pool
from pathlib import Path

import capa
import capa.main
import capa.rules
import capa.loader
import capa.render.json
import capa.capabilities.common
import capa.render.result_document as rd

logger = logging.getLogger("capa")


def get_capa_results(args):
    """
    run capa against the file at the given path, using the given rules.

    args is a tuple, containing:
      rules, signatures, format, backend, os, input_file
    as provided via the CLI arguments.

    args is a tuple because i'm not quite sure how to unpack multiple arguments using `map`.

    returns an dict with two required keys:
      path (str): the file system path of the sample to process
      status (str): either "error" or "ok"

    when status == "error", then a human readable message is found in property "error".
    when status == "ok", then the capa results are found in the property "ok".

    the capa results are a dictionary with the following keys:
      meta (dict): the meta analysis results
      capabilities (dict): the matched capabilities and their result objects
    """
    rules, signatures, format_, backend, os_, input_file = args

    parser = argparse.ArgumentParser(description="detect capabilities in programs.")
    capa.main.install_common_args(parser, wanted={"rules", "signatures", "format", "os", "backend", "input_file"})
    argv = [
        "--signatures",
        signatures,
        "--format",
        format_,
        "--backend",
        backend,
        "--os",
        os_,
        input_file,
    ]
    if rules:
        argv += ["--rules", rules]
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
        capa.main.ensure_input_exists_from_cli(args)
        input_format = capa.main.get_input_format_from_cli(args)
        rules = capa.main.get_rules_from_cli(args)
        backend = capa.main.get_backend_from_cli(args, input_format)
        sample_path = capa.main.get_sample_path_from_cli(args, backend)
        if sample_path is None:
            os_ = "unknown"
        else:
            os_ = capa.loader.get_os(sample_path)
        extractor = capa.main.get_extractor_from_cli(args, input_format, backend)
    except capa.main.ShouldExitError as e:
        # i'm not 100% sure if multiprocessing will reliably raise exceptions across process boundaries.
        # so instead, return an object with explicit success/failure status.
        #
        # if success, then status=ok, and results found in property "ok"
        # if error, then status=error, and human readable message in property "error"
        return {"path": input_file, "status": "error", "error": str(e), "status_code": e.status_code}
    except Exception as e:
        return {
            "path": input_file,
            "status": "error",
            "error": f"unexpected error: {e}",
        }

    capabilities, counts = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)

    meta = capa.loader.collect_metadata(argv, args.input_file, format_, os_, [], extractor, counts)
    meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities)

    doc = rd.ResultDocument.from_capa(meta, rules, capabilities)
    return {"path": input_file, "status": "ok", "ok": doc.model_dump()}


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

        parser = argparse.ArgumentParser(description="detect capabilities in programs.")
        capa.main.install_common_args(parser, wanted={"rules", "signatures", "format", "os", "backend"})
        parser.add_argument("input_directory", type=str, help="Path to directory of files to recursively analyze")
        parser.add_argument(
            "-n", "--parallelism", type=int, default=multiprocessing.cpu_count(), help="parallelism factor"
        )
        parser.add_argument("--no-mp", action="store_true", help="disable subprocesses")
        args = parser.parse_args(args=argv)

        samples = []
        for file in Path(args.input_directory).rglob("*"):
            samples.append(file)

        cpu_count = multiprocessing.cpu_count()

        def pmap(f, args, parallelism=cpu_count):
            """apply the given function f to the given args using subprocesses"""
            return multiprocessing.Pool(parallelism).imap(f, args)

        def tmap(f, args, parallelism=cpu_count):
            """apply the given function f to the given args using threads"""
            return multiprocessing.pool.ThreadPool(parallelism).imap(f, args)

        def map(f, args, parallelism=None):
            """apply the given function f to the given args in the current thread"""
            for arg in args:
                yield f(arg)

        if args.no_mp:
            if args.parallelism == 1:
                logger.debug("using current thread mapper")
                mapper = map
            else:
                logger.debug("using threading mapper")
                mapper = tmap
        else:
            logger.debug("using process mapper")
            mapper = pmap

        rules = args.rules
        if rules == [capa.main.RULES_PATH_DEFAULT_STRING]:
            rules = None

        results = {}
        for result in mapper(
            get_capa_results,
            [(rules, args.signatures, args.format, args.backend, args.os, str(sample)) for sample in samples],
            parallelism=args.parallelism,
        ):
            if result["status"] == "error":
                logger.warning(result["error"])
            elif result["status"] == "ok":
                doc = rd.ResultDocument.model_validate(result["ok"]).model_dump_json(exclude_none=True)
                results[result["path"]] = json.loads(doc)

            else:
                raise ValueError(f"unexpected status: {result['status']}")

        print(json.dumps(results))

        logger.info("done.")

        return 0


if __name__ == "__main__":
    sys.exit(main())
