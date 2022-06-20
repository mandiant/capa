#!/usr/bin/env python
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
                           input

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

Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import os
import sys
import json
import logging
import os.path
import argparse
import multiprocessing
import multiprocessing.pool

import capa
import capa.main
import capa.rules
import capa.render.json
import capa.render.result_document as rd

logger = logging.getLogger("capa")


def get_capa_results(args):
    """
    run capa against the file at the given path, using the given rules.

    args is a tuple, containing:
      rules (capa.rules.RuleSet): the rules to match
      signatures (List[str]): list of file system paths to signature files
      format (str): the name of the sample file format
      path (str): the file system path to the sample to process

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
    rules, sigpaths, format, path = args
    should_save_workspace = os.environ.get("CAPA_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)
    logger.info("computing capa results for: %s", path)
    try:
        extractor = capa.main.get_extractor(
            path, format, capa.main.BACKEND_VIV, sigpaths, should_save_workspace, disable_progress=True
        )
    except capa.main.UnsupportedFormatError:
        # i'm 100% sure if multiprocessing will reliably raise exceptions across process boundaries.
        # so instead, return an object with explicit success/failure status.
        #
        # if success, then status=ok, and results found in property "ok"
        # if error, then status=error, and human readable message in property "error"
        return {
            "path": path,
            "status": "error",
            "error": "input file does not appear to be a PE file: %s" % path,
        }
    except capa.main.UnsupportedRuntimeError:
        return {
            "path": path,
            "status": "error",
            "error": "unsupported runtime or Python interpreter",
        }
    except Exception as e:
        return {
            "path": path,
            "status": "error",
            "error": "unexpected error: %s" % (e),
        }

    meta = capa.main.collect_metadata([], path, [], extractor)
    capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)
    meta["analysis"].update(counts)
    meta["analysis"]["layout"] = capa.main.compute_layout(rules, extractor, capabilities)

    doc = rd.ResultDocument.from_capa(meta, rules, capabilities)

    return {"path": path, "status": "ok", "ok": doc.dict(exclude_none=True)}


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

        parser = argparse.ArgumentParser(description="detect capabilities in programs.")
        capa.main.install_common_args(parser, wanted={"rules", "signatures"})
        parser.add_argument("input", type=str, help="Path to directory of files to recursively analyze")
        parser.add_argument(
            "-n", "--parallelism", type=int, default=multiprocessing.cpu_count(), help="parallelism factor"
        )
        parser.add_argument("--no-mp", action="store_true", help="disable subprocesses")
        args = parser.parse_args(args=argv)
        capa.main.handle_common_args(args)

        try:
            rules = capa.main.get_rules(args.rules)
            rules = capa.rules.RuleSet(rules)
            logger.info("successfully loaded %s rules", len(rules))
        except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
            logger.error("%s", str(e))
            return -1

        try:
            sig_paths = capa.main.get_signatures(args.signatures)
        except (IOError) as e:
            logger.error("%s", str(e))
            return -1

        samples = []
        for (base, directories, files) in os.walk(args.input):
            for file in files:
                samples.append(os.path.join(base, file))

        def pmap(f, args, parallelism=multiprocessing.cpu_count()):
            """apply the given function f to the given args using subprocesses"""
            return multiprocessing.Pool(parallelism).imap(f, args)

        def tmap(f, args, parallelism=multiprocessing.cpu_count()):
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

        results = {}
        for result in mapper(
            get_capa_results, [(rules, sig_paths, "pe", sample) for sample in samples], parallelism=args.parallelism
        ):
            if result["status"] == "error":
                logger.warning(result["error"])
            elif result["status"] == "ok":
                results[result["path"]] = rd.ResultDocument.parse_obj(result["ok"]).json(exclude_none=True)
            else:
                raise ValueError("unexpected status: %s" % (result["status"]))

        print(json.dumps(results))

        logger.info("done.")

        return 0


if __name__ == "__main__":
    sys.exit(main())
