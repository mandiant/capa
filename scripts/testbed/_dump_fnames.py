"""
IDAPython script to dump JSON file of functions names { fva: fname }.
Meant to be run on benign files with PDB information. IDA should apply function names from the PDB files automatically.
Can also be run on annotated IDA database files.

Example usage (via IDA autonomous mode):
  ida.exe -A -S_dump_fnames.py "<output path>" <sample_path>
"""

import json

import idc
import idautils


def main():
    if len(idc.ARGV) != 2:
        # requires output file path argument
        idc.qexit(-1)

    # wait for auto-analysis to finish
    idc.auto_wait()

    INF_SHORT_DN_ATTR = idc.get_inf_attr(idc.INF_SHORT_DN)  # short form of demangled names

    fnames = {}
    for f in idautils.Functions():
        fname = idc.get_name(f)
        if fname.startswith("sub_"):
            continue

        name_demangled = idc.demangle_name(fname, INF_SHORT_DN_ATTR)
        if name_demangled:
            fname = name_demangled

        fnames[f] = fname

    with open(idc.ARGV[1], "w") as f:
        json.dump(fnames, f)

    # exit IDA
    idc.qexit(0)


if __name__ == "__main__":
    main()
