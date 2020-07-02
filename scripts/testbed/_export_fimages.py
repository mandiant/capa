"""
IDAPython script to export DOT files of function graphs.

Example usage (via IDA autonomous mode):
  ida.exe -A -S_export_fimages.py "<output dir>" <fva1> [<fva2> ...] <sample_path>
"""

import os

import idc
import idaapi
import ida_gdl


def main():
    if len(idc.ARGV) < 3:
        # requires output directory and function VAs argument(s)
        idc.qexit(-1)

    # wait for auto-analysis to finish
    idc.auto_wait()

    out_dir = idc.ARGV[1]
    fvas = [int(fva, 0x10) for fva in idc.ARGV[2:]]
    idb_name = os.path.split(idc.get_idb_path())[-1]

    for fva in fvas:
        fstart = idc.get_func_attr(fva, idc.FUNCATTR_START)
        name = "%s_0x%x" % (idb_name.replace(".", "_"), fstart)
        out_path = os.path.join(out_dir, name)
        fname = idc.get_name(fstart)

        if not ida_gdl.gen_flow_graph(
            out_path,
            "%s (0x%x)" % (fname, fstart),
            idaapi.get_func(fstart),
            0,
            0,
            ida_gdl.CHART_GEN_DOT | ida_gdl.CHART_PRINT_NAMES,
        ):
            print "IDA error generating flow graph"
        # TODO add label to DOT file, see https://stackoverflow.com/a/6452088/10548020
        # TODO highlight where rule matched

    # exit IDA
    idc.qexit(0)


if __name__ == "__main__":
    main()
