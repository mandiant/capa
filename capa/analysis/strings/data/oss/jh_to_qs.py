"""
convert from a jh CSV file to a .jsonl.gz OpenSourceString database.

the jh file looks like:

    # triplet,compiler,library,version,profile,path,function,type,value
    x64-windows-static,msvc143,bzip2,1.0.8#3,release,CMakeFiles/bz2.dir/bzlib.c.obj,BZ2_bzBuffToBuffCompress,number,0x00000100
    x64-windows-static,msvc143,bzip2,1.0.8#3,release,CMakeFiles/bz2.dir/bzlib.c.obj,BZ2_bzBuffToBuffCompress,number,0xfffffff8
    x64-windows-static,msvc143,bzip2,1.0.8#3,release,CMakeFiles/bz2.dir/bzlib.c.obj,BZ2_bzBuffToBuffCompress,number,0xfffffffe
    x64-windows-static,msvc143,bzip2,1.0.8#3,release,CMakeFiles/bz2.dir/bzlib.c.obj,BZ2_bzBuffToBuffCompress,api,BZ2_bzCompressInit
    x64-windows-static,msvc143,bzip2,1.0.8#3,release,CMakeFiles/bz2.dir/bzlib.c.obj,BZ2_bzBuffToBuffCompress,api,handle_compress
    x64-windows-static,msvc143,bzip2,1.0.8#3,release,CMakeFiles/bz2.dir/bzlib.c.obj,BZ2_bzBuffToBuffDecompress,number,0x0000fa90
    x64-windows-static,msvc143,bzip2,1.0.8#3,release,CMakeFiles/bz2.dir/bzlib.c.obj,BZ2_bzBuffToBuffDecompress,number,0xfffffff8
    x64-windows-static,msvc143,bzip2,1.0.8#3,release,CMakeFiles/bz2.dir/bzlib.c.obj,BZ2_bzBuffToBuffDecompress,number,0xfffffff9
    x64-windows-static,msvc143,bzip2,1.0.8#3,release,CMakeFiles/bz2.dir/bzlib.c.obj,BZ2_bzBuffToBuffDecompress,number,0xfffffffd

jh is found here: https://github.com/williballenthin/lancelot/blob/master/bin/src/bin/jh.rs
"""
import sys
import json
import pathlib

import msgspec

from capa.analysis.strings import LibraryString

p = pathlib.Path(sys.argv[1])
for line in p.read_text().split("\n"):
    if not line:
        continue

    if line.startswith("#"):
        continue

    triplet, compiler, library, version, profile, path, function, rest = line.split(",", 7)
    type, _, value = rest.partition(",")
    if type != "string":
        continue

    if value.startswith('"'):
        value = json.loads(value)

    s = LibraryString(
        string=value,
        library_name=library,
        library_version=version,
        file_path=path,
        function_name=function,
    )

    sys.stdout.buffer.write(msgspec.json.encode(s))
    sys.stdout.buffer.write(b"\n")
