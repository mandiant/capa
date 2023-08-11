#!/usr/bin/env python2
"""
match-2-yar

Invoke capa to extract the capabilities of the given sample or list of samples, 
and emit the matches as yara rules.

When providing multiple samples or directories the tool will attempt to create
"super rules" based on overlapping signatures


Example::

    $ python scripts/match-2-yar.py /tmp/suspicious.dll_
    ...

Example::

    $ python scripts/match-2-yar.py /tmp/suspicious.dll_ /tmp/suspicious2.dll_
    ...

"""
import os
import sys
import logging
import argparse
import collections
import multiprocessing
import multiprocessing.pool
from datetime import date
from pathlib import Path

import capa.main
import capa.rules
import capa.engine
import capa.helpers
import capa.features
import capa.exceptions
import capa.render.utils as rutils
import capa.render.verbose
import capa.features.freeze
import capa.render.result_document as rd
from capa.features.common import OS_AUTO
from capa.features.extractors.dnfile.extractor import DnfileFeatureExtractor

import dnfile
from dncil.clr.token import Token

from envi.memcanvas import MemoryCanvas
from vivisect.renderers import WorkspaceRenderer

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OPT_SYNTAX_INTEL
    from mkyara import YaraGenerator
    import yaramod
except ImportError:
    print("""\nFailed to import a module try installing required Python libraries with the following:
pip install mkyara yaramod
""" )
    sys.exit(1)


logger = logging.getLogger("capa.match-2-yar")


######## Vivisect Related Classes and Functions ########

class BufferCanvas(MemoryCanvas):
    """Subclass of Vivisect Memory canvas that captures
    disassemlby output as a string rather than printing to std.out
    """
    output = ""

    def addText(self, text, tag=None):
        """Overwriting the method responsible for writing to std.out
        """
        self.output += text

def get_disassembly_output(vw, va, size):
    """Get Vivisect's disassembly view for a given virtual addresss and size

    Args:
        vw: Vivisect Workspace
        va: Virtual Address to start disassembling from
        size: size in bytes to disassemble
    
    Returns:
        str: String containing vivisect's disassembly output
    """
    rend = WorkspaceRenderer(vw)
    mcav = BufferCanvas(vw)
    mcav.renderMemory(va, size, rend=rend)
    return mcav.output


def get_comment_for_func(vw, funcva):
    """Get a CodeFeature comment for a function
    
    This function gets the size of a function and 
    uses that to get a dump of the function disassembly 
    with get_dissasembly_output

    Args:
        vw: Vivisect Workspace
        funcva: Virtual Address of function to analyze
    
    Returns:
        str: String containing disassembly output for a function
    """
    funcsize = get_function_size(vw, funcva)
    return get_disassembly_output(vw, funcva, funcsize)

def get_comment_for_cb(vw, va):
    """Get a CodeFeature comment for a Code Block
    
    This function gets the size of a code block and 
    uses that to get a dump of the code block disassembly 
    with get_dissasembly_output
    
    Args:
        vw: Vivisect Workspace
        va: Virtual Address of Codeblock to analyze

    Returns:
        str: String containing disassembly output for a function
    """
    cb = vw.getCodeBlock(va)
    cbva, cbsize, cbfunc = cb
    return get_disassembly_output(vw, cbva, cbsize)

def get_function_size(vw, funcva):
    """Return the size of a function based on vivisect analysis

    Args:
        vw: Vivisect Workspace
        funcva: Virtual Address of function to analyze
    
    Returns:
        int: size of the function
    """
    fsize = 0
    if funcva not in vw.getFunctions():
        funcva = vw.getFunction(funcva)
        if funcva is None:
            raise Exception('Given funcva not a function or within a known function')
    func_blocks = [cbva for cbva, _, _ in vw.getFunctionBlocks(funcva)]
    # Figure out the size of the first linear chunk
    # in this function...
    cb = vw.getCodeBlock(funcva)
    if cb[0] not in func_blocks:
        raise Exception("funcva not in given func")
    while cb is not None:
        cbva, cbsize, cbfunc = cb
        if cbfunc != funcva:
            break
        fsize += cbsize
        cb = vw.getCodeBlock(cbva+cbsize)

    if fsize == 0:
        raise Exception("0 length function??!?1")
    
    return fsize

def get_function_bytes(vw, funcva):
    """Return the bytes from a function
    
    Args:
        vw: Vivisect Workspace
        funcva: Virtual Address of function to analyze
    
    Returns:
        bytes: bytes of a function
    """
    fsize = get_function_size(vw, funcva)
    return vw.readMemory(funcva, fsize)

def get_cb_bytes(vw, va):
    """Return the bytes from a code block
    
    Args:
        vw: Vivisect Workspace
        va: Virtual Address to analyze
    
    Returns:
        int: size of the function
    """
    cb = vw.getCodeBlock(va)
    cbva, cbsize, cbfunc = cb
    return vw.readMemory(cbva, cbsize)


######## Capstone Related Classes and Functions ########

VIVI_ARCH_TO_CAPSTONE = {
    'i386': (CS_ARCH_X86, CS_MODE_32),
    'amd64': (CS_ARCH_X86, CS_MODE_64)
}

def mkyara_sig_generation(start_va, bytez, arch, mode):
    """Mask x86/x64 instructions and generate a signature

    This uses mkyara's logic for now, but an area for research to
    build out the system to test resiliency.

    Args:
        start_va: virtual address of first instruction
        bytez: byte string containing raw bytes of the function
        arch: Capstone Architecture to use (CS_ARCH_X86 covers 32 and 64bit x86)
        mode: Capstone mode to choose between 32 and 64 bit
    
    Returns:
        str: signature string in the form of "AA BB CC DD"
    """
    gen = YaraGenerator("normal", arch, mode)
    gen.add_chunk(bytez, offset=start_va)

    md = Cs(arch, mode)
    md.detail = True
    md.syntax = CS_OPT_SYNTAX_INTEL

    sig = ""
    disasm = md.disasm(bytez, start_va)
    for ins in disasm:
        rule_part, comment = gen._process_instruction(ins)
        rule_part = gen.format_hex(rule_part)
        sig += rule_part + " "

    return sig
    

def genSigAndMask(start_va, bytez, vivi_arch='i386'):
    """Generate a signature and masked signature for a fuction virtual address

    This function performs the translation from vivisect arch
    to the mode and arch needed by capstone

    Args:
        start_va: virtual address of first instruction
        bytez: byte string containing raw bytes of the function
        vivi_arch: Vivisect architecture
    
    Returns:
        str: signature string in the form of "AA BB CC DD"
    """
    
    arch, mode = VIVI_ARCH_TO_CAPSTONE[vivi_arch]

    # Other option for normal is loose, but we won't use those here
    return mkyara_sig_generation(start_va, bytez, arch, mode)

######## .NET Related Classes and Functions ########

def format_operand(pe, op):
    """Return a string representation of a .NET operand
    
    Use a dnfile object to reference .NET tables to understand
    methods, classes, and strings
    
    Args:
        pe: dnfile object for a .NET PE
        op: dncil operand from an instruction
    Returns:
        str: string representation of an operand
    """
    if isinstance(op, Token):
        op = capa.features.extractors.dnfile.helpers.resolve_dotnet_token(pe, op)

    if isinstance(op, str):
        return f'"{op}"'
    elif isinstance(op, int):
        return hex(op)
    elif isinstance(op, list):
        return f"[{', '.join(['({:04X})'.format(x) for x in op])}]"
    elif isinstance(op, dnfile.mdtable.MemberRefRow) and not isinstance(op.Class.row, dnfile.mdtable.TypeSpecRow):
        return f"{str(op.Class.row.TypeNamespace)}.{op.Class.row.TypeName}::{op.Name}"
    elif isinstance(op, (dnfile.mdtable.FieldRow, dnfile.mdtable.MethodDefRow, dnfile.mdtable.MemberRefRow)):
        return f"{op.Name}"
    elif isinstance(op, (dnfile.mdtable.TypeDefRow, dnfile.mdtable.TypeRefRow)):
        return f"{op.TypeNamespace}.{op.TypeName}" 
    elif isinstance(op, (dnfile.mdtable.TypeSpecRow, dnfile.mdtable.MethodSpecRow)):
        return f"{str(op.struct)}"
    else:
        return "" if op is None else str(op)

def get_sig_and_mask_for_dotnet_func(dnpe, body):
    """Return the comment, sig, and bytes of a .NET Method
    
    Iterate a method body to get IL bytes and mask the operand
    values to create a more flexible signature

    Args:
        dnpe: dnfile object for a .NET PE
        body: dncil method body
    Returns:
        str comment: Comment string with formatted .NET IL disassembly
        str formatted_sig: signature as string with hex and wildcards
        str func_bytes: hex bytes of a .NET method
    """

    comment = ""
    sig = ""
    func_bytes = ""
    for insn in body.instructions:
        comment += (
                "{:04X}".format(insn.offset)
                + "    "
                + f"{' '.join('{:02x}'.format(b) for b in insn.get_bytes()) : <20}"
                + f"{str(insn.opcode) : <15}"
                + format_operand(dnpe, insn.operand)
                + "\n"
            )

        sig += insn.get_opcode_bytes().hex()
        func_bytes += insn.get_opcode_bytes().hex()

        if insn.operand:
            sig += '??' * len(insn.get_operand_bytes())
            func_bytes += insn.get_operand_bytes().hex()

    # Format the sig to be in the same style as the vivi portion (bytes seperated by spaces)
    formatted_sig = ""
    for idx, val in enumerate(sig):
        if idx > 0 and idx % 2 == 0: 
            formatted_sig += " "
        formatted_sig += val
        
       
    return comment, formatted_sig, func_bytes

######## CodeFeature Extractor Related Classes and Functions ########

class CodeFeature():
    """Basic object that that will be used to create yara rules
    """
    def __init__(self, sig: str, comment: str, bytez: bytes, filemd5:str):
        self.sig = sig
        self.comment = comment
        self.bytez = bytez
        self.filemd5 = filemd5

def get_code_features_for_capa_doc(doc: rd.ResultDocument, extractor):
    """Returns a dictionary mapping a filemd5 to a list of CodeFeatures 
    
    This function operates on x86/x64 PE files and creates
    CodeFeatures based on basic block and function CAPA matches

    Args:
        doc (rd.ResultDocument): CAPA result docs
        extractor: CAPA analysis extractor object
    Returns:
        dict: dictionary with a key of the filemd5 mapped to a list of CodeFeatures
    """
    # Grab the vivisect workspace object
    try:
        file_vw = extractor.vw
    except:
        print("No extractor workspace")
        file_vw = None
        raise

    # Get the filemd5 
    filemd5 = doc.meta.sample.md5


    cb_matches = collections.defaultdict(set)
    func_matches = collections.defaultdict(set)

    for rule in rutils.capability_rules(doc):
        if rule.meta.scope == capa.rules.FUNCTION_SCOPE:
            for addr, _ in rule.matches:
                func_matches[addr.value].add(rule.meta.name)
        elif rule.meta.scope == capa.rules.BASIC_BLOCK_SCOPE:
            for addr, _ in rule.matches:
                cb_matches[addr.value].add(rule.meta.name)
        else:
            # file scope
            pass

    code_features = []

    for addr, rules in cb_matches.items():
        comment = f"Basic Block at 0x{addr:08x}@{filemd5} with {len(rules)} features:\n"
        for rule_name in sorted(rules):
            comment += f"  - {rule_name}\n"
        comment += get_comment_for_cb(file_vw, addr)

        bytez = get_cb_bytes(file_vw, addr)
        sig = genSigAndMask(addr, bytez, doc.meta.analysis.arch)
        code_features.append(CodeFeature(sig,comment,bytez,filemd5))

    for addr, rules in func_matches.items():
        comment = f"function at 0x{addr:08x}@{filemd5} with {len(rules)} features:\n"
        for rule_name in sorted(rules):
            comment += f"  - {rule_name}\n"
        comment += get_comment_for_func(file_vw, addr)

        bytez = get_function_bytes(file_vw, addr)
        sig = genSigAndMask(addr, bytez, doc.meta.analysis.arch)
        code_features.append(CodeFeature(sig,comment,bytez,filemd5))


    if len(code_features) == 0:
        logger.warning("No code features found for %s", filemd5)
    return {filemd5: code_features}

def get_code_features_for_dotnet_doc(doc: rd.ResultDocument, extractor):
    """Returns a dictionary mapping a filemd5 to a list of CodeFeatures 
    
    This function operates on .NET PE files and creates
    CodeFeatures based on .NET method CAPA matches

    Args:
        doc (rd.ResultDocument): CAPA result docs
        extractor: CAPA analysis extractor object
    Returns:
        dict: dictionary with a key of the filemd5 mapped to a list of CodeFeatures
    """
    # Grab the vivisect workspace object
    try:
        dnpe = extractor.pe
    except:
        print("No dnpe file found")
        raise

    filemd5 = doc.meta.sample.md5

    func_matches = collections.defaultdict(set)

    for rule in rutils.capability_rules(doc):
        if rule.meta.scope == capa.rules.FUNCTION_SCOPE:
            for addr, _ in rule.matches:
                func_matches[addr.value].add(rule.meta.name)
        else:
            # file scope
            pass

    # Funcs is the cache of functions we need to reference to get 
    # the underlying dnfile object
    funcs = list(extractor.get_functions())

    # Return list of CodeFeature objects
    code_features = []

    logger.debug(f"Building CodeFeatures for {len(func_matches.keys())} functions in {filemd5}")
    for addr, rules in func_matches.items():
        func_name = extractor.token_cache.get_method(addr)
        comment = f"function {func_name} 0x{addr:08x}@{filemd5} with {len(rules)} features:\n"
        for rule_name in sorted(rules):
            comment += f"  - {rule_name}\n"

        # Get the CILMethodBody object by working with the function
        # collection we grabbed earlier
        f = [x for x in funcs if x.address.real == addr][0]
        func_comment, sig, bytez = get_sig_and_mask_for_dotnet_func(dnpe, f.inner)
        comment += func_comment

        code_features.append(CodeFeature(sig,comment,bytez,filemd5))


    if len(code_features) == 0:
        logger.warning("No code features found for %s", filemd5)
    return {filemd5: code_features}

######## CAPA Entrypoints ########

def run_capa_and_get_features(args):
    """Main CAPA analysis entrypoint
    
    This function kicks off CAPA analysis and builds CodeFeatures that 
    will be used to build yara rules in the main thread.

    Args:
        args: Tuple containing the following 
            - rules: CAPA rules loaded from a repo
            - sig_paths: Path to signatures used for library identification
            - format: Format for processing (dotnet or auto are the expected values)
            - os_: Operating system specified
            - path: Path to file for analyis
    Returns:
        dict: dictionary with the following keys
            - path: Path to file that was analyzed
            - status: Status of analysis (error or ok)
            - error (Optional): Details of errors that occured
            - ok (Optional): Dictionary mapping the filemd5 to a list of CodeFeatures
    """

    rules, sig_paths, format, os_, path = args
    should_save_workspace = os.environ.get("CAPA_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)

    try:
        extractor = capa.main.get_extractor(
            path, format, os_, capa.main.BACKEND_VIV, sig_paths, should_save_workspace, disable_progress=True
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
            "error": f"input file does not appear to be a PE file: {path}",
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
            "error": f"unexpected error: {e}",
        }

    meta = capa.main.collect_metadata([], path, format, os_, [], extractor)
    logger.info(f"Collecting capabilities for {path}")
    capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)

    meta.analysis.feature_counts = counts["feature_counts"]
    meta.analysis.library_functions = counts["library_functions"]
    meta.analysis.layout = capa.main.compute_layout(rules, extractor, capabilities)

    if capa.main.has_file_limitation(rules, capabilities):
        # bail if capa encountered file limitation e.g. a packed binary
        # do show the output in verbose mode, though.
            return {
                "path": path,
                "status": "error",
                "error": f"Encountered file limitation",
            }

    try:
        doc = rd.ResultDocument.from_capa(meta, rules, capabilities)
        logger.info(f"Building code features for {path}")
        if type(extractor) == DnfileFeatureExtractor:
            # Handle .NET files
            features = get_code_features_for_dotnet_doc(doc, extractor)
        else:
            # Handle other files
            features = get_code_features_for_capa_doc(doc, extractor)
    except Exception as e:
        return {
            "path": path,
            "status": "error",
            "error": f"unexpected error: {e}",
        }
    return {"path": path, "status": "ok", "ok": features}


def multi_process_capa(argv=None):
    """CAPA argument handler and multiprocessing manager
    
    This function processes CLI arguments and kicks of capa analysis
    and extacts CodeFeatures into a dictionary that maps filemd5s
    to a list of CodeFeatures that will be used to build yara rules

    Args:
        argv: 
    Returns:
        dict: dictionary mapping filemd5's processed to a list of CodeFeatures
    """
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Build YARA rules for CAPA matches")
    capa.main.install_common_args(parser, wanted={"rules", "signatures", "format", "os"})
    parser.add_argument("input", type=str, nargs="+", help="Path to directory or files to analyze")
    parser.add_argument(
        "-n", "--parallelism", type=int, default=multiprocessing.cpu_count(), help="parallelism factor"
    )
    parser.add_argument("--no-mp", action="store_true", help="disable subprocesses")
    args = parser.parse_args(args=argv)
    capa.main.handle_common_args(args)

    try:
        rules = capa.main.get_rules(args.rules)
        logger.info("successfully loaded %s rules", len(rules))
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        return -1

    try:
        sig_paths = capa.main.get_signatures(args.signatures)
    except IOError as e:
        logger.error("%s", str(e))
        return -1

    samples = []
    for p in args.input:
        path = Path(p)
        if not path.exists():
            raise ValueError(f"Invalid path {p}")
        if path.is_dir():
            samples.extend([x for x in path.rglob("*")])
        elif path.is_file():
            samples.append(path)
    logger.info("Starting to process %s files", len(samples))
            

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

    results = {}
    for result in mapper(
        run_capa_and_get_features,
        [(rules, sig_paths, args.format, OS_AUTO, sample) for sample in samples],
        parallelism=args.parallelism,
    ):
        if result["status"] == "error":
            logger.warning(f'{result["path"]}: {result["error"]}')
        elif result["status"] == "ok":
            results.update(result["ok"])
        else:
            raise ValueError(f"unexpected status: {result['status']}")

    logger.info(f"Done processing {len(samples)} samples")

    return results

######## YARA related functions ########

CODE_FEATURES_REFERENCED = []

def build_rule_from_combo(combo_dict: dict, **kwargs):
    """Build a yaramod yara rule using a combination dictionary
    
    Args:
        combo_dict: Dictionary of features that all matched on a group of files
    Returns:
        yaramod.Rule: yaramod representation of a yara rule generated for the file combination
    """

    # we're going to use this to create unique code features to insert the comment strings
    global CODE_FEATURES_REFERENCED


    # Build metadata for the rule
    rule_name = "super_rule_" + "_".join([x[:5] for x in sorted(combo_dict["files"])])
    metadict = dict(
        author=kwargs.get("author", "CAPA Matches"),
        date_created=kwargs.get("date_created", date.today().isoformat()),
        date_modified=kwargs.get("date_modified", date.today().isoformat()),
        description=kwargs.get("description", ""),
    )

    rule = yaramod.YaraRuleBuilder().with_name(rule_name)
    for metakey, metavalue in metadict.items():
        if metavalue is not None:
            rule = rule.with_string_meta(metakey, metavalue)

    # Add in hash meta
    rule = rule.with_name(rule_name)
    for hsh in combo_dict["files"]:
        rule = rule.with_string_meta("md5", hsh)

    conditions = [yaramod.of(yaramod.all(), yaramod.them())]
    for codefeature in combo_dict['features']:
        idx = len(CODE_FEATURES_REFERENCED)
        hexstr = yaramod.YaraHexStringBuilder()
        for byte in codefeature.sig.split(" "):
            if byte == "??":
                hexstr = hexstr.add(yaramod.wildcard())
            elif byte == '':
                continue
            else:
                hexstr = hexstr.add(yaramod.YaraHexStringBuilder(int(byte, 16)))
        rule = rule.with_hex_string(f"$c{idx}", hexstr.get())
        CODE_FEATURES_REFERENCED.append(codefeature)
        

    if len(conditions) == 1:
        # No fancy expression needed
        rule = rule.with_condition(conditions[0].get())
    else:
        rule = rule.with_condition(
            yaramod.conjunction(conditions, linebreaks=True).get()
        )
    return rule.get()

TAB_CHAR = " "*4

def replace_tabs_with_spaces(yara_text):
    """Replacing tabs with spaces in yara rule

    Args:
        yara_text: string of full yara rules text
    Returns:
        str: formatted yara rules text
    """
    return yara_text.replace("\t", TAB_CHAR)

def add_comments_to_yara_file(yara_text):
    """Add comments to yara file text

    Args:
        yara_text: string of full yara rules text
    Returns:
        str: formatted yara rules text
    """

    for idx, feature in enumerate(CODE_FEATURES_REFERENCED):
        # Find the str in yara_text
        # replace it with the comment
        search_str = f"$c{idx} ="
        comment_str = "/*\n"
        comment_str += ("\n"+2*TAB_CHAR).join(feature.comment.split("\n"))
        comment_str += "*/\n" + 2*TAB_CHAR + search_str
        yara_text = yara_text.replace(search_str, comment_str)
    return yara_text

def build_yara_ruleset(files_dict, **kwargs):
    """Build a YARA ruleset string based on CodeFeatures

    Args:
        files_dict: dictionary mapping filemd5s to list of CodeFeatures
    Returns:
        str: YARA ruleset
    """

    # First we'll build a dict with a key based on the masked bytes from each
    # Code feature
    similarity_dict = {}
    for filemd5, features in files_dict.items():
        for value in features:
            if value.sig not in similarity_dict:
                similarity_dict[value.sig] = {
                        "values":[value],
                        "files":set([value.filemd5])
                }
            else:
                similarity_dict[value.sig]['values'].append(value)
                similarity_dict[value.sig]['files'].add(value.filemd5)

    # Next we build out a combodict and track which files have which combos of features
    file_combinations = {}
    for feature, result_dict in similarity_dict.items():
        sample_combo_key = ":".join(list(sorted(result_dict["files"])))
        if sample_combo_key not in file_combinations:
            file_combinations[sample_combo_key] = dict()
            file_combinations[sample_combo_key]["files"] = sorted(
                result_dict["files"]
            )
            file_combinations[sample_combo_key]["feature_count"] = 0
            file_combinations[sample_combo_key]["features"] = []

        # Use the full code feature from the alphabetical match
        chosen_code_version = sorted(result_dict['values'], key=lambda x: x.filemd5)[0]
        file_combinations[sample_combo_key]["features"].append(
            chosen_code_version
        )
        file_combinations[sample_combo_key]["feature_count"] += 1

    # Create a list of combo keys and sort them so we get deterministic output
    combo_keys = sorted(file_combinations.keys(), key=lambda x: (len(x), x))

    # Build the YARA rule set based on the grouping
    yara_file = yaramod.YaraFileBuilder()
    observed_files = []

    for key in combo_keys:
        combo_dict = file_combinations[key]
        rule = build_rule_from_combo(
            combo_dict, **kwargs
        )
        if rule is not None:
            observed_files.extend(combo_dict["files"])
            yara_file = yara_file.with_rule(rule)

    # Turn the yaramod "file" into a string
    yara_text = yara_file.get().text_formatted

    yara_text = replace_tabs_with_spaces(yara_text)

    # Add our comments to the file
    yara_text = add_comments_to_yara_file(yara_text)

    return yara_text



def main(argv=None):
    all_features = multi_process_capa(argv)
    print(build_yara_ruleset(all_features))

if __name__ == "__main__":
    sys.exit(main())
