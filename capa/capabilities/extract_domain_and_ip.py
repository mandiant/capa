import re
import socket
import logging
import ipaddress
from typing import Dict, List, Tuple, Generator

from capa.features.insn import API, Feature
from capa.features.common import Address
from capa.render.result_document import ResultDocument
from capa.capabilities.domain_ip_helpers import get_extractor_from_doc
from capa.features.extractors.base_extractor import StaticFeatureExtractor, DynamicFeatureExtractor

logger = logging.getLogger(__name__)


def is_valid_domain(string: str) -> bool:
    """
    uses a regex to check whether a string could be a valid web domain

    ignores domain-like strings that have invalid top-level domains (e.g., ".exe", ".dll", etc.)
    """
    ##############
    # ideally 'DOMAIN_PATTERN' should probably be moved out of this function's scope but
    # then it would have to be passed as a variable to this function and that would make
    # rendering in the main function a lot more messy

    # See this Stackoverflow post that discusses the parts of this regex (http://stackoverflow.com/a/7933253/433790)
    # The following regex is based on the linked-to regex but significantly modified/updated
    DOMAIN_PATTERN = (
        r"^(?!.{256})(?:[a-z](?:[a-z0-9-']{0,61})?(?<![0-9'])\.)+(?:[a-z](?:[a-z0-9']{0,62})?|xn--[a-z0-9]{1,59})$"
    )
    ##############

    if re.search(DOMAIN_PATTERN, string):
        invalid_list = [
            "win",
            "exe",
            "dll",
            "med",
            "inf",
            "ini",
            "dat",
            "db",
            "log",
            "bak",
            "lnk",
            "bin",
            "scr",
            "exf",
        ]  # add more to this list

        top_level_domain = string.split(".")[-1]
        for invalid in invalid_list:
            if top_level_domain == invalid:
                return False

        return True

    return False


def is_ip_addr(string: str) -> bool:
    """checks if a string is a valid IP address"""
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False


def generate_insns_from_doc(doc: ResultDocument) -> Generator[Tuple[Feature, Address], None, None]:
    """
    checks whether extractor's type is StaticFeatureExtractor or DynamicFeatureExtractor

    if the type is StaticFeatureExtractor, this function yields assembly instruction's and addresses

    StaticFeatureExtractor example:
      mnemonic(xor), absolute(0x401015)
      mnemonic(lea), absolute(0x401017)
      mnemonic(mov), absolute(0x40101d)
      mnemonic(push), absolute(0x401023)
      number(0xF), absolute(0x401023)
      ...
      string(70.62.232.98), absolute(0x4010b6)
      mnemonic(call), absolute(0x4010bb)
      ...
      api(strncpy), absolute(0x4010f3)

    if the type is DynamicFeatureExtractor, this function yields "call features" which are analogous
    to assembly instructions but extracted from sandbox traces as opposed to files directly

    args:
      doc (ResultDocument): a ResultDocument object

    yields:
      feature, addr (Tuple[Feature, Address]):
          'feature' is either an assembly instruction or a call feature; and,
          'addr' is a memory address.
    """
    extractor = get_extractor_from_doc(doc)
    if isinstance(extractor, StaticFeatureExtractor):
        for func in extractor.get_functions():
            for block in extractor.get_basic_blocks(func):
                for insn in extractor.get_instructions(func, block):
                    for feature, addr in extractor.extract_insn_features(func, block, insn):
                        yield feature, addr

    elif isinstance(extractor, DynamicFeatureExtractor):
        for proc in extractor.get_processes():
            for thread in extractor.get_threads(proc):
                for call in extractor.get_calls(proc, thread):
                    for feature, addr in extractor.extract_call_features(proc, thread, call):
                        yield feature, addr


def default_extract_domain_names(doc: ResultDocument) -> Generator[str, None, None]:
    """
    loops through assembly instructions retrieved from a ResultDocument object

    this 'default' function is meant to merely tell users what domains/IPs are in a file,
    not to show users how many time each occur, so we consciously do not yield duplicates

    yields:
      potential web domain names and IP addresses
    """
    duplicates = set()
    for feature, _ in generate_insns_from_doc(doc):
        string = str(feature.value)
        if string in duplicates:
            continue

        if is_valid_domain(string):
            duplicates.add(string)
            yield string

        elif is_ip_addr(string):
            duplicates.add(string)
            yield string


def verbose_extract_domain_and_ip(doc: ResultDocument) -> Generator[str, None, None]:
    """calls verbose statement formatter for IP addresses and web domains"""
    for string, count in get_domain_ip_dict(doc).items():
        if is_ip_addr(string):
            yield formatted_ip_verbose(doc, string, count)
        else:
            yield formatted_domain_verbose(doc, string, count)


def get_domain_ip_dict(doc: ResultDocument):
    """
    returns dict of domains/IPs in a file and number of times each occur

    example:
      {'malicious-website.com/next/asxp.jpg': 3, 'other-website.net': 2}

    args:
      doc (ResultDocument): ResultDocument object which contains FeatureExtractor information, including file strings

    returns:
      domain_and_ip_counts (Dict[str, int]): dict of domain names and IP addresses and occurrances of each
        - Note: each full-path URL gets its own dict key
    """
    domain_and_ip_counts: Dict[str, int] = {}

    for feature, _ in generate_insns_from_doc(doc):
        extended_string = feature.value

        if not isinstance(extended_string, str):
            continue

        # this for loop cleans up any "http(s)://" strings
        for string in extended_string.split(" "):
            if string.startswith("http://"):
                string = string.split("http://")[-1]
                break

            elif string.startswith("https://"):
                string = string.split("https://")[-1]
                break

            else:
                # makes sure there are no weird "http(s)://" strings
                # if the assert statement runs, there's probably an issue
                assert not (any(prefix in string for prefix in ["http://", "https://"]))

        # for example, if string == "malware.com/next/virus.jpg",
        # the following "if-else" statements split at "/"
        # and checks whether "malware.com" is a web domain or IP address
        if is_valid_domain(string.split("/")[0]):
            try:
                domain_and_ip_counts[string] += 1
            except KeyError:
                domain_and_ip_counts[string] = 1

        elif is_ip_addr(string.split("/")[0]):
            try:
                domain_and_ip_counts[string] += 1
            except KeyError:
                domain_and_ip_counts[string] = 1

    return domain_and_ip_counts


def formatted_domain_verbose(doc: ResultDocument, domain: str, total_occurrances: int) -> str:
    """
    example output:

    capa -v suspicious.exe
    -----------------------
    malware.com
        |---- IP address:
        |        |----192.0.0.1
        |----Functions used to communicate with malware.com:
        |        |----InternetConnectA
        |        |----HttpOpenRequestA
        |        |----FtpGetFileA
        |----3 occurrances
    """
    return (
        f"{domain}\n"
        + f"    |---- {ip_address_statement(domain)}\n"
        + f"    |---- {networking_functions_statement(doc, domain)}\n"
        + f"    |---- {total_occurrances} occurrances"
    )


def formatted_ip_verbose(doc: ResultDocument, ip_addr: str, total_occurrances: int) -> str:
    """same as 'formatted_domain_verbose' but without 'ip_address_statement'"""
    return (
        f"{ip_addr}\n"
        + f"    |---- {networking_functions_statement(doc, ip_addr)}"
        + f"    |---- {total_occurrances} occurrances"
    )


def ip_address_statement(domain: str) -> str:
    """
    tries to identify a web domain's IP address

    this function's output is used by 'formatted_domain_verbose'

    return:
      (str): either the formatted IP address, or an error message
    """
    try:
        ip_address = socket.gethostbyname(domain)
        return "IP address:\n" + f"    |        |----{ip_address}\n"
    except socket.gaierror:
        return f"Could not get IP address for {domain.split('/')[0]}\n"


def networking_functions_statement(doc: ResultDocument, domain_or_ip: str):
    """prints the functions used to communicate with domain/ip"""
    api_functions = get_domain_or_ip_caller_functions(doc, domain_or_ip)

    if len(api_functions) == 0:
        statement = (
            f"{domain_or_ip} occurs but no functions found that use it.\n"
            "         If you think this is a mistake, please open an issue on\n"
            "         the capa GitHub page (https://github.com/mandiant/capa)\n"
        )
        return statement

    elif len(api_functions) == 1:
        statement = f"Function used to communicate with {domain_or_ip}:\n"
        for func in api_functions:
            return statement + f"    |    |----{func}\n"

    elif len(api_functions) > 1:
        statement = f"Functions used to communicate with {domain_or_ip}:\n"
        for function in api_functions:
            statement += f"    |    |----{function}\n"

        return statement

    else:
        raise LengthError("'api_functions' contains unexpected data!")


class LengthError(BaseException):
    pass


def get_domain_or_ip_caller_functions(doc: ResultDocument, domain_or_ip: str) -> List[str]:
    """
    for every occurrance of 'domain_or_ip' in the ResultDocument, we see which functions operate on it

    returns:
      List[str]: list of functions that operate on the 'domain_or_ip' string
    """
    api_functions = []
    for caller_func in yield_caller_funcs(doc, domain_or_ip):
        api_functions.append(caller_func)

    return api_functions


def yield_caller_funcs(doc: ResultDocument, domain_or_ip: str) -> Generator[str, None, None]:
    """
    We loop through asembly instructions and look for features whose values equal 'domain_or_ip'.
    When we find a feature, we look for a WinAPI instruction. WinAPI instructions are features:
    1) whose type is API; and,
    2) whose values are, heuristically, WinAPI networking functions.

    yields:
      (str): either a potential WinAPI function, or an error message
    """
    signal = 0
    for feature, _ in generate_insns_from_doc(doc):
        if isinstance(feature.value, str) and feature.value == domain_or_ip:
            signal = 1
            continue

        # we only run this block if we have found a 'target_string'
        if signal == 1:
            # skip instructions until we get to an API instruction
            if not isinstance(feature, API):
                continue

            signal = 0

            func = str(feature.value)  # redundant but helps pass mypy tests
            if "." in func:
                func = func.split(".")[-1]

            # at this point, we have found an API instruction
            # and see whether it could be a networking function
            if potential_winapi_function(func):
                yield func

            else:
                yield "Not able to identify the calling function"


def potential_winapi_function(string: str) -> bool:
    """
    some simple heuristics for checking whether a string is NOT a WinAPI function

    returns:
      True if string could be a WinAPI function
      False if string is not a WinAPI function
    """
    if string in excluded_functions():
        return False

    if any(x in string.lower() for x in quick_true()):
        return True

    if all(sep.isupper() for sep in string.split("_")) or all(
        sep.islower() for sep in string.split("_")
    ):  # WinAPI functions are usually mixed upper and lower case
        return False

    if not all(sep.isalpha() for sep in string.split("_")):  # if contains non-letters
        return False

    if too_many_consecutive_uppercase_letters(string, 7):  # maximum of 7 consecutive uppercase letters
        return False

    return True


def quick_true():
    """matched against lowercase strings"""
    return [
        "http",
        "ftp",
        "internet",
        "url",
        "connection",
        "connected",
        "online",
        "inet",
        "addr",
        "send",
        "recv",
        "sock",
        "select",
        "shutdown",
        "ntoh",
        "listen",
        "serv",
        "getpeer",
    ]


def excluded_functions():
    """
    add excluded functions here, e.g., those that can't accept an IP address/web domain as an argument
    """
    return ["Sleep"]


def too_many_consecutive_uppercase_letters(string, limit):
    """
    'HOSTENT' (probably) has the  most consecutive uppercase letters

    returns:
      True: too many consecutive uppercase letters, caller function disregards
      False: not too many consecutive uppercase, indicates this is a potential WinAPI function
    """
    counter = 0
    for i in string:
        if i.isupper():
            counter += 1
        else:  # basically reset counter if we reach a non-uppercase letter
            counter = 0

        if counter > limit:
            return True

    return False
