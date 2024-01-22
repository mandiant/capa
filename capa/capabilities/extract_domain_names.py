import re
import ipaddress
import socket
from typing import List, Iterator, Generator
from pathlib import Path

from capa import ida, ghidra
from capa.main import BACKEND_VIV, BACKEND_BINJA, BACKEND_DOTNET, BACKEND_PEFILE
from capa.helpers import is_runtime_ida, get_auto_format, is_runtime_ghidra
from capa.exceptions import UnsupportedFormatError
from capa.features.common import FORMAT_PE, FORMAT_ELF, FORMAT_CAPE, FORMAT_DOTNET
from capa.features.address import Address
from capa.features.extractors import viv, cape, binja, dnfile, pefile, elffile, dotnetfile
from capa.render.result_document import ResultDocument
from capa.features.extractors.base_extractor import (
    FunctionHandle,
    FeatureExtractor,
    StaticFeatureExtractor,
    DynamicFeatureExtractor,
)


def get_file_strings(doc: ResultDocument, extractor: FeatureExtractor) -> Iterator[str]:
    """extract strings from any given extractor"""
    if is_runtime_ida():
        strings, _ = ida.helpers.extract_file_strings()
    elif is_runtime_ghidra():
        strings, _ = ghidra.helpers.extract_file_strings()
    else:
        file = get_file_path(doc)
        format_ = get_auto_format(file)
        buf = file.read_bytes()
        if format_ == FORMAT_ELF:
            strings, _ = elffile.extract_file_strings(buf)
        elif format_ == BACKEND_VIV:
            strings, _ = viv.file.extract_file_strings(buf)
        elif format_ == BACKEND_PEFILE:
            strings, _ = pefile.extract_file_strings(buf)
        else:
            if format_ == BACKEND_BINJA:
                strings, _ = binja.file.extract_file_strings(extractor.bv)
            elif format_ == BACKEND_DOTNET:
                strings, _ = dnfile.file.extract_file_strings(extractor.pe)
            elif format_ == FORMAT_CAPE:
                strings, _ = cape.file.extract_file_strings(extractor.report)
            else:
                raise UnsupportedFormatError()

    return strings


def get_file_path(doc: ResultDocument) -> Path:
    return doc.meta.sample.path


def default_extract_domain_names(file: Path) -> Iterator[str]:
    """yield web domain regex matches from list of strings"""
    ##############
    # ideally we probably should move the 'DOMAIN_PATTERN' out of this function's scope but
    # then we would have to pass it as a variable to this function and that would make
    # rendering in the main function a lot more messy

    # See this Stackoverflow post that discusses the parts of this regex (http://stackoverflow.com/a/7933253/433790)
    DOMAIN_PATTERN = r"^(?!.{256})(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63}|xn--[a-z0-9]{1,59})$"
    ##############
    for string in get_file_strings(file):
        if re.search(DOMAIN_PATTERN, string):
            yield string

        elif is_ip_addr(string):
            yield string


def verbose_extract_domains_and_ips(extractor: FeatureExtractor, doc: ResultDocument) -> Generator[str, None, None]:
    """yield web domain and ip address regex matches from list of strings"""
    DOMAIN_PATTERN = r"^(?!.{256})(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63}|xn--[a-z0-9]{1,59})$"
    domain_counts = {}
    ip_counts = {}

    file = get_file_path(doc)
    for string in get_file_strings(extractor, file):
        if re.search(DOMAIN_PATTERN, string):
            try:
                domain_counts[string] += 1
            except KeyError:
                domain_counts[string] = 1

        elif is_ip_addr(string):
            try:
                ip_counts[string] += 1
            except KeyError:
                ip_counts[string] = 1

    domain_and_ip_counts = dict(domain_counts.items() + ip_counts.items())

    for string, total_occurrances in domain_and_ip_counts:
        if is_ip_addr(string) == True:
            yield formatted_ip_verbose(extractor, file, string, total_occurrances)
        else:
            yield formatted_domain_verbose(extractor, file, string, total_occurrances)
        

def is_ip_addr(string: str) -> bool:
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False
    

def formatted_ip_verbose(extractor: FeatureExtractor, file: Path, string: str, total_occurrances: int) -> str:
    """same as 'formatted_domain_verbose' but without 'ip_address_statement'"""
    return (
        f"{string}\n"
        + f"    |---- {networking_functions_statement(extractor, file, string)}\n"
        + f"    |---- {total_occurrances} occurrances\n"
    )


def formatted_domain_verbose(extractor: FeatureExtractor, file: Path, string: str, total_occurrances: int) -> str:
    """
    example output:

    capa -v suspicious.exe
    -----------------------
    google.com
        |---- IP address:
        |        |----192.0.0.1
        |        |----192.0.0.2
        |----Functions used to communicate with google.com:
        |        |----InternetConnectA
        |        |----HttpOpenRequestA
        |        |----FtpGetFileA
        |----3 occurrances
    """
    return (
        f"{string}\n"
        + f"    |---- {ip_address_statement(string)}\n"
        + f"    |---- {networking_functions_statement(extractor, file, string)}\n"
        + f"    |---- {total_occurrances} occurrances\n"
    )


def ip_address_statement(string: str) -> str:
    ip_address = socket.gethostbyname(string)
    # we don't need to account for multiple IP addresses
    # for a single domain, do we?
    return "IP address:\n".join(f"|        |----{ip_address}")


def networking_functions_statement(extractor: FeatureExtractor, file: Path, string: str) -> str:
    """ """
    api_functions = get_domain_functions(extractor, file, string)
    if len(api_functions) == 1:
        return f"Function used to communicate with {string}: ".join(f"{function}\n" for function in api_functions)
    else:
        statement = f"Functions used to communicate with {string}:\n"
        for function in api_functions:
            statement.join(f"|    |----{function}\n")

        return statement


# make this function a descriptor and pass either 'domain' or 'ip address' to its third parameter
def get_domain_functions(extractor: FeatureExtractor, file: Path, domain_or_ip: str) -> List[str]:
    """
    for every occurrance of 'domain' in the extractor, we see which function (e.g., Windows API)
    uses it

    returns:
      List[str]: list of functions that are used in communication with a domain
    """
    api_functions = []

    # if we don't '+ 1' below, we may miss network management functions 
    # in the last loop through 'yielded_caller_func_static/dynamic'
    occurrances = occurrances_in_file(file, domain_or_ip) + 1

    while occurrances > 0:
        try:
            caller_func = yielded_caller_func_static(extractor, domain_or_ip, file, 0)
        except NotImplementedError:  # if StaticExtractor methods are not implemented, we call DynamicExtractor yielder
            caller_func = yielded_caller_func_dynamic(extractor, domain_or_ip, file, 0)
            
        if caller_func == None:
            continue
            
        api_functions.append(caller_func)
        occurrances = occurrances - 1

    return api_functions


def occurrances_in_file(file, domain) -> int:
    """determines number of times that 'domain' occurs in a file"""
    counter = 0
    for string in get_file_strings(file):
        if string == domain:
            counter += 1

    return counter


def yielded_caller_func_static(
    extractor: StaticFeatureExtractor, target_string: str, file: Path, start_position: Address
):
    """
    analogous to 'yielded_caller_func_dynamic' but tailored to StaticFeatureExtractor (instead of DynamicFeatureExtractor)
    """
    for func in extractor.get_functions():
        for feature, addr in func.extract_function_features():
            if addr < start_position:
                continue

            if feature.value == target_string:
                # yield the function operating on the web domain
                function_name = get_function_name(func, file)
                yield function_name

                # add any other network protocols here that Windows API implements
                if any(["Http", "Https", "Ftp"]) in function_name:
                    continue

                # if the yielded function is not a network protocol function
                # (e.g., "Https," "Ftp," etc.), we ask if the yielded function 
                # is passed to other functions that are network protocol functions
                else:
                    try:
                        # when we do 'start_position = addr', we ignore 'function_name' when it occurs
                        # before 'feature' (i.e., before 'addr')
                        yield from yielded_caller_func_dynamic(extractor, function_name, file, addr)
                    
                    except StopIteration:
                        yield None



def get_function_name(func: FunctionHandle, file: Path) -> str:
    """    
    helper function for 'yielded_caller_func_static,' not used in yielded_caller_func_dynamic

    args:
      func (FunctionHandle): function handle
      file (Path): path to input file

    returns:
      function_name (str): function's name (e.g., "HttpOpenRequestA")
    """
    format_ = get_auto_format(file)
    if format_ == FORMAT_PE:
        function_name = pefile.get_function_name(func.address)
    elif format_ == BACKEND_PEFILE:  # is this the same as 'FORMAT_PE'? - they reference different strings
        function_name = pefile.get_function_name(func.address)
    elif format_ == FORMAT_DOTNET:
        function_name = dotnetfile.get_function_name(func.address)
    elif format_ == FORMAT_ELF:
        function_name = elffile.get_function_name(func.address)
    elif format_ == BACKEND_VIV:
        function_name = viv.extractor.get_function_name(func.address)
    elif format_ == BACKEND_BINJA:
        function_name = binja.file.extract_function_name(func)
    else:
        raise UnsupportedFormatError("Unexpected format! Please open an issue on GitHub")

    return function_name


def yielded_caller_func_dynamic(
    extractor: DynamicFeatureExtractor, target_string: str, file: Path, start_position: Address
) -> Generator[str]:
    """
    we look into an extractor to see what APIs operate on a web domain

    examines calling context of web domains and yields any functions that 
    operate on them. next, recursively examines calling contexts of yielded
    functions and yields additional network management functions
    (e.g., "HttpOpenRequestA", "FtpGetFileA", etc.).

    """
    for ph in extractor.get_processes():
        for th in extractor.get_threads(ph):
            for ch in extractor.get_calls(ph, th):
                for feature, addr in extractor.extract_call_features(ph, th, ch):
                    # if we are in the 'yield from' statement, this ignores
                    # appearances of api_name that occur before web domain
                    if addr < start_position:
                        continue

                    if feature.value == target_string:
                        # yield the function operating on the web domain
                        api_name = extractor.extract_call_features(ph, th, ch)[0][0]
                        yield api_name
                        
                        if any(["Http", "Https", "Ftp"]) in api_name:
                            continue

                        # if the yielded function is not a network protocol function
                        # (e.g., "Https," "Ftp," etc.), we ask if the yielded function 
                        # is passed to other functions that are network protocol functions
                        else:
                            try:
                                # when we do 'start_position = addr', we ignore 'function_name' when it occurs
                                # before 'feature' (i.e., before 'addr')
                                yield from yielded_caller_func_dynamic(extractor, api_name, file, addr)
                            
                            except StopIteration:
                                yield None