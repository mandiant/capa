import re
import socket
import ipaddress
from typing import List, Iterator, Generator

from capa.exceptions import UnsupportedFormatError
from capa.capabilities import domain_ip_helpers
from capa.features.common import FORMAT_PE, FORMAT_ELF, FORMAT_DOTNET
from capa.features.address import Address
from capa.features.extractors import viv, binja, pefile, elffile, dotnetfile
from capa.render.result_document import ResultDocument
from capa.features.extractors.base_extractor import FunctionHandle

# these constants are also defined in capa.main
# defined here to avoid a circular import
BACKEND_VIV = "vivisect"
BACKEND_DOTNET = "dotnet"
BACKEND_BINJA = "binja"
BACKEND_PEFILE = "pefile"


def invalid_domain(string: str) -> bool:
    """
    supports the domain extractor functions '*_extract_domain_names'
    
    causes the extractor function to ignore domain-like strings
    that have invalid top-level domains (e.g., ".exe", ".dll", etc.)
    """
    invalid_list = ["win", "exe", "dll", "med"]  # add more to this list

    for domain in invalid_list:
        if domain == string:
            return False
        
    return True


def default_extract_domain_names(doc: ResultDocument) -> Iterator[str]:
    """yield web domain regex matches from list of strings"""
    ##############
    # ideally we probably should move the 'DOMAIN_PATTERN' out of this function's scope but
    # then we would have to pass it as a variable to this function and that would make
    # rendering in the main function a lot more messy

    # See this Stackoverflow post that discusses the parts of this regex (http://stackoverflow.com/a/7933253/433790)
    DOMAIN_PATTERN = r"^(?!.{256})(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63}|xn--[a-z0-9]{1,59})$"
    ##############
    for string in domain_ip_helpers.get_file_strings(doc):
        # re.search only accepts 'str' on byte-like objects so
        # we convert the type of 'string'
        string = string.value
        if re.search(DOMAIN_PATTERN, string):
            if not invalid_domain(string):
                yield string

        elif is_ip_addr(string):
            yield string


def verbose_extract_domain_and_ip(doc: ResultDocument) -> Generator[str, None, None]:
    """yield web domain and ip address regex matches from list of strings"""
    ##############
    # ideally we probably should move the 'DOMAIN_PATTERN' out of this function's scope but
    # then we would have to pass it as a variable to this function and that would make
    # rendering in the main function a lot more messy

    # See this Stackoverflow post that discusses the parts of this regex (http://stackoverflow.com/a/7933253/433790)
    DOMAIN_PATTERN = r"^(?!.{256})(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63}|xn--[a-z0-9]{1,59})$"
    ##############
    domain_counts = {}
    ip_counts = {}

    for string in domain_ip_helpers.get_file_strings(doc):
        string = string.value
        if re.search(DOMAIN_PATTERN, string):
            if not invalid_domain(string):
                try:
                    domain_counts[string] += 1
                except KeyError:
                    domain_counts[string] = 1

        elif is_ip_addr(string):
            try:
                ip_counts[string] += 1
            except KeyError:
                ip_counts[string] = 1

    # TODO (aaronatp): when capa drops support for python 3.8,
    # rewrite the following with '|' instead of lists
    domain_and_ip_counts = dict(list(domain_counts.items()) + list(ip_counts.items()))

    for string, total_occurrances in domain_and_ip_counts.items():
        if is_ip_addr(string):
            yield formatted_ip_verbose(doc, string, total_occurrances)
        else:
            yield formatted_domain_verbose(doc, string, total_occurrances)


def is_ip_addr(string: str) -> bool:
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False
    

def formatted_ip_verbose(doc: ResultDocument, string: str, total_occurrances: int) -> str:
    """same as 'formatted_domain_verbose' but without 'ip_address_statement'"""
    return (
        f"{string}\n"
        + f"    |---- {networking_functions_statement(doc, string)}\n"
        + f"    |---- {total_occurrances} occurrances\n"
    )


def formatted_domain_verbose(doc: ResultDocument, string: str, total_occurrances: int) -> str:
    """
    example output:

    capa -v suspicious.exe
    -----------------------
    google.com
        |---- IP address:
        |        |----192.0.0.1
        |----Functions used to communicate with google.com:
        |        |----InternetConnectA
        |        |----HttpOpenRequestA
        |        |----FtpGetFileA
        |----3 occurrances
    """
    return (
        f"{string}\n"
        + f"    |---- {ip_address_statement(string)}\n"
        + f"    |---- {networking_functions_statement(doc, string)}\n"
        + f"    |---- {total_occurrances} occurrances\n"
    )


def ip_address_statement(string: str) -> str:
    ip_address = socket.gethostbyname(string)
    # we don't need to account for multiple IP addresses
    # for a single domain, do we?
    return "IP address:\n".join(f"|        |----{ip_address}")


def networking_functions_statement(doc: ResultDocument, string: str) -> str:
    """prints functions used to communicate with domain/ip"""
    api_functions = get_domain_or_ip_caller_functions(doc, string)
    if len(api_functions) == 1:
        return f"Function used to communicate with {string}\n|    |----{str(api_functions)}"
    else:
        statement = f"Functions used to communicate with {string}:\n"
        for function in api_functions:
            statement.join(f"|    |----{function}\n")

        return statement


def get_domain_or_ip_caller_functions(doc: ResultDocument, domain_or_ip: str) -> List[str]:
    """
    for every occurrance of 'domain' in the extractor, we see which function (e.g., Windows API)
    uses it

    returns:
      List[str]: list of functions that are used in communication with a domain
    """
    api_functions = []

    try:
        for caller_func in yielded_caller_func_static(doc, domain_or_ip, 0):
            if caller_func is None:
                continue
            api_functions.append(caller_func)
    
    except NotImplementedError:
        for caller_func in yielded_caller_func_dynamic(doc, domain_or_ip, 0):
            if caller_func is None:
                continue
            api_functions.append(caller_func)

    return api_functions


def yielded_caller_func_static(
        doc: ResultDocument, target_string: str, start_position: Address
):
    """
    analogous to 'yielded_caller_func_dynamic' but tailored to StaticFeatureExtractor (instead of DynamicFeatureExtractor)
    """
    extractor = domain_ip_helpers.get_extractor_from_doc(doc)
    for func in extractor.get_functions():
        for feature, addr in func.extract_function_features():
            if addr < start_position:
                continue

            if feature.value == target_string:
                function_name = get_function_name(doc, func)
                yield function_name  # yield the function operating on the web domain/IP address

                # add any other network protocols here that Windows APIs implements
                if any(["HTTP", "HTTPS", "FTP", "UDP"]) in function_name.upper():
                    continue

                # if the yielded function is not a network protocol function
                # (e.g., "Https," "Ftp," etc.), we ask if the yielded function
                # is passed to other functions that are network protocol functions
                else:
                    try:
                        # when we do 'start_position = addr', we ignore 'function_name' when it occurs
                        # before 'feature' (i.e., before 'addr')
                        yield from yielded_caller_func_static(doc, function_name, addr)

                    except StopIteration:
                        yield None


def get_function_name(doc: ResultDocument, func: FunctionHandle) -> str:
    """
    helper function for 'yielded_caller_func_static,' not used in yielded_caller_func_dynamic

    returns:
      function_name (str): function's name (e.g., "HttpOpenRequestA")
    """
    file = domain_ip_helpers.get_file_path(doc)
    format_ = domain_ip_helpers.get_auto_format(file)
    if format_ == BACKEND_PEFILE or format_ == FORMAT_PE:
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
        raise UnsupportedFormatError(
          "Unexpected format! Please open an issue on GitHub (https://github.com/mandiant/capa/issues)"
        )

    return function_name


def yielded_caller_func_dynamic(
        doc: ResultDocument, target_string: str, start_position: Address
) -> Generator[str, None, None]:
    """
    we look into an extractor to see what APIs operate on a web domain

    examines calling context of web domains and yields any functions that
    operate on them. next, recursively examines calling contexts of yielded
    functions and yields additional network management functions
    (e.g., "HttpOpenRequestA", "FtpGetFileA", etc.).

    """
    extractor = domain_ip_helpers.get_extractor_from_doc(doc)
    for ph in extractor.get_processes():
        for th in extractor.get_threads(ph):
            for ch in extractor.get_calls(ph, th):
                for feature, addr in extractor.extract_call_features(ph, th, ch):
                    # if we are in the 'yield from' statement, this ignores
                    # appearances of api_name that occur before web domain
                    if addr < start_position:
                        continue

                    if feature.value == target_string:
                        api_name = extractor.extract_call_features(ph, th, ch)[0][0]
                        yield api_name  # yield the function operating on the web domain

                        if any(["HTTP", "HTTPS", "FTP", "UDP"]) in api_name.upper():
                            continue

                        # if the yielded function is not a network protocol function
                        # (e.g., "Https," "Ftp," etc.), we ask if the yielded function
                        # is passed to other functions that are network protocol functions
                        else:
                            try:
                                # when we do 'start_position = addr', we ignore 'function_name' when it occurs
                                # before 'feature' (i.e., before 'addr')
                                yield from yielded_caller_func_dynamic(doc, api_name, addr)

                            except StopIteration:
                                yield None