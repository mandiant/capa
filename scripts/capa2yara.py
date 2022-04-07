"""
Convert capa rules to YARA rules (where this is possible)

    usage: capa2yara.py [-h] [--private] [--version] [-v] [-vv] [-d] [-q] [--color {auto,always,never}] [-t TAG] rules

Capa to YARA rule converter

positional arguments:
  rules                 Path to rules

optional arguments:
  -h, --help            show this help message and exit
  --private, -p         Create private rules
  --version             show program's version number and exit
  -v, --verbose         enable verbose result document (no effect with --json)
  -vv, --vverbose       enable very verbose result document (no effect with --json)
  -d, --debug           enable debugging output on STDERR
  -q, --quiet           disable all output but errors
  --color {auto,always,never}
                        enable ANSI color codes in results, default: only during interactive session
  -t TAG, --tag TAG     filter on rule meta field values


Copyright (C) 2020, 2021 Arnim Rupp (@ruppde) and Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""

import re
import sys
import string
import logging
import argparse
import datetime
import itertools

import capa.main
import capa.rules
import capa.engine
import capa.features
import capa.features.insn
from capa.features.common import String

logger = logging.getLogger("capa2yara")

today = str(datetime.date.today())

# create unique variable names for each rule in case somebody wants to move/copy stuff around later
var_names = ["".join(letters) for letters in itertools.product(string.ascii_lowercase, repeat=3)]


# this have to be the internal names used by capa.py which are sometimes different to the ones written out in the rules, e.g. "2 or more" is "Some", count is Range
unsupported = ["characteristic", "mnemonic", "offset", "subscope", "Range"]
# TODO shorten this list, possible stuff:
# - 2 or more strings: e.g.
# -- https://github.com/mandiant/capa-rules/blob/master/collection/file-managers/gather-direct-ftp-information.yml
# -- https://github.com/mandiant/capa-rules/blob/master/collection/browser/gather-firefox-profile-information.yml
# - count(string    (1 rule: /executable/subfile/pe/contain-an-embedded-pe-file.yml)
# - count(match( could be done by creating the referenced rule a 2nd time with the condition, that it hits x times (only 1 rule: ./anti-analysis/anti-disasm/contain-anti-disasm-techniques.yml)
# - it would be technically possible to get the "basic blocks" working, but the rules contain mostly other non supported statements in there => not worth the effort.

# collect all converted rules to be able to check if we have needed sub rules for match:
converted_rules = []
count_incomplete = 0

default_tags = "CAPA "

# minimum number of rounds to do be able to convert rules which depend on referenced rules in several levels of depth
min_rounds = 5

unsupported_capa_rules = open("unsupported_capa_rules.yml", "wb")
unsupported_capa_rules_names = open("unsupported_capa_rules.txt", "wb")
unsupported_capa_rules_list = []

condition_header = """
    capa_pe_file and
"""

condition_rule = """
private rule capa_pe_file : CAPA {
    meta:
        description = "match in PE files. used by all further CAPA rules"
        author = "Arnim Rupp"
    condition:
        uint16be(0) == 0x4d5a
        or uint16be(0) == 0x558b
        or uint16be(0) == 0x5649
}
"""


def check_feature(statement, rulename):
    if statement in unsupported:
        logger.info("unsupported: " + statement + " in rule: " + rulename)
        return True
    else:
        return False


def get_rule_url(path):
    path = re.sub(r"\.\.\/", "", path)
    path = re.sub(r"capa-rules\/", "", path)
    return "https://github.com/mandiant/capa-rules/blob/master/" + path


def convert_capa_number_to_yara_bytes(number):
    if not number.startswith("0x"):
        print("TODO: fix decimal")
        sys.exit()

    number = re.sub(r"^0[xX]", "", number)
    logger.info("number ok: " + repr(number))

    # include spaces every 2 hex
    bytesv = re.sub(r"(..)", r"\1 ", number)

    # reverse order
    bytesl = bytesv.split(" ")
    bytesl.reverse()
    bytesv = " ".join(bytesl)

    # fix spaces
    bytesv = bytesv[1:] + " "

    return bytesv


def convert_rule_name(rule_name):

    # yara rule names: "Identifiers must follow the same lexical conventions of the C programming language, they can contain any alphanumeric character and the underscore character, but the first character cannot be a digit. Rule identifiers are case sensitive and cannot exceed 128 characters." so we replace any non-alpanum with _
    rule_name = re.sub(r"\W", "_", rule_name)
    rule_name = "capa_" + rule_name

    return rule_name


def convert_description(statement):
    try:
        desc = statement.description
        if desc:
            yara_desc = " // " + desc
            logger.info("using desc: " + repr(yara_desc))
            return yara_desc
    except:
        # no description
        pass

    return ""


def convert_rule(rule, rulename, cround, depth):

    depth += 1
    logger.info("recursion depth: " + str(depth))

    global var_names

    def do_statement(s_type, kid):
        yara_strings = ""
        yara_condition = ""
        if check_feature(s_type, rulename):
            return "BREAK", s_type
        elif s_type == "string":
            string = kid.value
            logger.info("doing string: " + repr(string))
            string = string.replace("\\", "\\\\")
            string = string.replace("\n", "\\n")
            string = string.replace("\t", "\\t")
            var_name = "str_" + var_names.pop(0)
            yara_strings += "\t$" + var_name + ' = "' + string + '" ascii wide' + convert_description(kid) + "\n"
            yara_condition += "\t$" + var_name + " "
        elif s_type == "api" or s_type == "import":
            # TODO: is it possible in YARA to make a difference between api & import?

            # https://github.com/mandiant/capa-rules/blob/master/doc/format.md#api
            api = kid.value
            logger.info("doing api: " + repr(api))

            #    e.g. kernel32.CreateNamedPipe => look for kernel32.dll and CreateNamedPipe
            if "." in api:
                dll, api = api.split(".")

                # usage of regex is needed and /i because string search for "CreateMutex" in imports() doesn't look for e.g. CreateMutexA
                yara_condition += "\tpe.imports(/" + dll + "/i, /" + api + "/) "

            else:
                # e.g. - api: 'CallNextHookEx'
                # (from user32.dll)

                # even looking for empty string in dll_regex doesn't work for some files (list below) with pe.imports so do just a string search
                # yara_condition += '\tpe.imports(/.{0,30}/i, /' + api + '/) '
                # 5fbbfeed28b258c42e0cfeb16718b31c, 2D3EDC218A90F03089CC01715A9F047F, 7EFF498DE13CC734262F87E6B3EF38AB, C91887D861D9BD4A5872249B641BC9F9, a70052c45e907820187c7e6bcdc7ecca, 0596C4EA5AA8DEF47F22C85D75AACA95
                var_name = "api_" + var_names.pop(0)

                # limit regex with word boundary \b but also search for appended A and W
                # TODO: better use something like /(\\x00|\\x01|\\x02|\\x03|\\x04)' + api + '(A|W)?\\x00/  ???
                yara_strings += "\t$" + var_name + " = /\\b" + api + "(A|W)?\\b/ ascii wide\n"
                yara_condition += "\t$" + var_name + " "

        elif s_type == "export":
            export = kid.value
            logger.info("doing export: " + repr(export))

            yara_condition += '\tpe.exports("' + export + '") '

        elif s_type == "section":
            # https://github.com/mandiant/capa-rules/blob/master/doc/format.md#section
            section = kid.value
            logger.info("doing section: " + repr(section))

            # e.g. - section: .rsrc
            var_name_sec = var_names.pop(0)
            # yeah, it would be better to make one loop out of multiple sections but we're in POC-land (and I guess it's not much of a performance hit, loop over short array?)
            yara_condition += (
                "\tfor any " + var_name_sec + " in pe.sections : ( " + var_name_sec + '.name == "' + section + '" ) '
            )

        elif s_type == "match":
            # https://github.com/mandiant/capa-rules/blob/master/doc/format.md#matching-prior-rule-matches-and-namespaces
            match = kid.value
            logger.info("doing match: " + repr(match))

            # e.g. - match: create process
            #      - match: host-interaction/file-system/write
            match_rule_name = convert_rule_name(match)

            if match.startswith(rulename + "/"):
                logger.info("Depending on myself = basic block: " + match)
                return "BREAK", "Depending on myself = basic block"

            if match_rule_name in converted_rules:
                yara_condition += "\t" + match_rule_name + "\n"
            else:
                # don't complain in the early rounds as there should be 3+ rounds (if all rules are converted)
                if cround > min_rounds - 2:
                    logger.info("needed sub-rule not converted (yet, maybe in next round): " + repr(match))
                    return "BREAK", "needed sub-rule not converted"
                else:
                    return "BREAK", "NOLOG"

        elif s_type == "bytes":
            bytesv = kid.get_value_str()
            logger.info("doing bytes: " + repr(bytesv))
            var_name = var_names.pop(0)

            yara_strings += "\t$" + var_name + " = { " + bytesv + " }" + convert_description(kid) + "\n"
            yara_condition += "\t$" + var_name + " "

        elif s_type == "number":
            number = kid.get_value_str()
            logger.info("doing number: " + repr(number))

            if len(number) < 10:
                logger.info("too short for byte search (until I figure out how to do it properly)" + repr(number))
                return "BREAK", "Number too short"

            # there's just one rule which contains 0xFFFFFFF but yara gives a warning if if used
            if number == "0xFFFFFFFF":
                return "BREAK", "slow byte pattern for YARA search"

            logger.info("number ok: " + repr(number))
            number = convert_capa_number_to_yara_bytes(number)
            logger.info("number ok: " + repr(number))

            var_name = "num_" + var_names.pop(0)
            yara_strings += "\t$" + var_name + " = { " + number + "}" + convert_description(kid) + "\n"
            yara_condition += "$" + var_name + " "

        elif s_type == "regex":
            regex = kid.get_value_str()
            logger.info("doing regex: " + repr(regex))

            # change capas /xxx/i to yaras /xxx/ nocase, count will be used later to decide appending 'nocase'
            regex, count = re.subn(r"/i$", "/", regex)

            # remove / in the begining and end
            regex = regex[1:-1]

            # all .* in the regexes of capa look like they should be maximum 100 chars so take 1000 to speed up rules and prevent yara warnings on poor performance
            regex = regex.replace(".*", ".{,1000}")
            # strange: capa accepts regexes with unsescaped / like - string: /com/exe4j/runtime/exe4jcontroller/i in capa-rules/compiler/exe4j/compiled-with-exe4j.yml, needs a fix for yara:
            # would assume that get_value_str() gives the raw string
            regex = re.sub(r"(?<!\\)/", r"\/", regex)

            # capa uses python regex which accepts /reg(|.exe)/ but yaras regex engine doesn't not => fix it
            # /reg(|.exe)/ => /reg(.exe)?/
            regex = re.sub(r"\(\|([^\)]+)\)", r"(\1)?", regex)

            # change begining of line to null byte, e.g. /^open => /\x00open (not word boundary because we're not looking for the begining of a word in a text but usually a function name if there's ^ in a capa rule)
            regex = re.sub(r"^\^", r"\\x00", regex)

            # regex = re.sub(r"^\^", r"\\b", regex)

            regex = "/" + regex + "/"
            if count:
                regex += " nocase"

            # strange: if statement.name == "string", the string is as it is, if statement.name == "regex", the string has // around it, e.g. /regex/
            var_name = "re_" + var_names.pop(0)
            yara_strings += "\t" + "$" + var_name + " = " + regex + " ascii wide " + convert_description(kid) + "\n"
            yara_condition += "\t" + "$" + var_name + " "
        elif s_type == "Not" or s_type == "And" or s_type == "Or":
            pass
        else:
            logger.info("something unhandled: " + repr(s_type))
            sys.exit()

        return yara_strings, yara_condition

    # end: def do_statement

    yara_strings_list = []
    yara_condition_list = []
    rule_comment = ""
    incomplete = 0

    statement = rule.name

    logger.info("doing statement: " + statement)

    if check_feature(statement, rulename):
        return "BREAK", statement, rule_comment, incomplete

    if statement == "And" or statement == "Or":
        desc = convert_description(rule)
        if desc:
            logger.info("description of bool statement: " + repr(desc))
            yara_strings_list.append("\t" * depth + desc + "\n")
    elif statement == "Not":
        logger.info("one of those seldom nots: " + rule.name)

    # check for nested statements
    try:
        kids = rule.children
        num_kids = len(kids)
        logger.info("kids: " + kids)
    except:
        logger.info("no kids in rule: " + rule.name)

        try:
            # maybe it's "Not" = only one child:
            kid = rule.child
            kids = [kid]
            num_kids = 1
            logger.info("kid: %s", kids)
        except:
            logger.info("no kid in rule: %s", rule.name)

    # just a single statement without 'and' or 'or' before it in this rule
    if "kids" not in locals().keys():
        logger.info("no kids: " + rule.name)

        yara_strings_sub, yara_condition_sub = do_statement(statement, rule)

        if yara_strings_sub == "BREAK":
            logger.info("Unknown feature at1: " + rule.name)
            return "BREAK", yara_condition_sub, rule_comment, incomplete
        yara_strings_list.append(yara_strings_sub)
        yara_condition_list.append(yara_condition_sub)

    else:
        x = 0
        logger.info("doing kids: %r - len: %s", kids, num_kids)
        for kid in kids:
            s_type = kid.name
            logger.info("doing type: " + s_type + " kidnum: " + str(x))

            if s_type == "Some":
                cmin = kid.count
                logger.info("Some type with mininum: " + str(cmin))

                if not cmin:
                    logger.info("this is optional: which means, we can just ignore it")
                    x += 1
                    continue
                elif statement == "Or":
                    logger.info("we're inside an OR, we can just ignore it")
                    x += 1
                    continue
                else:
                    # this is "x or more". could be coded for strings TODO
                    return "BREAK", "Some aka x or more (TODO)", rule_comment, incomplete

            if s_type == "And" or s_type == "Or" or s_type == "Not" and not kid.name == "Some":
                logger.info("doing bool with recursion: " + repr(kid))
                logger.info("kid coming: " + repr(kid.name))
                # logger.info("grandchildren: " + repr(kid.children))

                #
                # here we go into RECURSION
                #
                yara_strings_sub, yara_condition_sub, rule_comment_sub, incomplete_sub = convert_rule(
                    kid, rulename, cround, depth
                )

                logger.info("coming out of this recursion, depth: " + repr(depth) + " s_type: " + s_type)

                if yara_strings_sub == "BREAK":
                    logger.info(
                        "Unknown feature at2: " + rule.name + " - s_type: " + s_type + " - depth: " + str(depth)
                    )

                    # luckily this is only a killer, if we're inside an 'And', inside 'Or' we're just missing some coverage
                    # only accept incomplete rules in rounds > 3 because the reason might be a reference to another rule not converted yet because of missing dependencies
                    logger.info("rule.name,  depth,  cround: " + rule.name + ", " + str(depth) + ", " + str(cround))
                    if rule.name == "Or" and depth == 1 and cround > min_rounds - 1:
                        logger.info(
                            "Unknown feature, just ignore this branch and keep the rest bec we're in Or (1): "
                            + s_type
                            + " - depth: "
                            + str(depth)
                        )
                        # remove last 'or'
                        # yara_condition = re.sub(r'\sor $', ' ', yara_condition)
                        rule_comment += "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
                        x += 1
                        incomplete = 1
                        continue
                    else:
                        return "BREAK", yara_condition_sub, rule_comment, incomplete

                rule_comment += rule_comment_sub
                yara_strings_list.append(yara_strings_sub)
                yara_condition_list.append(yara_condition_sub)

                incomplete = incomplete or incomplete_sub

            yara_strings_sub, yara_condition_sub = do_statement(s_type, kid)

            if yara_strings_sub == "BREAK":
                logger.info("Unknown feature at3: " + rule.name)
                logger.info("rule.name,  depth,  cround: " + rule.name + ", " + str(depth) + ", " + str(cround))
                if rule.name == "Or" and depth == 1 and cround > min_rounds - 1:
                    logger.info(
                        "Unknown feature, just ignore this branch and keep the rest bec we're in Or (2): "
                        + s_type
                        + " - depth: "
                        + str(depth)
                    )

                    rule_comment += "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
                    x += 1
                    incomplete = 1
                    continue
                else:
                    return "BREAK", yara_condition_sub, rule_comment, incomplete

            # don't append And or Or if we got no condition back from this kid from e.g. match in myself or unsupported feature inside 'Or'
            if not yara_condition_sub:
                continue

            yara_strings_list.append(yara_strings_sub)
            yara_condition_list.append(yara_condition_sub)
            x += 1

    # this might happen, if all conditions are inside "or" and none of them was supported
    if not yara_condition_list:
        return (
            "BREAK",
            'Multiple statements inside "- or:" where all unsupported, the last one was "' + s_type + '"',
            rule_comment,
            incomplete,
        )

    if statement == "And" or statement == "Or":
        if yara_strings_list:
            yara_strings = "".join(yara_strings_list)
        else:
            yara_strings = ""

        yara_condition = " (\n\t\t" + ("\n\t\t" + statement.lower() + " ").join(yara_condition_list) + " \n\t) "

    elif statement == "Some":
        cmin = rule.count
        logger.info("Some type with mininum at2: " + str(cmin))

        if not cmin:
            logger.info("this is optional: which means, we can just ignore it")
        else:
            # this is "x or more". could be coded for strings TODO
            return "BREAK", "Some aka x or more (TODO)", rule_comment, incomplete
    elif statement == "Not":
        logger.info("Not")
        yara_strings = "".join(yara_strings_list)
        yara_condition = "not " + "".join(yara_condition_list) + " "
    else:
        if len(yara_condition_list) != 1:
            logger.info("something wrong around here" + repr(yara_condition_list) + " - " + statement)
            sys.exit()

        # strings might be empty with only conditions
        if yara_strings_list:
            yara_strings = "\n\t" + yara_strings_list[0]

        yara_condition = "\n\t" + yara_condition_list[0]

    logger.info(f"# end of convert_rule() #strings: {len(yara_strings_list)} #conditions: {len(yara_condition_list)}")
    logger.info(f"strings: {yara_strings} conditions: {yara_condition}")

    return yara_strings, yara_condition, rule_comment, incomplete


def output_yar(yara):
    print(yara + "\n")


def output_unsupported_capa_rules(yaml, capa_rulename, url, reason):

    if reason != "NOLOG":
        if capa_rulename not in unsupported_capa_rules_list:
            logger.info("unsupported: " + capa_rulename + " - reason: " + reason + " - url: " + url)

            unsupported_capa_rules_list.append(capa_rulename)
            unsupported_capa_rules.write(yaml.encode("utf-8") + b"\n")
            unsupported_capa_rules.write(
                (
                    "Reason: "
                    + reason
                    + " (there might be multiple unsupported things in this rule, this is the 1st one encountered)"
                ).encode("utf-8")
                + b"\n"
            )
            unsupported_capa_rules.write(url.encode("utf-8") + b"\n----------------------------------------------\n")
            unsupported_capa_rules_names.write(capa_rulename.encode("utf-8") + b":")
            unsupported_capa_rules_names.write(reason.encode("utf-8") + b":")
            unsupported_capa_rules_names.write(url.encode("utf-8") + b"\n")


def convert_rules(rules, namespaces, cround):
    for rule in rules.rules.values():

        rule_name = convert_rule_name(rule.name)

        if rule.meta.get("capa/subscope-rule", False):
            logger.info("skipping sub scope rule capa: " + rule.name)
            continue

        if rule_name in converted_rules:
            logger.info("skipping already converted rule capa: " + rule.name + " - yara rule: " + rule_name)
            continue

        logger.info("-------------------------- DOING RULE CAPA: " + rule.name + " - yara rule: " + rule_name)
        if "capa/path" in rule.meta:
            url = get_rule_url(rule.meta["capa/path"])
        else:
            url = "no url"

        logger.info("URL: " + url)
        logger.info("statements: " + repr(rule.statement))

        # don't really know what that passed empty string is good for :)
        dependencies = rule.get_dependencies(namespaces)

        if len(dependencies):
            logger.info("Dependencies at4: " + rule.name + " - dep: " + str(dependencies))

            for dep in dependencies:
                logger.info("Dependencies at44: " + dep)
                if not dep.startswith(rule.name + "/"):
                    logger.info("Depending on another rule: " + dep)
                    continue

        yara_strings, yara_condition, rule_comment, incomplete = convert_rule(rule.statement, rule.name, cround, 0)

        if yara_strings == "BREAK":
            # only give up if in final extra round #9000
            if cround == 9000:
                output_unsupported_capa_rules(rule.to_yaml(), rule.name, url, yara_condition)
            logger.info("Unknown feature at5: " + rule.name)
        else:

            yara_meta = ""
            metas = rule.meta
            rule_tags = ""

            for meta in metas:
                meta_name = meta
                # e.g. 'examples:' can be a list
                seen_hashes = []
                if isinstance(metas[meta], list):
                    if meta_name == "examples":
                        meta_name = "hash"
                    if meta_name == "att&ck":
                        meta_name = "attack"
                        for attack in list(metas[meta]):
                            logger.info("attack:" + attack)
                            # cut out tag in square brackets, e.g. Defense Evasion::Obfuscated Files or Information [T1027] => T1027
                            r = re.search(r"\[(T[^\]]*)", attack)
                            if r:
                                tag = r.group(1)
                                logger.info("attack tag:" + tag)
                                tag = re.sub(r"\W", "_", tag)
                                rule_tags += tag + " "
                                # also add a line "attack = ..." to yaras 'meta:' to keep the long description:
                                yara_meta += '\tattack = "' + attack + '"\n'
                    elif meta_name == "mbc":
                        for mbc in list(metas[meta]):
                            logger.info("mbc:" + mbc)
                            # cut out tag in square brackets, e.g. Cryptography::Encrypt Data::RC6 [C0027.010] => C0027.010
                            r = re.search(r"\[(.[^\]]*)", mbc)
                            if r:
                                tag = r.group(1)
                                logger.info("mbc tag:" + tag)
                                tag = re.sub(r"\W", "_", tag)
                                rule_tags += tag + " "

                                # also add a line "mbc = ..." to yaras 'meta:' to keep the long description:
                                yara_meta += '\tmbc = "' + mbc + '"\n'

                    for value in metas[meta]:
                        if meta_name == "hash":
                            value = re.sub(r"^([0-9a-f]{20,64}):0x[0-9a-f]{1,10}$", r"\1", value, flags=re.IGNORECASE)

                            # examples in capa can contain the same hash several times with different offset, so check if it's already there:
                            # (keeping the offset might be interessting for some but breaks yara-ci for checking of the final rules
                            if value not in seen_hashes:
                                yara_meta += "\t" + meta_name + ' = "' + value + '"\n'
                                seen_hashes.append(value)

                else:
                    # no list:
                    if meta == "capa/path":
                        url = get_rule_url(metas[meta])
                        meta_name = "reference"
                        meta_value = "This YARA rule converted from capa rule: " + url
                    else:
                        meta_value = metas[meta]

                    if meta_name == "name":
                        meta_name = "description"
                        meta_value += " (converted from capa rule)"
                    elif meta_name == "lib":
                        meta_value = str(meta_value)
                    elif meta_name == "capa/nursery":
                        meta_name = "capa_nursery"
                        meta_value = str(meta_value)

                    # for the rest of the maec/malware-category names:
                    meta_name = re.sub(r"\W", "_", meta_name)

                    if meta_name and meta_value:
                        yara_meta += "\t" + meta_name + ' = "' + meta_value + '"\n'

            rule_name_bonus = ""
            if rule_comment:
                yara_meta += '\tcomment = "' + rule_comment + '"\n'
            yara_meta += '\tdate = "' + today + '"\n'
            yara_meta += '\tminimum_yara = "3.8"\n'
            yara_meta += '\tlicense = "Apache-2.0 License"\n'

            # check if there's some beef in condition:
            tmp_yc = re.sub(r"(and|or|not)", "", yara_condition)
            if re.search(r"\w", tmp_yc):

                yara = ""
                if make_priv:
                    yara = "private "

                # put yara rule tags here:
                rule_tags = default_tags + rule_tags
                yara += "rule " + rule_name + " : " + rule_tags + " { \n  meta: \n " + yara_meta + "\n"

                if "$" in yara_strings:
                    yara += "  strings: \n " + yara_strings + " \n"

                yara += "  condition:" + condition_header + yara_condition + "\n}"

                # TODO: now the rule is finished and could be automatically checked with the capa-testfile(s) named in meta (doing it for all of them using yara-ci upload at the moment)
                output_yar(yara)
                converted_rules.append(rule_name)
                global count_incomplete
                count_incomplete += incomplete
            else:
                output_unsupported_capa_rules(rule.to_yaml(), rule.name, url, yara_condition)
                pass


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Capa to YARA rule converter")
    parser.add_argument("rules", type=str, help="Path to rules")
    parser.add_argument("--private", "-p", action="store_true", help="Create private rules", default=False)
    capa.main.install_common_args(parser, wanted={"tag"})

    args = parser.parse_args(args=argv)
    global make_priv
    make_priv = args.private

    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.ERROR
    else:
        level = logging.INFO

    logging.basicConfig(level=level)
    logging.getLogger("capa2yara").setLevel(level)

    try:
        rules = capa.main.get_rules([args.rules], disable_progress=True)
        namespaces = capa.rules.index_rules_by_namespace(list(rules))
        rules = capa.rules.RuleSet(rules)
        logger.info("successfully loaded %s rules (including subscope rules which will be ignored)", len(rules))
        if args.tag:
            rules = rules.filter_rules_by_meta(args.tag)
            logger.debug("selected %s rules", len(rules))
            for i, r in enumerate(rules.rules, 1):
                logger.debug(" %d. %s", i, r)
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        return -1

    output_yar(
        "// Rules from Mandiant's https://github.com/mandiant/capa-rules converted to YARA using https://github.com/mandiant/capa/blob/master/scripts/capa2yara.py by Arnim Rupp"
    )
    output_yar(
        "// Beware: These are less rules than capa (because not all fit into YARA, stats at EOF) and is less precise because e.g. capas function scopes are applied to the whole file"
    )
    output_yar(
        '// Beware: Some rules are incomplete because an optional branch was not supported by YARA. These rules are marked in a comment in meta: (search for "incomplete")'
    )
    output_yar("// Rule authors and license stay the same")
    output_yar(
        '// att&ck and MBC tags are put into YARA rule tags. All rules are tagged with "CAPA" for easy filtering'
    )
    output_yar("// The date = in meta: is the date of converting (there is no date in capa rules)")
    output_yar("// Minimum YARA version is 3.8.0 plus PE module")
    output_yar('\nimport "pe"')

    output_yar(condition_rule)

    # do several rounds of converting rules because some rules for match: might not be converted in the 1st run
    num_rules = 9999999
    cround = 0
    while num_rules != len(converted_rules) or cround < min_rounds:
        cround += 1
        logger.info("doing convert_rules(), round: " + str(cround))
        num_rules = len(converted_rules)
        convert_rules(rules, namespaces, cround)

    # one last round to collect all unconverted rules
    convert_rules(rules, namespaces, 9000)

    stats = "\n// converted rules              : " + str(len(converted_rules))
    stats += "\n//   among those are incomplete : " + str(count_incomplete)
    stats += "\n// unconverted rules            : " + str(len(unsupported_capa_rules_list)) + "\n"
    logger.info(stats)
    output_yar(stats)

    return 0


if __name__ == "__main__":
    sys.exit(main())
