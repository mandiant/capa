__version__ = "4.0.1"


def get_major_version():
    return int(__version__.partition(".")[0])


def get_rules_branch():
    return f"v{get_major_version()}"


def get_rules_checkout_command():
    return f"$ git clone https://github.com/mandiant/capa-rules.git -b {get_rules_branch()} /local/path/to/rules"
