__version__ = "5.1.0"


def get_major_version():
    return int(__version__.partition(".")[0])
