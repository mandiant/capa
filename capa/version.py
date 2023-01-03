__version__ = "4.0.1"


def get_major_version():
    return int(__version__.partition(".")[0])
