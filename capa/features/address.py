import abc

from dncil.clr.token import Token


class Address(abc.ABC):
    @abc.abstractmethod
    def __eq__(self, other):
        ...

    @abc.abstractmethod
    def __lt__(self, other):
        # implement < so that addresses can be sorted from low to high
        ...

    @abc.abstractmethod
    def __hash__(self):
        # implement hash so that addresses can be used in sets and dicts
        ...

    @abc.abstractmethod
    def __repr__(self):
        # implement repr to help during debugging
        ...


class AbsoluteVirtualAddress(int, Address):
    """an absolute memory address"""

    def __new__(cls, v):
        assert v >= 0
        return int.__new__(cls, v)

    def __repr__(self):
        return f"absolute(0x{self:x})"


class RelativeVirtualAddress(int, Address):
    """a memory address relative to a base address"""

    def __repr__(self):
        return f"relative(0x{self:x})"


class FileOffsetAddress(int, Address):
    """an address relative to the start of a file"""

    def __new__(cls, v):
        assert v >= 0
        return int.__new__(cls, v)

    def __repr__(self):
        return f"file(0x{self:x})"


class DNTokenAddress(Address):
    """a .NET token"""

    def __init__(self, token: Token):
        self.token = token

    def __eq__(self, other):
        return self.token.value == other.token.value

    def __lt__(self, other):
        return self.token.value < other.token.value

    def __hash__(self):
        return hash(self.token.value)

    def __repr__(self):
        return f"token(0x{self.token.value:x})"

    def __index__(self):
        # returns the object converted to an integer
        return self.token.value


class DNTokenOffsetAddress(Address):
    """an offset into an object specified by a .NET token"""

    def __init__(self, token: Token, offset: int):
        assert offset >= 0
        self.token = token
        self.offset = offset

    def __eq__(self, other):
        return (self.token.value, self.offset) == (other.token.value, other.offset)

    def __lt__(self, other):
        return (self.token.value, self.offset) < (other.token.value, other.offset)

    def __hash__(self):
        return hash((self.token.value, self.offset))

    def __repr__(self):
        return f"token(0x{self.token.value:x})+(0x{self.offset:x})"

    def __index__(self):
        return self.token.value + self.offset


class _NoAddress(Address):
    def __eq__(self, other):
        return True

    def __lt__(self, other):
        return False

    def __hash__(self):
        return hash(0)

    def __repr__(self):
        return "no address"


NO_ADDRESS = _NoAddress()
