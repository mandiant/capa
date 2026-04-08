# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc
from typing import Optional


def _process_sort_key(process: Optional["ProcessAddress"]) -> tuple:
    """Create a total ordering key for nested process addresses."""
    if process is None:
        return (0,)

    instance_id = process.instance_id if process.instance_id is not None else -1
    return (1, _process_sort_key(process.parent), process.pid, instance_id)


class Address(abc.ABC):
    @abc.abstractmethod
    def __eq__(self, other): ...

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

    def __hash__(self):
        return int.__hash__(self)


class ProcessAddress(Address):
    """an address of a process in a dynamic execution trace

    Args:
        pid: process ID assigned by the OS
        parent: full address of the parent process, enabling unique tracking
            of the parent even if its PID was recycled by the OS.
            Use None for root/top-level processes (ppid == 0).
        instance_id: sandbox-specific unique identifier to distinguish
            processes whose OS-assigned PIDs collide due to reuse.
            For VMRay this is the monitor_id; for CAPE it is a sequential
            counter; for Drakvuf it is 0 (TID recycling is not tracked there).
    """

    def __init__(
        self,
        pid: int,
        parent: Optional["ProcessAddress"] = None,
        instance_id: Optional[int] = None,
    ):
        assert pid > 0
        if parent is not None:
            assert parent.pid > 0
        self.pid = pid
        self.parent = parent
        self.instance_id = instance_id

    @property
    def ppid(self) -> int:
        """OS parent PID (0 if no parent)."""
        return self.parent.pid if self.parent else 0

    def __repr__(self):
        parts = []
        if self.parent is not None:
            parts.append(f"ppid: {self.parent.pid}")
        parts.append(f"pid: {self.pid}")
        if self.instance_id is not None:
            parts.append(f"instance_id: {self.instance_id}")
        return "process(%s)" % ", ".join(parts)

    def __hash__(self):
        return hash((self.parent, self.pid, self.instance_id))

    def __eq__(self, other):
        if not isinstance(other, ProcessAddress):
            return NotImplemented
        return (self.parent, self.pid, self.instance_id) == (
            other.parent,
            other.pid,
            other.instance_id,
        )

    def __lt__(self, other):
        assert isinstance(other, ProcessAddress)
        return _process_sort_key(self) < _process_sort_key(other)


class ThreadAddress(Address):
    """addresses a thread in a dynamic execution trace

    Args:
        process: address of the containing process
        tid: thread ID assigned by the OS
        instance_id: sandbox-specific unique identifier to distinguish
            threads whose OS-assigned TIDs collide due to reuse.
            For VMRay this is the monitor_id; for CAPE it is a sequential
            counter; for Drakvuf it is 0 (TID recycling is not tracked there).
    """

    def __init__(
        self, process: ProcessAddress, tid: int, instance_id: Optional[int] = None
    ):
        assert tid >= 0
        self.process = process
        self.tid = tid
        self.instance_id = instance_id

    def __repr__(self):
        iid_part = (
            f", instance_id: {self.instance_id}" if self.instance_id is not None else ""
        )
        return f"{self.process}, thread(tid: {self.tid}{iid_part})"

    def __hash__(self):
        return hash((self.process, self.tid, self.instance_id))

    def __eq__(self, other):
        if not isinstance(other, ThreadAddress):
            return NotImplemented
        return (self.process, self.tid, self.instance_id) == (
            other.process,
            other.tid,
            other.instance_id,
        )

    def __lt__(self, other):
        assert isinstance(other, ThreadAddress)
        self_iid = self.instance_id if self.instance_id is not None else -1
        other_iid = other.instance_id if other.instance_id is not None else -1
        return (_process_sort_key(self.process), self.tid, self_iid) < (
            _process_sort_key(other.process),
            other.tid,
            other_iid,
        )


class DynamicCallAddress(Address):
    """addresses a call in a dynamic execution trace"""

    def __init__(self, thread: ThreadAddress, id: int):
        assert id >= 0
        self.thread = thread
        self.id = id

    def __repr__(self):
        return f"{self.thread}, call(id: {self.id})"

    def __hash__(self):
        return hash((self.thread, self.id))

    def __eq__(self, other):
        return isinstance(other, DynamicCallAddress) and (self.thread, self.id) == (
            other.thread,
            other.id,
        )

    def __lt__(self, other):
        assert isinstance(other, DynamicCallAddress)
        return (self.thread, self.id) < (other.thread, other.id)


class RelativeVirtualAddress(int, Address):
    """a memory address relative to a base address"""

    def __repr__(self):
        return f"relative(0x{self:x})"

    def __hash__(self):
        return int.__hash__(self)


class FileOffsetAddress(int, Address):
    """an address relative to the start of a file"""

    def __new__(cls, v):
        assert v >= 0
        return int.__new__(cls, v)

    def __repr__(self):
        return f"file(0x{self:x})"

    def __hash__(self):
        return int.__hash__(self)


class DNTokenAddress(int, Address):
    """a .NET token"""

    def __new__(cls, token: int):
        return int.__new__(cls, token)

    def __repr__(self):
        return f"token(0x{self:x})"

    def __hash__(self):
        return int.__hash__(self)


class DNTokenOffsetAddress(Address):
    """an offset into an object specified by a .NET token"""

    def __init__(self, token: int, offset: int):
        assert offset >= 0
        self.token = token
        self.offset = offset

    def __eq__(self, other):
        return (self.token, self.offset) == (other.token, other.offset)

    def __lt__(self, other):
        return (self.token, self.offset) < (other.token, other.offset)

    def __hash__(self):
        return hash((self.token, self.offset))

    def __repr__(self):
        return f"token(0x{self.token:x})+(0x{self.offset:x})"

    def __index__(self):
        return self.token + self.offset


class _NoAddress(Address):
    def __eq__(self, other):
        return True

    def __lt__(self, other):
        return False

    def __gt__(self, other):
        # Mixed-type comparison: (real_address < NO_ADDRESS) invokes this so sort works.
        # NoAddress sorts last.
        return other is not self

    def __hash__(self):
        return hash(0)

    def __repr__(self):
        return "no address"


NO_ADDRESS = _NoAddress()
