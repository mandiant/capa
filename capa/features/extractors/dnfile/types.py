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


from typing import Optional


class DnType:
    def __init__(
        self, token: int, class_: tuple[str, ...], namespace: str = "", member: str = "", access: Optional[str] = None
    ):
        self.token: int = token
        self.access: Optional[str] = access
        self.namespace: str = namespace
        self.class_: tuple[str, ...] = class_

        if member == ".ctor":
            member = "ctor"
        if member == ".cctor":
            member = "cctor"

        self.member: str = member

    def __hash__(self):
        return hash((self.token, self.access, self.namespace, self.class_, self.member))

    def __eq__(self, other):
        return (
            self.token == other.token
            and self.access == other.access
            and self.namespace == other.namespace
            and self.class_ == other.class_
            and self.member == other.member
        )

    def __str__(self):
        return DnType.format_name(self.class_, namespace=self.namespace, member=self.member)

    def __repr__(self):
        return str(self)

    @staticmethod
    def format_name(class_: tuple[str, ...], namespace: str = "", member: str = ""):
        if len(class_) > 1:
            class_str = "/".join(class_)  # Concat items in tuple, separated by a "/"
        else:
            class_str = "".join(class_)  # Convert tuple to str
        # like File::OpenRead
        name: str = f"{class_str}::{member}" if member else class_str
        if namespace:
            # like System.IO.File::OpenRead
            name = f"{namespace}.{name}"
        return name


class DnUnmanagedMethod:
    def __init__(self, token: int, module: str, method: str):
        self.token: int = token
        self.module: str = module
        self.method: str = method

    def __hash__(self):
        return hash((self.token, self.module, self.method))

    def __eq__(self, other):
        return self.token == other.token and self.module == other.module and self.method == other.method

    def __str__(self):
        return DnUnmanagedMethod.format_name(self.module, self.method)

    def __repr__(self):
        return str(self)

    @staticmethod
    def format_name(module, method):
        return f"{module}.{method}"
