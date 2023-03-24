# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import ida_kernwin
from PyQt5 import QtCore

from capa.ida.plugin.error import UserCancelledError
from capa.features.extractors.ida.extractor import IdaFeatureExtractor
from capa.features.extractors.base_extractor import FunctionHandle


class CapaExplorerProgressIndicator(QtCore.QObject):
    """implement progress signal, used during feature extraction"""

    progress = QtCore.pyqtSignal(str)

    def update(self, text):
        """emit progress update

        check if user cancelled action, raise exception for parent function to catch
        """
        if ida_kernwin.user_cancelled():
            raise UserCancelledError("user cancelled")
        self.progress.emit(f"extracting features from {text}")


class CapaExplorerFeatureExtractor(IdaFeatureExtractor):
    """subclass the IdaFeatureExtractor

    track progress during feature extraction, also allow user to cancel feature extraction
    """

    def __init__(self):
        super().__init__()
        self.indicator = CapaExplorerProgressIndicator()

    def extract_function_features(self, fh: FunctionHandle):
        self.indicator.update(f"function at {hex(fh.inner.start_ea)}")
        return super().extract_function_features(fh)
