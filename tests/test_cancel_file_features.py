# Copyright 2023 Google LLC
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

"""
Tests for the file-feature cancellation fix in capa explorer.

These tests mock out all IDA Pro APIs so they can run without IDA Pro installed.
They verify the three changes made to support cancellation during file feature extraction:

  Part 1 — extractor.py: CapaExplorerFeatureExtractor.extract_file_features() override
            calls indicator.update() once per FILE_HANDLER and stops on cancel.
  Part 2 — cache.py:     CapaRuleGenFeatureCache._find_file_features() cancel check
            raises UserCancelledError when user_cancelled() fires mid-loop.
  Part 3 — form.py:      load_capa_function_results() catches UserCancelledError
            and returns False cleanly instead of logging it as an error.
"""

import sys
import types
import collections
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Comprehensive IDA Pro mock installation
# Must be done at module level so it runs before any pytest collection
# imports capa.ida submodules.
# ---------------------------------------------------------------------------

def _build_ida_mocks():
    """
    Return a dict of module_name -> module for all IDA Pro stubs needed
    to import capa.ida.plugin.* without a live IDA installation.
    """
    mocks = {}

    # idaapi — use MagicMock so any attribute access (idaapi.segment_t, etc.)
    # auto-resolves. Explicitly set the attributes that must be real types or
    # specific values so inheritance and comparisons work correctly.
    idaapi = MagicMock()
    idaapi.plugin_t = type("plugin_t", (), {})
    idaapi.PluginForm = type("PluginForm", (), {
        "WOPN_TAB": 0, "WOPN_RESTORE": 0, "WCLS_CLOSE_LATER": 0, "WCLS_SAVE": 0,
        "Show": MagicMock(), "FormToPyQtWidget": MagicMock(),
    })
    idaapi.f_PE = 1
    idaapi.f_ELF = 18
    idaapi.f_BIN = 3
    idaapi.f_COFF = 6
    idaapi.PLUGIN_SKIP = 0
    idaapi.PLUGIN_OK = 1
    idaapi.BWN_DISASM = 1
    idaapi.ASKBTN_YES = 1
    idaapi.ASKBTN_CANCEL = -1
    idaapi.get_kernel_version = MagicMock(return_value="8.3")
    mocks["idaapi"] = idaapi

    # ida_kernwin — user_cancelled is overridden per-test via the fixture
    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.user_cancelled = MagicMock(return_value=False)
    ida_kernwin.replace_wait_box = MagicMock()
    ida_kernwin.show_wait_box = MagicMock()
    ida_kernwin.hide_wait_box = MagicMock()
    ida_kernwin.ask_buttons = MagicMock(return_value=0)
    ida_kernwin.ASKBTN_YES = 1
    ida_kernwin.ASKBTN_CANCEL = -1
    # UI_Hooks and action helpers used in capa/ida/plugin/__init__.py
    ida_kernwin.UI_Hooks = type("UI_Hooks", (), {"hook": MagicMock(), "unhook": MagicMock()})
    ida_kernwin.get_registered_actions = MagicMock(return_value=[])
    ida_kernwin.load_custom_icon = MagicMock(return_value=0)
    ida_kernwin.update_action_icon = MagicMock()
    ida_kernwin.free_custom_icon = MagicMock()
    mocks["ida_kernwin"] = ida_kernwin

    # ida_settings
    ida_settings_mod = types.ModuleType("ida_settings")
    ida_settings_mod.IDASettings = MagicMock()
    mocks["ida_settings"] = ida_settings_mod

    # idautils — needed by capa/features/extractors/ida/file.py
    idautils = types.ModuleType("idautils")
    idautils.Strings = MagicMock(return_value=[])
    idautils.Functions = MagicMock(return_value=[])
    idautils.Segments = MagicMock(return_value=[])
    idautils.CodeRefsTo = MagicMock(return_value=[])
    idautils.XrefsFrom = MagicMock(return_value=[])
    mocks["idautils"] = idautils

    # ida_entry — needed by capa/features/extractors/ida/file.py
    ida_entry = types.ModuleType("ida_entry")
    ida_entry.get_entry_qty = MagicMock(return_value=0)
    ida_entry.get_entry = MagicMock(return_value=0)
    ida_entry.get_entry_name = MagicMock(return_value="")
    mocks["ida_entry"] = ida_entry

    # remaining IDA stubs — use MagicMock so any attribute access at module-level
    # (e.g. ida_nalt.BPU_1B, ida_nalt.get_default_encoding_idx) returns a mock
    # instead of raising AttributeError.
    for name in [
        "ida_netnode", "idc", "ida_nalt", "ida_funcs", "ida_bytes",
        "ida_segment", "ida_name", "ida_lines", "ida_ua", "ida_xref",
        "ida_typeinf", "ida_allins", "ida_struct", "ida_frame",
        "ida_ida", "ida_loader",
    ]:
        mocks[name] = MagicMock()

    return mocks, ida_kernwin


_IDA_MOCKS, _IDA_KERNWIN_MOCK = _build_ida_mocks()
sys.modules.update(_IDA_MOCKS)

# Qt compat mock — needed before importing anything from capa.ida.plugin
_qt_compat = types.ModuleType("capa.ida.plugin.qt_compat")
_QtCore = MagicMock()
_QtCore.QObject = object   # plain base class so Qt inheritance compiles
_qt_compat.QtCore = _QtCore
_qt_compat.Qt = MagicMock()
_qt_compat.QtWidgets = MagicMock()
_qt_compat.QtGui = MagicMock()
_qt_compat.QAction = MagicMock()
_qt_compat.Signal = MagicMock(return_value=MagicMock())
_qt_compat.qt_get_item_flag_tristate = MagicMock(return_value=MagicMock())
sys.modules["capa.ida.plugin.qt_compat"] = _qt_compat

# ---------------------------------------------------------------------------
# Now it's safe to import the modules under test
# ---------------------------------------------------------------------------

from capa.ida.plugin.error import UserCancelledError  # noqa: E402
import capa.ida.plugin.extractor as extractor_mod      # noqa: E402
import capa.ida.plugin.cache as cache_mod              # noqa: E402
import capa.features.extractors.ida.file as ida_file_mod  # noqa: E402

import pytest  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_user_cancelled(return_value=False):
    """Reset the user_cancelled mock to a fixed return value."""
    _IDA_KERNWIN_MOCK.user_cancelled = MagicMock(return_value=return_value)


def _make_indicator(cancelled=False):
    """Build a CapaExplorerProgressIndicator with a no-op progress signal."""
    _reset_user_cancelled(cancelled)
    indicator = object.__new__(extractor_mod.CapaExplorerProgressIndicator)
    indicator.progress = MagicMock()
    return indicator


def _make_extractor_with_indicator(cancelled=False):
    """Build a CapaExplorerFeatureExtractor with a real indicator."""
    extractor = object.__new__(extractor_mod.CapaExplorerFeatureExtractor)
    extractor.indicator = _make_indicator(cancelled)
    return extractor


# ---------------------------------------------------------------------------
# Part 1: CapaExplorerProgressIndicator
# ---------------------------------------------------------------------------

class TestProgressIndicator:
    def test_raises_user_cancelled_error_when_cancelled(self):
        """
        indicator.update() must raise UserCancelledError when
        ida_kernwin.user_cancelled() returns True.
        """
        indicator = _make_indicator(cancelled=True)
        with pytest.raises(UserCancelledError):
            indicator.update("test handler")

    def test_no_raise_when_not_cancelled(self):
        """
        indicator.update() must NOT raise when user_cancelled() returns False.
        """
        indicator = _make_indicator(cancelled=False)
        indicator.update("test handler")   # should not raise


# ---------------------------------------------------------------------------
# Part 1: extract_file_features() override
# ---------------------------------------------------------------------------

class TestExtractFileFeatures:
    def setup_method(self):
        """Swap FILE_HANDLERS for lightweight stubs before each test."""
        self._original_handlers = ida_file_mod.FILE_HANDLERS

        self.feature_a = MagicMock(name="feature_a")
        self.feature_b = MagicMock(name="feature_b")

        feature_a = self.feature_a
        feature_b = self.feature_b

        def handler_a():
            yield (feature_a, 0x1000)

        def handler_b():
            yield (feature_b, 0x2000)

        self.handler_a = handler_a
        self.handler_b = handler_b
        ida_file_mod.FILE_HANDLERS = (handler_a, handler_b)

    def teardown_method(self):
        ida_file_mod.FILE_HANDLERS = self._original_handlers
        _reset_user_cancelled(False)

    def test_calls_indicator_update_once_per_handler(self):
        """
        extract_file_features() must call self.indicator.update() exactly
        once per FILE_HANDLER so the cancel check fires before each handler.
        """
        extractor = _make_extractor_with_indicator(cancelled=False)
        extractor.indicator.update = MagicMock()

        results = list(extractor.extract_file_features())

        assert len(results) == 2, f"expected 2 features, got {len(results)}"
        assert extractor.indicator.update.call_count == 2, (
            f"expected update() called twice (once per handler), "
            f"got {extractor.indicator.update.call_count}"
        )
        # each message should contain the handler function name
        msgs = [c[0][0] for c in extractor.indicator.update.call_args_list]
        assert "handler_a" in msgs[0]
        assert "handler_b" in msgs[1]

    def test_stops_before_second_handler_when_cancelled(self):
        """
        If the user cancels after the first handler, extract_file_features()
        must raise UserCancelledError before handler_b runs.
        """
        # Build extractor first — this calls _reset_user_cancelled internally,
        # so the toggle must be installed AFTER to avoid being overwritten.
        extractor = object.__new__(extractor_mod.CapaExplorerFeatureExtractor)
        extractor.indicator = object.__new__(extractor_mod.CapaExplorerProgressIndicator)
        extractor.indicator.progress = MagicMock()

        call_count = {"n": 0}

        def toggle():
            call_count["n"] += 1
            return call_count["n"] >= 2   # False on 1st call, True on 2nd

        # Install toggle after extractor is built so it isn't reset
        _IDA_KERNWIN_MOCK.user_cancelled = toggle

        handler_b_ran = {"ran": False}
        original_b = self.handler_b

        def handler_b_spy():
            handler_b_ran["ran"] = True
            yield from original_b()

        ida_file_mod.FILE_HANDLERS = (self.handler_a, handler_b_spy)

        with pytest.raises(UserCancelledError):
            list(extractor.extract_file_features())

        assert not handler_b_ran["ran"], "handler_b should NOT have run after cancel"

    def test_yields_all_features_when_not_cancelled(self):
        """
        extract_file_features() must yield every feature when the user
        does not cancel.
        """
        extractor = _make_extractor_with_indicator(cancelled=False)
        results = list(extractor.extract_file_features())
        assert len(results) == 2
        assert results[0][0] is self.feature_a
        assert results[1][0] is self.feature_b


# ---------------------------------------------------------------------------
# Part 2: CapaRuleGenFeatureCache._find_file_features()
# ---------------------------------------------------------------------------

class TestFindFileFeatures:
    def setup_method(self):
        _reset_user_cancelled(False)

    def teardown_method(self):
        _reset_user_cancelled(False)

    def _make_cache(self, feature_pairs):
        """Build a minimal cache object whose extractor yields the given pairs."""
        def fake_extract():
            yield from feature_pairs

        cache = object.__new__(cache_mod.CapaRuleGenFeatureCache)
        cache.extractor = MagicMock()
        cache.extractor.extract_file_features = fake_extract
        cache.file_node = MagicMock()
        cache.file_node.features = collections.defaultdict(set)
        return cache

    def test_stores_all_features_when_not_cancelled(self):
        """All yielded features must be stored when user_cancelled() is always False."""
        feature_a, feature_b = MagicMock(), MagicMock()
        cache = self._make_cache([(feature_a, 0x1000), (feature_b, None)])

        cache._find_file_features()

        assert 0x1000 in cache.file_node.features[feature_a]
        assert feature_b in cache.file_node.features

    def test_raises_user_cancelled_mid_loop(self):
        """
        _find_file_features() must raise UserCancelledError when
        user_cancelled() returns True partway through iteration.
        """
        processed = {"count": 0}

        def cancel_after_first():
            return processed["count"] >= 1

        _IDA_KERNWIN_MOCK.user_cancelled = cancel_after_first

        def fake_extract():
            for i in range(5):
                processed["count"] += 1
                yield (MagicMock(), 0x1000 + i)

        cache = object.__new__(cache_mod.CapaRuleGenFeatureCache)
        cache.extractor = MagicMock()
        cache.extractor.extract_file_features = fake_extract
        cache.file_node = MagicMock()
        cache.file_node.features = collections.defaultdict(set)

        with pytest.raises(UserCancelledError):
            cache._find_file_features()

        assert processed["count"] == 1, (
            f"expected extraction to stop after 1 feature, processed {processed['count']}"
        )

    def test_cancel_check_fires_for_every_feature(self):
        """
        user_cancelled() must be called once per yielded feature so there are
        no silent batches between cancel polls.
        """
        _reset_user_cancelled(False)
        _IDA_KERNWIN_MOCK.user_cancelled = MagicMock(return_value=False)

        features = [(MagicMock(), 0x1000 + i) for i in range(4)]
        cache = self._make_cache(features)
        cache._find_file_features()

        assert _IDA_KERNWIN_MOCK.user_cancelled.call_count == 4, (
            f"expected user_cancelled() called 4 times (once per feature), "
            f"got {_IDA_KERNWIN_MOCK.user_cancelled.call_count}"
        )


# ---------------------------------------------------------------------------
# Part 3: load_capa_function_results() UserCancelledError handling
# ---------------------------------------------------------------------------

class TestLoadCapaFunctionResults:
    def setup_method(self):
        _reset_user_cancelled(False)

    def teardown_method(self):
        _reset_user_cancelled(False)

    def _make_form(self):
        """Build a minimal CapaExplorerForm stub for load_capa_function_results()."""
        import capa.ida.plugin.form as form_mod

        form = object.__new__(form_mod.CapaExplorerForm)
        form.rulegen_ruleset_cache = MagicMock()   # skip rule loading
        form.rulegen_feature_cache = None           # force cache construction
        form.rulegen_feature_extractor = None
        form.rulegen_current_function = None
        return form

    def test_returns_false_when_cache_raises_user_cancelled(self):
        """
        load_capa_function_results() must return False when
        CapaRuleGenFeatureCache construction raises UserCancelledError.
        """
        import capa.ida.plugin.form as form_mod

        with patch.object(form_mod, "CapaRuleGenFeatureCache",
                          side_effect=UserCancelledError("user cancelled")):
            with patch.object(form_mod, "CapaExplorerFeatureExtractor",
                              return_value=MagicMock()):
                result = self._make_form().load_capa_function_results()

        assert result is False, f"expected False on UserCancelledError, got {result!r}"

    def test_logs_info_not_exception_on_user_cancel(self):
        """
        Before the fix, UserCancelledError was caught by 'except Exception' and
        logged as an error. Verify the correct except branch is taken: info log,
        not exception log.
        """
        import capa.ida.plugin.form as form_mod

        with patch.object(form_mod, "CapaRuleGenFeatureCache",
                          side_effect=UserCancelledError("user cancelled")):
            with patch.object(form_mod, "CapaExplorerFeatureExtractor",
                              return_value=MagicMock()):
                with patch("capa.ida.plugin.form.logger") as mock_logger:
                    self._make_form().load_capa_function_results()

        mock_logger.exception.assert_not_called()
        mock_logger.info.assert_any_call("User cancelled analysis.")

    def test_generic_exception_still_logged_as_error(self):
        """
        Ensure the generic Exception path still works — a non-cancel exception
        must still be logged via logger.exception (not silently swallowed).
        """
        import capa.ida.plugin.form as form_mod

        with patch.object(form_mod, "CapaRuleGenFeatureCache",
                          side_effect=RuntimeError("some unexpected error")):
            with patch.object(form_mod, "CapaExplorerFeatureExtractor",
                              return_value=MagicMock()):
                with patch("capa.ida.plugin.form.logger") as mock_logger:
                    result = self._make_form().load_capa_function_results()

        assert result is False
        mock_logger.exception.assert_called_once()
