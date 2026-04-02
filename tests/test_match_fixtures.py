from pathlib import Path

import pytest

import capa.capabilities.common
import capa.capabilities.dynamic
import match_fixtures

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "matcher"
FIXTURE_PATHS = sorted(
    path for path in FIXTURE_DIR.rglob("*") if path.suffix in {".json", ".yml", ".yaml"}
)
FIXTURES = [
    fixture for path in FIXTURE_PATHS for fixture in match_fixtures.load_fixtures(path)
]
FIXTURE_IDS = [
    f"{fixture.path.relative_to(FIXTURE_DIR)}[{fixture.index}]::{fixture.name}"
    for fixture in FIXTURES
]


@pytest.mark.parametrize("fixture", FIXTURES, ids=FIXTURE_IDS)
def test_match_fixture(fixture: match_fixtures.MatchFixture):
    with pytest.MonkeyPatch.context() as patch:
        if fixture.span_size is not None:
            patch.setattr(capa.capabilities.dynamic, "SPAN_SIZE", fixture.span_size)

        capabilities = capa.capabilities.common.find_capabilities(
            fixture.ruleset,
            fixture.extractor,
            disable_progress=True,
        )

    assert (
        match_fixtures.render_matches(fixture, capabilities.matches)
        == fixture.expected_matches
    )
