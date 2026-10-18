"""Optional dependency extras never identify a separate bumped package."""

import pytest

from tests.test_dependency_drift_precision import _assume, _push, _status
from tests.test_dependency_drift_precision import engine as engine


@pytest.mark.parametrize("assumed,bumped", [
    ("requests[socks]", "socks"),
    ("requests[socks,security]", "socks"),
    ("requests[socks,security]", "security"),
    ("Requests_OAuthlib[security]", "security"),
    ("socks", "requests[socks]"),
])
def test_extras_do_not_supply_a_separate_package_identity(engine, assumed, bumped):
    assumption = _assume(engine, f"the {assumed} library remains compatible")
    (notice_id,) = _push(engine, f"Bump {bumped} from 1.0 to 2.0")["invalidations"]
    assert _status(engine, assumption.id) == "active"
    assert _status(engine, notice_id) == "pending_confirmation"


@pytest.mark.parametrize("assumed,bumped", [
    ("requests[socks]", "requests"),
    ("requests[socks,security]", "requests[security]"),
    ("Requests_OAuthlib[security]", "requests-oauthlib"),
])
def test_extras_preserve_the_base_package_identity(engine, assumed, bumped):
    assumption = _assume(engine, f"the {assumed} library remains compatible")
    (notice_id,) = _push(engine, f"Bump {bumped} from 1.0 to 2.0")["invalidations"]
    assert _status(engine, assumption.id) == "invalidated"
    assert _status(engine, notice_id) == "open"


@pytest.mark.parametrize("assumed,bumped", [
    ("requests[socks, security]", "socks"),
    ("requests[socks, security]", "security"),
    ("requests[ socks ]", "socks"),
    ("requests [socks]", "socks"),
    ("requests [socks, security]", "security"),
    ("socks", "requests [socks]"),
])
def test_spaced_extras_do_not_supply_a_separate_package_identity(engine, assumed, bumped):
    # PyPA permits spaces/tabs before brackets and around extra identifiers/commas:
    # https://packaging.python.org/en/latest/specifications/dependency-specifiers/
    assumption = _assume(engine, f"the {assumed} library remains compatible")
    (notice_id,) = _push(engine, f"Bump {bumped} from 1.0 to 2.0")["invalidations"]
    assert _status(engine, assumption.id) == "active"
    assert _status(engine, notice_id) == "pending_confirmation"


@pytest.mark.parametrize("assumed,bumped", [
    ("requests[socks, security]", "requests"),
    ("requests[ socks ]", "requests"),
    ("requests [socks]", "requests"),
    ("requests", "requests[socks, security]"),
    ("requests", "requests[ socks ]"),
    ("requests", "requests [socks]"),
    ("Requests_OAuthlib [ socks, security ]", "requests-oauthlib\t[ security ]"),
    ("requests[]", "requests[]"),
    ("requests[ ]", "requests [\t]"),
])
def test_spaced_or_empty_extras_preserve_the_base_package_identity(engine, assumed, bumped):
    assumption = _assume(engine, f"the {assumed} library remains compatible")
    (notice_id,) = _push(engine, f"Bump {bumped} from 1.0 to 2.0")["invalidations"]
    assert _status(engine, assumption.id) == "invalidated"
    assert _status(engine, notice_id) == "open"
