"""The advance is a property of the deployment, so both of its components read it (ADR-0023).

ADR-0023 gave the kernel a clock override so a reviewer could watch expiry and decay happen on a
deployment rather than in this repository's tests. Its residuals section reasoned about the offline
CLI and never about the gateway — which is the component that enforces.

The gateway stamps an action-request's `not-after` from its own clock. Against a kernel running
ahead, every gated call arrived already past that instant and came back `gate-request-expired`
instead of `gate-parked`, so nothing could be queued and no human could approve anything. Three
independent evaluations reached that state; one spent the rest of its run unable to approve a single
call, and the facility that caused it is the one built so reviewers could observe the product.
"""

from __future__ import annotations

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.config import ConfigError, GatewayConfig, load_config_file

ACKNOWLEDGEMENT = clock_module.CLOCK_ADVANCE_ACKNOWLEDGEMENT


def test_a_deployment_that_says_nothing_about_its_clock_gets_the_hosts() -> None:
    config = GatewayConfig()
    assert type(clock_module.from_config(config)) is clock_module.Clock


def test_an_advance_moves_the_gateways_clock_forward() -> None:
    config = GatewayConfig.model_validate(
        {"clock": {"advance": "P7D", "acknowledged": ACKNOWLEDGEMENT}}
    )
    clock = clock_module.from_config(config)
    assert isinstance(clock, clock_module.AdvancedClock)
    # Seven days ahead of the host, to the second the comparison can be made without a race.
    assert clock.now() > clock_module.shift(clock_module.now(), 6 * 86400)
    assert clock.now() < clock_module.shift(clock_module.now(), 8 * 86400)


def test_the_acknowledgement_is_required_and_exact() -> None:
    """The sentence is the point: a deployment running this way emits records whose timestamps are
    not when anything happened, and it says so in the file that gets diffed and reviewed."""
    with pytest.raises(ValueError, match="acknowledged must read exactly"):
        GatewayConfig.model_validate({"clock": {"advance": "P7D"}})
    with pytest.raises(ValueError, match="acknowledged must read exactly"):
        GatewayConfig.model_validate(
            {"clock": {"advance": "P7D", "acknowledged": "yes I know what I am doing"}}
        )


def test_the_acknowledgement_alone_buys_nothing() -> None:
    with pytest.raises(ValueError, match="no clock.advance"):
        GatewayConfig.model_validate({"clock": {"acknowledged": ACKNOWLEDGEMENT}})


def test_the_clock_cannot_be_moved_backwards() -> None:
    """Not a check — a grammar. `advance` is an ISO 8601 duration of §01 §2.4, which has no sign, so
    "move the clock back an hour" is not a sentence this configuration can say."""
    with pytest.raises(ValueError, match="encoding-bad-duration"):
        GatewayConfig.model_validate(
            {"clock": {"advance": "-PT1H", "acknowledged": ACKNOWLEDGEMENT}}
        )
    with pytest.raises(ValueError, match="positive duration"):
        GatewayConfig.model_validate(
            {"clock": {"advance": "PT0S", "acknowledged": ACKNOWLEDGEMENT}}
        )


def test_the_gateways_advance_is_spelled_the_same_as_the_kernels(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Byte-identical to `stozher_kernel::clock::CLOCK_ADVANCE_ACKNOWLEDGEMENT`, and read from a
    real file the way an operator writes one — two components of one deployment do not get two
    spellings of the same declaration."""
    source = (
        "kernel/stozher-kernel/src/clock.rs"
    )
    from pathlib import Path

    rust = (Path(__file__).resolve().parents[2] / source).read_text()
    assert f'"{ACKNOWLEDGEMENT}"' in rust, "the two components disagree on the acknowledgement"

    written = tmp_path / "stozher-gateway.toml"
    written.write_text(f'[clock]\nadvance = "PT5H"\nacknowledged = "{ACKNOWLEDGEMENT}"\n')
    config = load_config_file(written)
    assert config.clock.advance == "PT5H"
    assert isinstance(clock_module.from_config(config), clock_module.AdvancedClock)


def test_a_malformed_advance_is_refused_at_load_not_at_the_first_call(tmp_path) -> None:  # type: ignore[no-untyped-def]
    written = tmp_path / "stozher-gateway.toml"
    written.write_text(f'[clock]\nadvance = "five hours"\nacknowledged = "{ACKNOWLEDGEMENT}"\n')
    with pytest.raises(ConfigError):
        load_config_file(written)
