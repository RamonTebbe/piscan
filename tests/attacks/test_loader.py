import textwrap

import pytest

from piscan.attacks.loader import (
    Attack,
    PAYLOADS_DIR,
    load_attacks,
    group_by_category,
)


def test_core_library_loads_into_attack_objects():
    attacks = load_attacks(PAYLOADS_DIR / "core.yaml")
    assert len(attacks) >= 6
    assert all(isinstance(a, Attack) for a in attacks)


def test_core_library_has_the_three_categories():
    attacks = load_attacks(PAYLOADS_DIR / "core.yaml")
    grouped = group_by_category(attacks)
    assert set(grouped) == {"direct_override", "role_play_jailbreak", "prompt_leaking"}


def test_grouping_puts_each_attack_under_its_own_category():
    attacks = load_attacks(PAYLOADS_DIR / "core.yaml")
    grouped = group_by_category(attacks)
    for category, items in grouped.items():
        assert all(a.category == category for a in items)


def test_invalid_yaml_error_names_the_file_and_the_id(tmp_path):
    # A broken entry: the required "description" field is missing.
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        textwrap.dedent(
            """
            - id: broken-001
              category: direct_override
              owasp: LLM01
              prompt: "missing the description field"
            """
        ).strip()
    )
    with pytest.raises(ValueError) as excinfo:
        load_attacks(bad)
    message = str(excinfo.value)
    assert "broken-001" in message  # tells you WHICH attack
    assert "bad.yaml" in message    # ...and in WHICH file
