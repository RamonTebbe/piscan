"""Attack schema + loader for the YAML payload library.

Attacks are data, not code: they live in YAML files under payloads/ and are
validated into Attack objects on load. Keeping the attack library as data lets
it grow without touching any Python — and pydantic guarantees every loaded
attack is well-formed before the rest of the pipeline ever sees it.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

# Where the bundled attack library lives, relative to this file.
PAYLOADS_DIR = Path(__file__).parent / "payloads"


class Attack(BaseModel):
    """One prompt-injection attack, validated from a YAML entry."""

    # Reject unknown fields so a typo in the YAML (e.g. "promt:") fails loudly
    # instead of being silently ignored.
    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    owasp: str
    prompt: str
    description: str


def load_attacks(path: str | Path) -> list[Attack]:
    """Read a YAML file and validate every entry into an Attack.

    Raises ValueError — naming the file and the offending id — if the file is
    not a list or any entry fails schema validation.
    """
    path = Path(path)
    raw = yaml.safe_load(path.read_text())

    if not isinstance(raw, list):
        raise ValueError(
            f"{path.name}: expected a list of attacks, got {type(raw).__name__}"
        )

    attacks: list[Attack] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"{path.name}: entry #{index} is not a mapping")
        # Pull the id up front so we can name it even if validation fails.
        attack_id = item.get("id", f"<entry #{index}>")
        try:
            attacks.append(Attack(**item))
        except ValidationError as error:
            raise ValueError(
                f"{path.name}: invalid attack '{attack_id}': {error}"
            ) from error
    return attacks


def group_by_category(attacks: list[Attack]) -> dict[str, list[Attack]]:
    """Group attacks into {category: [attacks]}, preserving input order."""
    grouped: dict[str, list[Attack]] = {}
    for attack in attacks:
        grouped.setdefault(attack.category, []).append(attack)
    return grouped
