# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Create summary documents for a rule package."""

import json
from collections import defaultdict
from dataclasses import dataclass, field
from functools import reduce
from pathlib import Path
from typing import Any

from marshmallow import pre_load

from .attack import CURRENT_ATTACK_VERSION
from .mixins import MarshmallowDataclassMixin
from .rule import TOMLRule
from .schemas import definitions

_DEFAULT_PLATFORMS = [
    "Azure AD",
    "Containers",
    "Google Workspace",
    "IaaS",
    "Linux",
    "macOS",
    "Network",
    "Office 365",
    "PRE",
    "SaaS",
    "Windows",
]
_DEFAULT_NAVIGATOR_LINKS = {"label": "repo", "url": "https://github.com/elastic/detection-rules"}
# Layers published to the ATT&CK navigator gist. Tag/index layers exceed GitHub's gist limits.
PUBLISHED_NAVIGATOR_LAYERS = ("all", "platforms")


@dataclass
class NavigatorMetadata(MarshmallowDataclassMixin):
    """Metadata for ATT&CK navigator objects."""

    name: str
    value: str


@dataclass
class NavigatorLinks(MarshmallowDataclassMixin):
    """Metadata for ATT&CK navigator objects."""

    label: str
    url: str


@dataclass
class Techniques(MarshmallowDataclassMixin):
    """ATT&CK navigator techniques array class."""

    techniqueID: str
    tactic: str
    score: int
    metadata: list[NavigatorMetadata]
    links: list[NavigatorLinks]

    color: str = ""
    comment: str = ""
    enabled: bool = True
    showSubtechniques: bool = False

    @pre_load
    def set_score(self, data: dict[str, Any], **_: Any) -> dict[str, Any]:
        data["score"] = len(data["metadata"])
        return data


@dataclass
class Navigator(MarshmallowDataclassMixin):
    """ATT&CK navigator class."""

    @dataclass
    class Versions:
        attack: str
        layer: str = "4.4"
        navigator: str = "4.5.5"

    @dataclass
    class Filters:
        platforms: list[str] = field(default_factory=_DEFAULT_PLATFORMS.copy)

    @dataclass
    class Layout:
        layout: str = "side"
        aggregateFunction: str = "average"
        showID: bool = True
        showName: bool = True
        showAggregateScores: bool = False
        countUnscored: bool = False

    @dataclass
    class Gradient:
        colors: list[str] = field(default_factory=["#d3e0fa", "#0861fb"].copy)
        minValue: int = 0
        maxValue: int = 10

    # not all defaults set
    name: str
    versions: Versions
    techniques: list[Techniques]

    # all defaults set
    filters: Filters = field(default_factory=Filters)
    layout: Layout = field(default_factory=Layout)
    gradient: Gradient = field(default_factory=Gradient)

    domain: str = "enterprise-attack"
    description: str = "Elastic detection-rules coverage"
    hideDisabled: bool = False
    legendItems: list[Any] = field(default_factory=list)  # type: ignore[reportUnknownVariableType]

    links: list[NavigatorLinks] = field(default_factory=[_DEFAULT_NAVIGATOR_LINKS].copy)  # type: ignore[reportAssignmentType]
    metadata: list[NavigatorLinks] | None = field(default_factory=list)  # type: ignore[reportAssignmentType]
    showTacticRowBackground: bool = False
    selectTechniquesAcrossTactics: bool = False
    selectSubtechniquesWithParent: bool = False
    sorting: int = 0
    tacticRowBackground: str = "#dddddd"


def technique_dict() -> dict[str, Any]:
    return {"metadata": [], "links": []}


def sanitize_navigator_name(name: str) -> str:
    """Make a navigator layer name safe as a single-path filename."""
    return name.replace("*", "WILDCARD").replace("/", "-").replace("\\", "-")


def navigator_layer_path(directory: Path, name: str) -> Path:
    """Build a layer JSON path without treating dots in the name as a suffix."""
    return directory / f"{sanitize_navigator_name(name)}.json"


def navigator_layer_label(filename: str) -> str:
    """Display name for a layer file: drop only the final .json suffix."""
    return filename.removesuffix(".json")


def navigator_gist_filename(layer_name: str) -> str:
    """Gist filename for a published navigator layer."""
    return f"Elastic-detection-rules-{sanitize_navigator_name(layer_name)}.json"


def select_navigator_gist_files(directory: Path) -> dict[Path, str]:
    """Return only the navigator layers published to the ATT&CK gist."""
    allowed = {navigator_gist_filename(name) for name in PUBLISHED_NAVIGATOR_LAYERS}
    selected = {path: path.read_text() for path in sorted(directory.glob("*.json")) if path.name in allowed}
    missing = sorted(allowed - {path.name for path in selected})
    if missing:
        raise FileNotFoundError(f"Missing navigator gist layers in {directory}: {', '.join(missing)}")
    return selected


def navigator_tag_layer_key(tag: str) -> str:
    """Layer dict key for a rule tag. Sanitize only when writing filenames."""
    expected_prefixes = {t.split(":")[0] + ":" for t in definitions.EXPECTED_RULE_TAGS}
    stripped = reduce(lambda s, substr: s.replace(substr, ""), expected_prefixes, tag).lstrip()
    return stripped.replace(" ", "-").lower()


class NavigatorBuilder:
    """Rule navigator mappings and management."""

    def __init__(self, detection_rules: list[TOMLRule]) -> None:
        self.detection_rules = detection_rules

        self.layers: dict[str, Any] = {
            "all": defaultdict(lambda: defaultdict(technique_dict)),  # type: ignore[reportUnknownLambdaType]
            "platforms": defaultdict(lambda: defaultdict(technique_dict)),  # type: ignore[reportUnknownLambdaType]
            # these will build multiple layers
            "indexes": defaultdict(lambda: defaultdict(lambda: defaultdict(technique_dict))),  # type: ignore[reportUnknownLambdaType]
            "tags": defaultdict(lambda: defaultdict(lambda: defaultdict(technique_dict))),  # type: ignore[reportUnknownLambdaType]
        }
        self.process_rules()

    @staticmethod
    def meta_dict(name: str, value: Any) -> dict[str, Any]:
        return {"name": name, "value": value}

    @staticmethod
    def links_dict(label: str, url: Any) -> dict[str, Any]:
        return {"label": label, "url": url}

    def rule_links_dict(self, rule: TOMLRule) -> dict[str, Any]:
        """Create a links dictionary for a rule."""
        base_url = "https://github.com/elastic/detection-rules/blob/main/rules/"
        base_path = rule.get_base_rule_dir()

        if not base_path:
            raise ValueError("Could not find a valid base path for the rule")

        base_path_str = str(base_path)
        url = f"{base_url}{base_path_str}"
        return self.links_dict(rule.name, url)

    def get_layer(self, layer_name: str, layer_key: str | None = None) -> dict[str, Any]:
        """Safely retrieve a layer with optional sub-keys."""
        return self.layers[layer_name][layer_key] if layer_key else self.layers[layer_name]

    def _update_all(self, rule: TOMLRule, tactic: str, technique_id: str) -> None:
        value = f"{rule.contents.data.type}/{rule.contents.data.get('language')}"
        self.add_rule_to_technique(rule, "all", tactic, technique_id, value)

    def _update_platforms(self, rule: TOMLRule, tactic: str, technique_id: str) -> None:
        if not rule.path:
            raise ValueError("No rule path found")
        value = rule.path.parent.name
        self.add_rule_to_technique(rule, "platforms", tactic, technique_id, value)

    def _update_indexes(self, rule: TOMLRule, tactic: str, technique_id: str) -> None:
        for index in rule.contents.data.get("index") or []:  # type: ignore[reportUnknownVariableType]
            value = rule.id
            self.add_rule_to_technique(rule, "indexes", tactic, technique_id, value, layer_key=index.lower())  # type: ignore[reportUnknownVariableType]

    def _update_tags(self, rule: TOMLRule, tactic: str, technique_id: str) -> None:
        for _tag in rule.contents.data.get("tags") or []:  # type: ignore[reportUnknownVariableType]
            value = rule.id
            layer_key = navigator_tag_layer_key(_tag)  # type: ignore[reportUnknownArgumentType]
            self.add_rule_to_technique(rule, "tags", tactic, technique_id, value, layer_key=layer_key)

    def add_rule_to_technique(  # noqa: PLR0913, PLR0917
        self,
        rule: TOMLRule,
        layer_name: str,
        tactic: str,
        technique_id: str,
        value: str,
        layer_key: str | None = None,
    ) -> None:
        """Add a rule to a technique metadata and links."""
        layer = self.get_layer(layer_name, layer_key)
        layer[tactic][technique_id]["metadata"].append(self.meta_dict(rule.name, value))
        layer[tactic][technique_id]["links"].append(self.rule_links_dict(rule))

    def process_rule(self, rule: TOMLRule, tactic: str, technique_id: str) -> None:
        self._update_all(rule, tactic, technique_id)
        self._update_platforms(rule, tactic, technique_id)
        self._update_indexes(rule, tactic, technique_id)
        self._update_tags(rule, tactic, technique_id)

    def process_rules(self) -> None:
        """Adds rule to each applicable layer, including multi-layers."""
        for rule in self.detection_rules:
            threat = rule.contents.data.threat
            if threat:
                for entry in threat:
                    tactic = entry.tactic.name.lower()
                    if entry.technique:
                        for technique_entry in entry.technique:
                            technique_id = technique_entry.id
                            self.process_rule(rule, tactic, technique_id)

                            if technique_entry.subtechnique:
                                for sub in technique_entry.subtechnique:
                                    self.process_rule(rule, tactic, sub.id)

    def build_navigator(self, layer_name: str, layer_key: str | None = None) -> Navigator:
        populated_techniques: list[dict[str, Any]] = []
        layer = self.get_layer(layer_name, layer_key)
        base_name = f"{layer_name}-{layer_key}" if layer_key else layer_name
        name = f"Elastic-detection-rules-{sanitize_navigator_name(base_name)}"

        for tactic, techniques in layer.items():
            tactic_normalized = "-".join(tactic.lower().split())
            for technique_id, rules_data in techniques.items():
                rules_data.update(tactic=tactic_normalized, techniqueID=technique_id)
                _techniques = Techniques.from_dict(rules_data)

                populated_techniques.append(_techniques.to_dict())

        base_nav_obj = {
            "name": name,
            "techniques": populated_techniques,
            "versions": {"attack": CURRENT_ATTACK_VERSION},
        }
        return Navigator.from_dict(base_nav_obj)

    def build_all(self, layer_names: tuple[str, ...] | None = None) -> list[Navigator]:
        built: list[Navigator] = []
        layers = {name: self.layers[name] for name in layer_names} if layer_names is not None else self.layers

        for layer_name, data in layers.items():
            # this is a single layer
            if "defense evasion" in data:
                built.append(self.build_navigator(layer_name))
            else:
                # multi layers
                built.extend([self.build_navigator(layer_name, layer_key) for layer_key in data])

        return built

    @staticmethod
    def _save(built: Navigator, directory: Path, verbose: bool = True) -> Path:
        path = navigator_layer_path(directory, built.name)
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_text(json.dumps(built.to_dict(), indent=2))

        if verbose:
            print(f"saved: {path}")
        return path

    def save_layer(
        self,
        layer_name: str,
        directory: Path,
        layer_key: str | None = None,
        verbose: bool = True,
    ) -> tuple[Path, Navigator]:
        built = self.build_navigator(layer_name, layer_key)
        return self._save(built, directory, verbose), built

    def save_all(
        self,
        directory: Path,
        verbose: bool = True,
        layer_names: tuple[str, ...] | None = None,
    ) -> dict[Path, Navigator]:
        paths: dict[Path, Navigator] = {}
        built_layers = self.build_all(layer_names)
        output_names: dict[str, list[str]] = {}
        for built in built_layers:
            filename = navigator_layer_path(directory, built.name).name
            output_names.setdefault(filename, []).append(built.name)

        collisions = {name: originals for name, originals in output_names.items() if len(originals) > 1}
        if collisions:
            details = "; ".join(f"{name} <= {originals}" for name, originals in sorted(collisions.items()))
            raise ValueError(f"Navigator layer filenames collide after sanitization: {details}")

        for built in built_layers:
            path = self._save(built, directory, verbose)
            paths[path] = built

        return paths
