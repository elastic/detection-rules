# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Create summary documents for a rule package."""

from collections import defaultdict
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Dict, List, Optional
from marshmallow import pre_load

import json

from . import utils
from .attack import CURRENT_ATTACK_VERSION
from .mixins import MarshmallowDataclassMixin
from .rule import TOMLRule


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
    "Windows"
]
_DEFAULT_NAVIGATOR_LINKS = {
    "label": "repo",
    "url": "https://github.com/elastic/detection-rules"
}


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
    metadata: List[NavigatorMetadata]
    links: List[NavigatorLinks]

    color: str = ''
    comment: str = ''
    enabled: bool = True
    showSubtechniques: bool = False

    @pre_load
    def set_score(self, data: dict, **kwargs):
        data['score'] = len(data['metadata'])
        return data


@dataclass
class Navigator(MarshmallowDataclassMixin):
    """ATT&CK navigator class."""
    @dataclass
    class Versions:
        attack: str
        layer: str = '4.3'
        navigator: str = '4.5.5'

    @dataclass
    class Filters:
        platforms: list = field(default_factory=_DEFAULT_PLATFORMS.copy)

    @dataclass
    class Layout:
        layout: str = 'side'
        aggregateFunction: str = 'average'
        showID: bool = True
        showName: bool = True
        showAggregateScores: bool = False
        countUnscored: bool = False

    @dataclass
    class Gradient:
        colors: list = field(default_factory=['#d3e0fa', '#0861fb'].copy)
        minValue: int = 0
        maxValue: int = 10

    # not all defaults set
    name: str
    versions: Versions
    techniques: List[Techniques]

    # all defaults set
    filters: Filters = fields(Filters)
    layout: Layout = fields(Layout)
    gradient: Gradient = fields(Gradient)

    domain: str = 'enterprise-attack'
    description: str = 'Elastic detection-rules coverage'
    hideDisabled: bool = False
    legendItems: list = field(default_factory=list)
    links: List[NavigatorLinks] = field(default_factory=[_DEFAULT_NAVIGATOR_LINKS].copy)
    metadata: Optional[List[NavigatorLinks]] = field(default_factory=list)
    showTacticRowBackground: bool = False
    selectTechniquesAcrossTactics: bool = False
    selectSubtechniquesWithParent: bool = False
    sorting: int = 0
    tacticRowBackground: str = '#dddddd'


def technique_dict() -> dict:
    return {'metadata': [], 'links': []}


class NavigatorBuilder:
    """Rule navigator mappings and management."""

    def __init__(self, detection_rules: List[TOMLRule]):
        self.detection_rules = detection_rules

        self.layers = {
            'all': defaultdict(lambda: defaultdict(technique_dict)),
            'platforms': defaultdict(lambda: defaultdict(technique_dict)),

            # these will build multiple layers
            'indexes': defaultdict(lambda: defaultdict(lambda: defaultdict(technique_dict))),
            'tags': defaultdict(lambda: defaultdict(lambda: defaultdict(technique_dict)))
        }
        self.process_rules()

    @staticmethod
    def meta_dict(name: str, value: any) -> dict:
        meta = {
            'name': name,
            'value': value
        }
        return meta

    @staticmethod
    def links_dict(label: str, url: any) -> dict:
        links = {
            'label': label,
            'url': url
        }
        return links

    def rule_links_dict(self, rule: TOMLRule) -> dict:
        base_url = 'https://github.com/elastic/detection-rules/blob/main/rules/'
        local_rules_path = utils.get_path('rules')
        base_path = rule.path.relative_to(local_rules_path)
        url = f'{base_url}{base_path}'
        return self.links_dict(rule.name, url)

    def get_layer(self, layer_name: str, layer_key: Optional[str] = None) -> dict:
        """Safely retrieve a layer with optional sub-keys."""
        return self.layers[layer_name][layer_key] if layer_key else self.layers[layer_name]

    def _update_all(self, rule: TOMLRule, tactic: str, technique_id: str):
        value = f'{rule.contents.data.type}/{rule.contents.data.get("language")}'
        self.add_rule_to_technique(rule, 'all', tactic, technique_id, value)

    def _update_platforms(self, rule: TOMLRule, tactic: str, technique_id: str):
        value = rule.path.parent.name
        self.add_rule_to_technique(rule, 'platforms', tactic, technique_id, value)

    def _update_indexes(self, rule: TOMLRule, tactic: str, technique_id: str):
        for index in rule.contents.data.get('index', []):
            value = rule.id
            self.add_rule_to_technique(rule, 'indexes', tactic, technique_id, value, layer_key=index.lower())

    def _update_tags(self, rule: TOMLRule, tactic: str, technique_id: str):
        for tag in rule.contents.data.get('tags', []):
            value = rule.id
            layer_key = tag.replace(' ', '-').lower()
            self.add_rule_to_technique(rule, 'tags', tactic, technique_id, value, layer_key=layer_key)

    def add_rule_to_technique(self,
                              rule: TOMLRule,
                              layer_name: str,
                              tactic: str,
                              technique_id: str,
                              value: str,
                              layer_key: Optional[str] = None):
        """Add a rule to a technique metadata and links."""
        layer = self.get_layer(layer_name, layer_key)
        layer[tactic][technique_id]['metadata'].append(self.meta_dict(rule.name, value))
        layer[tactic][technique_id]['links'].append(self.rule_links_dict(rule))

    def process_rule(self, rule: TOMLRule, tactic: str, technique_id: str):
        self._update_all(rule, tactic, technique_id)
        self._update_platforms(rule, tactic, technique_id)
        self._update_indexes(rule, tactic, technique_id)
        self._update_tags(rule, tactic, technique_id)

    def process_rules(self):
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

    def build_navigator(self, layer_name: str, layer_key: Optional[str] = None) -> Navigator:
        populated_techniques = []
        layer = self.get_layer(layer_name, layer_key)
        base_name = f'{layer_name}-{layer_key}' if layer_key else layer_name
        base_name = base_name.replace('*', 'WILDCARD')
        name = f'Elastic-detection-rules-{base_name}'

        for tactic, techniques in layer.items():
            tactic_normalized = '-'.join(tactic.lower().split())
            for technique_id, rules_data in techniques.items():
                rules_data.update(tactic=tactic_normalized, techniqueID=technique_id)
                techniques = Techniques.from_dict(rules_data)

                populated_techniques.append(techniques.to_dict())

        base_nav_obj = {
            'name': name,
            'techniques': populated_techniques,
            'versions': {'attack': CURRENT_ATTACK_VERSION}
        }
        navigator = Navigator.from_dict(base_nav_obj)
        return navigator

    def build_all(self) -> List[Navigator]:
        built = []

        for layer_name, data in self.layers.items():
            # this is a single layer
            if 'defense evasion' in data:
                built.append(self.build_navigator(layer_name))
            else:
                # multi layers
                for layer_key, sub_data in data.items():
                    built.append(self.build_navigator(layer_name, layer_key))

        return built

    @staticmethod
    def _save(built: Navigator, directory: Path, verbose=True) -> Path:
        path = directory.joinpath(built.name).with_suffix('.json')
        path.write_text(json.dumps(built.to_dict(), indent=2))

        if verbose:
            print(f'saved: {path}')
        return path

    def save_layer(self,
                   layer_name: str,
                   directory: Path,
                   layer_key: Optional[str] = None,
                   verbose=True
                   ) -> (Path, dict):
        built = self.build_navigator(layer_name, layer_key)
        return self._save(built, directory, verbose), built

    def save_all(self, directory: Path, verbose=True) -> Dict[Path, Navigator]:
        paths = {}

        for built in self.build_all():
            path = self._save(built, directory, verbose)
            paths[path] = built

        return paths
