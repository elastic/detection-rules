# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Load generic toml formatted files for exceptions and actions."""
import io
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Union

import pytoml

from .action import TOMLAction, TOMLActionContents
from .config import parse_rules_config
from .exception import TOMLException, TOMLExceptionContents
from .rule_loader import dict_filter
from .schemas import definitions


RULES_CONFIG = parse_rules_config()

GenericCollectionTypes = Union[TOMLAction, TOMLException]
GenericCollectionContentTypes = Union[TOMLActionContents, TOMLExceptionContents]


def metadata_filter(**metadata) -> Callable[[GenericCollectionTypes], bool]:
    """Get a filter callback based off item metadata"""
    flt = dict_filter(metadata)

    def callback(item: GenericCollectionTypes) -> bool:
        target_dict = item.contents.metadata.to_dict()
        return flt(target_dict)

    return callback


class GenericCollection:
    """Generic collection for action and exception objects."""

    items: list
    __default = None

    def __init__(self, items: Optional[List[GenericCollectionTypes]] = None):
        self.id_map: Dict[definitions.UUIDString, GenericCollectionTypes] = {}
        self.file_map: Dict[Path, GenericCollectionTypes] = {}
        self.name_map: Dict[definitions.RuleName, GenericCollectionTypes] = {}
        self.items: List[GenericCollectionTypes] = []
        self.errors: Dict[Path, Exception] = {}
        self.frozen = False

        self._toml_load_cache: Dict[Path, dict] = {}

        for items in (items or []):
            self.add_item(items)

    def __len__(self) -> int:
        """Get the total amount of exceptions in the collection."""
        return len(self.items)

    def __iter__(self) -> Iterable[GenericCollectionTypes]:
        """Iterate over all items in the collection."""
        return iter(self.items)

    def __contains__(self, item: GenericCollectionTypes) -> bool:
        """Check if an item is in the map by comparing IDs."""
        return item.id in self.id_map

    def filter(self, cb: Callable[[TOMLException], bool]) -> 'GenericCollection':
        """Retrieve a filtered collection of items."""
        filtered_collection = GenericCollection()

        for item in filter(cb, self.items):
            filtered_collection.add_item(item)

        return filtered_collection

    @staticmethod
    def deserialize_toml_string(contents: Union[bytes, str]) -> dict:
        """Deserialize a TOML string into a dictionary."""
        return pytoml.loads(contents)

    def _load_toml_file(self, path: Path) -> dict:
        """Load a TOML file into a dictionary."""
        if path in self._toml_load_cache:
            return self._toml_load_cache[path]

        # use pytoml instead of toml because of annoying bugs
        # https://github.com/uiri/toml/issues/152
        # might also be worth looking at https://github.com/sdispater/tomlkit
        with io.open(path, "r", encoding="utf-8") as f:
            toml_dict = self.deserialize_toml_string(f.read())
            self._toml_load_cache[path] = toml_dict
            return toml_dict

    def _get_paths(self, directory: Path, recursive=True) -> List[Path]:
        """Get all TOML files in a directory."""
        return sorted(directory.rglob('*.toml') if recursive else directory.glob('*.toml'))

    def _assert_new(self, item: GenericCollectionTypes) -> None:
        """Assert that the item is new and can be added to the collection."""
        id_map = self.id_map
        file_map = self.file_map
        name_map = self.name_map

        assert not self.frozen, f"Unable to add item {item.name} {item.id} to a frozen collection"
        assert item.id not in id_map, \
            f"Rule ID {item.id} for {item.name} collides with rule {id_map.get(item.id).name}"
        assert item.name not in name_map, \
            f"Rule Name {item.name} for {item.id} collides with rule ID {name_map.get(item.name).id}"

        if item.path is not None:
            item_path = item.path.resolve()
            assert item_path not in file_map, f"Item file {item_path} already loaded"
            file_map[item_path] = item

    def add_item(self, item: GenericCollectionTypes) -> None:
        """Add a new item to the collection."""
        self._assert_new(item)
        self.id_map[item.id] = item
        self.name_map[item.name] = item
        self.items.append(item)

    def load_dict(self, obj: dict, path: Optional[Path] = None) -> GenericCollectionTypes:
        """Load a dictionary into the collection."""
        is_exception = True if 'exceptions' in obj else False
        if not RULES_CONFIG.bypass_version_lock:
            # remove version and revision fields if bypassing version lock
            obj.pop('version', None)

        contents = TOMLExceptionContents.from_dict(obj) if is_exception else TOMLActionContents.from_dict(obj)
        item = TOMLException(path=path, contents=contents)
        self.add_item(item)
        return item

    def load_file(self, path: Path) -> GenericCollectionTypes:
        """Load a single file into the collection."""
        try:
            path = path.resolve()

            # use the default generic loader as a cache.
            # if it already loaded the item, then we can just use it from that
            if self.__default is not None and self is not self.__default:
                if path in self.__default.file_map:
                    item = self.__default.file_map[path]
                    self.add_item(item)
                    return item

            obj = self._load_toml_file(path)
            return self.load_dict(obj, path=path)
        except Exception:
            print(f"Error loading item in {path}")
            raise

    def load_files(self, paths: Iterable[Path]) -> None:
        """Load multiple files into the collection."""
        for path in paths:
            self.load_file(path)

    def load_directory(
        self, directory: Path, recursive=True, toml_filter: Optional[Callable[[dict], bool]] = None
    ) -> None:
        """Load all TOML files in a directory."""
        paths = self._get_paths(directory, recursive=recursive)
        if toml_filter is not None:
            paths = [path for path in paths if toml_filter(self._load_toml_file(path))]

        self.load_files(paths)

    def load_directories(
        self, directories: Iterable[Path], recursive=True, toml_filter: Optional[Callable[[dict], bool]] = None
    ) -> None:
        """Load all TOML files in multiple directories."""
        for path in directories:
            self.load_directory(path, recursive=recursive, toml_filter=toml_filter)

    def freeze(self) -> None:
        """Freeze the generic collection and make it immutable going forward."""
        self.frozen = True

    @classmethod
    def default(cls) -> 'GenericCollection':
        """Return the default item collection, which retrieves from default config location."""
        if cls.__default is None:
            collection = GenericCollection()
            if RULES_CONFIG.exception_dir:
                collection.load_directory(RULES_CONFIG.exception_dir)
            if RULES_CONFIG.action_dir:
                collection.load_directory(RULES_CONFIG.action_dir)
            collection.freeze()
            cls.__default = collection

        return cls.__default
