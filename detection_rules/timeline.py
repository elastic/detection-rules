# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Dataclasses for timeline templates."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytoml  # type: ignore[reportMissingTypeStubs]

from .mixins import MarshmallowDataclassMixin
from .schemas import definitions


@dataclass(frozen=True)
class TimelineTemplateMeta(MarshmallowDataclassMixin):
    """Metadata stored in a timeline template's ``[metadata]`` section."""

    # Every template has a unique ``templateTimelineId`` value that is used by
    # rules.  We keep this value so that loaders and CLI utilities can map the
    # TOML representation back to the correct template on disk.
    timeline_template_id: definitions.UUIDString
    # The exported payload also contains a human friendly title.  Storing the
    # title in the metadata allows quick inspection of the file without parsing
    # the full template dictionary.
    timeline_template_title: str
    # These fields are optional when exporting with ``--strip-dates``.  They are
    # included here so that templates can preserve their creation and update
    # times when desired.
    creation_date: definitions.Date | None = None
    updated_date: definitions.Date | None = None


@dataclass(frozen=True)
class TOMLTimelineTemplateContents(MarshmallowDataclassMixin):
    """Object for timeline template contents from a TOML file."""

    metadata: TimelineTemplateMeta
    # The timeline itself is stored as an arbitrary mapping.  The dictionary is
    # round-tripped back to JSON when importing into Kibana, therefore it keeps
    # all fields returned by the export API.
    timeline: dict[str, Any]

    @classmethod
    def from_timeline_dict(
        cls,
        timeline_dict: dict[str, Any],
        strip_dates: bool = False,
    ) -> "TOMLTimelineTemplateContents":
        """Create contents from a Kibana export dictionary."""

        # Extract the required identifiers from the exported payload.  The
        # ``templateTimelineId`` field is mandatory for timeline templates.
        timeline_id = timeline_dict.get("templateTimelineId")
        if not timeline_id:
            raise ValueError("timeline template missing templateTimelineId field")
        title = timeline_dict.get("title", f"Timeline {timeline_id}")

        # Build the metadata block for the TOML representation.  When dates are
        # available and not explicitly stripped we convert the millisecond epoch
        # values to the ``YYYY/MM/DD`` format used throughout the repository.
        metadata: dict[str, Any] = {
            "timeline_template_id": timeline_id,
            "timeline_template_title": title,
        }
        if not strip_dates:
            created = timeline_dict.get("created")
            updated = timeline_dict.get("updated")
            if isinstance(created, int):
                metadata["creation_date"] = datetime.fromtimestamp(created / 1000, UTC).strftime("%Y/%m/%d")
            if isinstance(updated, int):
                metadata["updated_date"] = datetime.fromtimestamp(updated / 1000, UTC).strftime("%Y/%m/%d")

        return cls.from_dict({"metadata": metadata, "timeline": timeline_dict})

    def to_api_format(self) -> dict[str, Any]:
        """Convert the TOML representation back to the Kibana API format."""

        # The API expects the raw timeline dictionary.  No additional processing
        # is required here because the resource helper ensures that any missing
        # fields are populated with defaults.
        return self.timeline


@dataclass(frozen=True)
class TOMLTimelineTemplate:
    """Object for a timeline template stored as TOML."""

    contents: TOMLTimelineTemplateContents
    path: Path

    @property
    def name(self) -> str:
        """Return a human friendly name for the template."""

        return self.contents.metadata.timeline_template_title

    @property
    def id(self) -> definitions.UUIDString:
        """Expose the template's identifier used by rules."""

        return self.contents.metadata.timeline_template_id

    def save_toml(self) -> None:
        """Serialize the template to its TOML file on disk."""

        if not self.path:
            raise ValueError(f"Can't save timeline template for {self.name} without a path")
        path = self.path
        # Ensure the file has a ``.toml`` suffix so that the generic loader can
        # discover it automatically.
        if path.suffix != ".toml":
            path = path.with_suffix(".toml")
        with path.open("w") as f:
            contents_dict = self.contents.to_dict()
            # Sort the dictionary so that the metadata block is written first.
            sorted_dict = dict(sorted(contents_dict.items(), key=lambda item: item[0] != "metadata"))
            pytoml.dump(sorted_dict, f)  # type: ignore[reportUnknownMemberType]
