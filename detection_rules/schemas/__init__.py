from .base import TomlMetadata
from .rta_schema import validate_rta_mapping
from ..semver import Version

# import all of the schema versions
from .v78 import ApiSchema78
from .v79 import ApiSchema79

__all__ = (
    "all_schemas",
    "downgrade",
    "CurrentSchema",
    "validate_rta_mapping",
    "TomlMetadata",
)

all_schemas = [
    ApiSchema78,
    ApiSchema79,
]

CurrentSchema = max(all_schemas, key=lambda cls: Version(cls.STACK_VERSION))


def downgrade(api_contents, target_version):
    """Downgrade a rule to a target stack version."""
    # truncate to (major, minor)
    target_version = Version(target_version)[:2]
    versions = set(Version(schema_cls.STACK_VERSION) for schema_cls in all_schemas)
    role = api_contents.get("type")

    check_versioned = "version" in api_contents

    if target_version not in versions:
        raise ValueError(f"Unable to downgrade from {CurrentSchema.STACK_VERSION} to {target_version}")

    current_schema = None

    for target_schema in reversed(all_schemas):
        if check_versioned:
            target_schema = target_schema.versioned()

        if current_schema is not None:
            api_contents = current_schema.downgrade(target_schema, api_contents, role)

        current_schema = target_schema
        if Version(current_schema.STACK_VERSION) == target_version:
            break

    return api_contents
