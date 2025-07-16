# Optional Metadata Dates

Validation of rule TOML files no longer fails if `creation_date` or `updated_date` fields are missing. These values may be stripped during export and should not be required on import.

Implementation updated `RuleMeta` in `detection_rules/rule.py` to make these fields optional and adjusted sorting in `packaging.py` to handle missing dates. Test `test_updated_date_newer_than_creation` now skips rules without date metadata.
