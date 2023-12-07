# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1d452f81-8f5a-44a3-ae95-e95fe4bf2762",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '4630d948-40d4-4cef-ac69-4002e29bc3db', 'rule_name': 'Adding Hidden File Attribute via Attrib'}],
    techniques=['T1564', 'T1564.001'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    attrib = "C:\\Users\\Public\\attrib.exe"
    common.copy_file(EXE_FILE, attrib)

    # Execute command
    common.execute([attrib, "/c", "echo", "+h"], timeout=10)
    common.remove_file(attrib)


if __name__ == "__main__":
    exit(main())
