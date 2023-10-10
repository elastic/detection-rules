# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="82e913eb-441b-4c93-bad9-6340af0cc71b",
    platforms=["windows"],
    endpoint=[],
    siem=[{
        'rule_id': '68921d85-d0dc-48b3-865f-43291ca2c4f2',
        'rule_name': 'Persistence via TelemetryController Scheduled Task Hijack'
    }],
    techniques=['T1053', 'T1053.005'],
)
EXE_FILE = common.get_path("bin", "renamed_posh.exe")


@common.requires_os(*metadata.platforms)
def main():
    compattelrunner = "C:\\Users\\Public\\compattelrunner.exe"
    child = "C:\\Users\\Public\\child.exe"
    common.copy_file(EXE_FILE, child)
    common.copy_file(EXE_FILE, compattelrunner)

    common.execute([compattelrunner, "/c", child, "echo", "-cv"], timeout=5, kill=True)
    common.remove_files(child, compattelrunner)


if __name__ == "__main__":
    exit(main())
