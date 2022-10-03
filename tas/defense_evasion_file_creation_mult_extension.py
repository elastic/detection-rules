# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import os


metadata = RtaMetadata(
    uuid="6a53a46a-a7d3-43df-bef3-9fe89582af04",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '8b2b3a62-a598-4293-bc14-3d5fa22bb98f', 'rule_name': 'Executable File Creation with Multiple Extensions'}],
    techniques=[""],
)


@common.requires_os(metadata.platforms)
def main():
    mult_ext = os.path.abspath("mult.jpg.exe")
    with open(mult_ext, 'w'):
        pass
    common.remove_file(mult_ext)


if __name__ == "__main__":
    exit(main())
