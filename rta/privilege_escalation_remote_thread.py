# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import os
import platform

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="e1ff47b2-af5d-4cfc-bd94-e0b86828b241",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "Potential Code Injection via Remote Thread", "rule_id": "458f0b4b-be9a-45bc-8f19-a26dac267250"}
    ],
    siem=[],
    techniques=["T1055"],
)


@common.requires_os(metadata.platforms)
def main():

    if platform.processor() == "arm":
        name = "thread_injector_arm"
        sleep_name = "com.apple.sleep_arm"
    else:
        name = "thread_injector_intel"
        sleep_name = "com.apple.sleep_intel"
    sleep_path = common.get_path("bin", sleep_name)
    os.system(f"{sleep_path} 5000 &")

    path = common.get_path("bin", name)
    os.system(f"{path} `pgrep {sleep_name}`")


if __name__ == "__main__":
    exit(main())
