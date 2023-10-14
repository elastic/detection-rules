# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="0630610d-a9ae-47df-9e2f-e7f393972f1e",
    platforms=["macos"],
    endpoint=[
        {"rule_name": "Execution of Non-Executable File via Shell", "rule_id": "c0770406-7ede-4049-a7a1-999c15fb60bd"}
    ],
    siem=[],
    techniques=["T1036", "T1059", "T1059.004"],
)


@common.requires_os(*metadata.platforms)
def main():

    common.log("Executing bash on unexecutable file.")
    with common.temporary_file("testing", "/*.txt"):
        common.execute(["/bin/bash", "/*.txt"])


if __name__ == "__main__":
    exit(main())
