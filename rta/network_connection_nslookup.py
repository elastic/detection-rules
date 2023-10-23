# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="d6c94638-5c8a-40e9-9ad8-86a8f97cc043",
    platforms=["windows"],
    endpoint=[],
    siem=[{'rule_id': '3a59fc81-99d3-47ea-8cd6-d48d561fca20', 'rule_name': 'Potential DNS Tunneling via NsLookup'}],
    techniques=['T1071', 'T1071.004'],
)


@common.requires_os(*metadata.platforms)
def main():
    nslookup = "C:\\Windows\\System32\\nslookup.exe"

    # Execute command 15 times
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)
    common.execute([nslookup, "-q=aaaa", "google.com"], timeout=10)


if __name__ == "__main__":
    exit(main())
