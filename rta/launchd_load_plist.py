# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="17c710a6-9070-4448-b68c-a3694657552e",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Persistence via Suspicious Launch Agent or Launch Daemon",
            "rule_id": "c6037fad-ad13-46a6-9f7f-4deeef5ac69b",
        },
    ],
    siem=[],
    techniques=["T1547", "T1547.011", "T1543", "T1543.001", "T1543.004"],
)

plist = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.example.myapp</string>
    <key>ProgramArguments</key>
    <array>
      <string>bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
  </dict>
</plist>
"""


@common.requires_os(*metadata.platforms)
def main():
    plist_name = "com.test.plist"
    daemon_dir = Path("/", "Library", "LaunchDaemons").expanduser()
    daemon_dir.mkdir(parents=True, exist_ok=True)
    plist_path = str(daemon_dir / plist_name)

    # with common.temporary_file(plist, file_name=plist_path):
    with open(plist_path, "w") as f:
        f.write(plist)
        common.execute(["launchctl", "load", plist_path], kill=True)
        common.execute(["launchctl", "unload", plist_path], kill=True)


if __name__ == "__main__":
    exit(main())
