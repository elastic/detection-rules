# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from .. import common
from .. import RtaMetadata

from pathlib import Path

metadata = RtaMetadata(
    uuid="c01971a7-3aa6-4c43-aee6-85d48e93b8c1",
    platforms=["macos"],
    endpoint=[
        {"rule_id": "2ac8ec88-8549-4fcb-9697-5f53e2f78bf4", "rule_name": "Suspicious Terminal Plist Modification"}
    ],
    siem=[],
    techniques=["T1547", "T1547.011"],
)

plist_content = """
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

    common.log("Executing plutil commands to modify plist file.")
    plist = f"{Path.home()}/Library/Preferences/com.apple.Terminal.plist"

    if not Path(plist).exists():
        common.log(f"Creating plist file {plist}")
        Path(plist).write_text(plist_content)
    common.execute(["plutil", "-convert", "xml1", plist])
    common.execute(["plutil", "-convert", "binary1", plist])


if __name__ == "__main__":
    exit(main())
