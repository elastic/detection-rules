# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
from pathlib import Path


metadata = RtaMetadata(
    uuid="12e70377-e24e-4374-8aec-42064614d706",
    platforms=["macos"],
    endpoint=[
        {
            "rule_name": "Suspicious Property List File Creation or Modification",
            "rule_id": "901f0c30-a7c5-40a5-80e3-a50c6714432f",
        }
    ],
    siem=[],
    techniques=["T1547", "T1543"],
)


@common.requires_os(metadata.platforms)
def main():
    launch_agents_dir = Path.home() / "Library" / "Launchagents"
    plistbuddy_bin = "/usr/libexec/PlistBuddy"
    plist_file = Path.home() / "Library" / "Launchagents" / "init_verx.plist"

    # Create launch agents dir if it doesn't exist
    if not launch_agents_dir.exists():
        common.log(f"Creating directory {launch_agents_dir}")
        launch_agents_dir.mkdir()

    # Create plist file using Plistbuddy
    common.log("Executing PlistBuddy commands to create plist file")
    common.execute(
        [f"{plistbuddy_bin}", "-c", "Add :Label string init_verx", f"{plist_file}"],
        shell=True,
    )
    common.pause()
    common.execute([f"{plistbuddy_bin}", "-c", "Add :RunAtLoad bool true", f"{plist_file}"])
    common.pause()
    common.execute([f"{plistbuddy_bin}", "-c", "Add :StartInterval integer 3600", f"{plist_file}"])
    common.pause()
    common.execute([f"{plistbuddy_bin}", "-c", "Add :ProgramArguments array", f"{plist_file}"])
    common.pause()
    common.execute(
        [
            f"{plistbuddy_bin}",
            "-c",
            "Add :ProgramArguments:0 string '/bin/sh'",
            f"{plist_file}",
        ]
    )
    common.pause()
    common.execute(
        [
            f"{plistbuddy_bin}",
            "-c",
            "Add :ProgramArguments:1 string -c",
            f"{plist_file}",
        ]
    )

    # Delete the plist file if it exists
    if plist_file.exists():
        common.log(f"Deleting plist file {plist_file}")
        plist_file.unlink()


if __name__ == "__main__":
    exit(main())
