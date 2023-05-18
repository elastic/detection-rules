# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="44345dc0-883f-41b7-ad34-1d84cfd57129",
    platforms=["macos"],
    endpoint=[],
    siem=[{"rule_name": "Suspicious Calendar File Modification", "rule_id": "cb71aa62-55c8-42f0-b0dd-afb0bb0b1f51"}],
    techniques=["T1546"],
)


@common.requires_os(metadata.platforms)
def main():

    cal_dir = Path(f"{Path.home()}/Library/Calendars/")
    cal_calendar = cal_dir.joinpath("test.calendar", "Events")
    cal_calendar.mkdir(parents=True, exist_ok=True)
    cal_path = str(cal_calendar.joinpath("test.ics"))
    common.log(f"Executing file modification on {cal_path} to mimic suspicious calendar file modification")
    common.temporary_file_helper("testing", file_name=cal_path)

    # cleanup
    common.remove_directory(str(cal_calendar))
    common.remove_directory(str(cal_dir))


if __name__ == "__main__":
    exit(main())
