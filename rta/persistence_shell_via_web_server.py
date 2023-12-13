import os
from . import common
import pathlib
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="884ae75b-d9ed-448c-9267-fb470fffb249",
    platforms=["linux"],
    endpoint=[{"rule_id": "753f83ff-437b-4952-8612-07e3c1327daf", "rule_name": "Potential Shell via Web Server"}],
    siem=[],
    techniques=["T1505", "T1505.003"],
)


@common.requires_os(*metadata.platforms)
def main():
    masquerade = "/tmp/httpd"
    masquerade2 = "/tmp/bash"
    # used only for linux at 2 places to enumerate xargs as parent process.
    working_dir = "/tmp/fake_folder/httpd"
    # Using the Linux binary that simulates parent-> child process in Linux
    source = common.get_path("bin", "linux_ditto_and_spawn_parent_child")
    common.copy_file(source, masquerade)
    common.copy_file(source, masquerade2)
    # In linux the working directory is being projected as parent process.
    # Hence, to simulate the parent process without many changes to execute logic
    # a fake folder structure is created for execution.
    # The execution working directory is changed to the fake folder, to simulate as xargs parent process in Linux.
    pathlib.Path(working_dir).mkdir(parents=True, exist_ok=True)
    os.chdir(working_dir)

    # Execute command
    common.log("Launching fake commands for potential shell via webserver")
    command = f"{masquerade2} pwd"
    common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)
    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)
    common.remove_directory(working_dir)


if __name__ == "__main__":
    exit(main())
