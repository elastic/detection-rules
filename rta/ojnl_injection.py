from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="b48a9dd2-8fe7-41e1-9af2-65f609a54237",
    platforms=["linux"],
    endpoint=[
        {
            "rule_id": "8fff17c6-f0ba-4996-bcc3-342a9ebd0ef3",
            "rule_name": "Remote Code Execution via Confluence OGNL Injection",
        }
    ],
    siem=[],
    techniques=["T1190"],
)


@common.requires_os(*metadata.platforms)
def main():
    masquerade = "/tmp/confluence/jre/fake/java"
    masquerade2 = "/tmp/bash"
    # Using the Linux binary that simulates parent-> child process in Linux
    source = common.get_path("bin", "linux_ditto_and_spawn_parent_child")
    common.copy_file(source, masquerade)
    common.copy_file(source, masquerade2)

    # Execute command
    common.log("Launching fake commands for Remote Code Execution via Confluence")
    command = f"{masquerade2} date"
    common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
