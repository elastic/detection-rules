from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="b2603bac-ba1c-4e6e-a041-ed8772fded75",
    platforms=["linux"],
    endpoint=[
        {"rule_id": "276a5df0-7e20-4218-ade1-3f3ed711d4cb", "rule_name": "Potential Multi Architecture File Downloads"}
    ],
    siem=[],
    techniques=["T1105"],
)


@common.requires_os(*metadata.platforms)
def main():
    masquerade = "/tmp/curl"
    source = common.get_path("bin", "linux.ditto_and_spawn")
    common.copy_file(source, masquerade)

    # Execute command
    common.log("Launching fake commands to mimic multi arch file downloads")
    command = "http://fake/mipsel"

    for i in range(8):
        common.execute([masquerade, command], timeout=0.3, kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
