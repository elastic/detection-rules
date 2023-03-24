from . import common
from multiprocessing import Process
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="04361aca-0550-4134-ac21-939bf4a0582f",
    platforms=["macos", "linux"],
    endpoint=[
        {
            "rule_id": "41f1f818-0efe-4670-a2ed-7a4c200dd621",
            "rule_name": "Suspicious Content Extracted or Decompressed via Built-In Utilities",
        }
    ],
    siem=[],
    techniques=["T1059", "T1059.004", "T1027", "T1140"],
)


def test(masquerade, masquerade2):
    common.execute([masquerade2, "childprocess", masquerade, "testnessus_sutest"], timeout=0.3, kill=True)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/funzip"
    masquerade2 = "/tmp/bash"
    if common.CURRENT_OS == "linux":
        source = common.get_path("bin", "linux.ditto_and_spawn")
        common.copy_file(source, masquerade)
        common.copy_file(source, masquerade2)
    else:
        common.create_macos_masquerade(masquerade)
        common.create_macos_masquerade(masquerade2)

    # Execute command
    common.log("Launching fake funzip commands to extract suspicious content")
    processes = []

    for i in range(2):
        p = Process(
            target=test,
            args=(
                masquerade,
                masquerade2,
            ),
        )
        processes.append(p)

    for i in processes:
        i.start()

    for i in processes:
        i.join()

    # cleanup
    common.remove_file(masquerade)
    common.remove_file(masquerade2)


if __name__ == "__main__":
    exit(main())
