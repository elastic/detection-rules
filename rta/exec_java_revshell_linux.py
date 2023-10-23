# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata

metadata = RtaMetadata(
    uuid="e0db3577-879e-4ac2-bd58-691e1343afca",
    platforms=["linux"],
    endpoint=[{"rule_name": "Potential Linux Reverse Shell via Java", "rule_id": "e0db3577-879e-4ac2-bd58-691e1343afca"}],
    siem=[],
    techniques=["T1059", "T1071"],
)

@common.requires_os(*metadata.platforms)

def main():
  common.log("Creating a fake Java executable..")
  masquerade = "/bin/java"
  source = common.get_path("bin", "netcon_exec_chain.elf")
  common.copy_file(source, masquerade)

  common.log("Granting execute permissions...")
  common.execute(['chmod', '+x', masquerade])

  commands = [
   masquerade,
   'chain',
   '-h',
   '127.0.0.1',
   '-p',
   '1337',
   '-c',
   '-jar'
  ]

  common.log("Simulating reverse shell activity..")
  common.execute([*commands], timeout=5)
  common.log("Reverse shell simulation successful!")
  common.log("Cleaning...")
  common.remove_file(masquerade)
  common.log("RTA completed!")

if __name__ == "__main__":
   exit(main())
