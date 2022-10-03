from detection_rules.rule_loader import RuleCollection
import uuid
import pyperclip as pc

rules = RuleCollection.default()

while True:
    name = input("Insert rule name: ")
    
    siem = {
        "rule_id": "",
        "rule_name": ""
    }
    
    for rule in rules:
        contents = rule.contents
        if name == contents.name:
            siem["rule_name"] = contents.name
            siem["rule_id"] = contents.id
    
    metadata2 = f"""
metadata = RtaMetadata(
    uuid="{uuid.uuid4()}",
    platforms=["windows"],
    endpoint=[],
    siem=[{siem}],
    techniques=[""],
)
"""
    print(metadata2)
    pc.copy(metadata2)