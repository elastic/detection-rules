from detection_rules.rule_loader import RuleCollection
import pyperclip


rules = RuleCollection.default().rules

while True:
    name = input("Insert rule name: ")
    for rule in rules:
        contents = rule.contents
        if name == contents.name:
            threat = rule.contents.data.threat
            technique_ids = []
            for entry in threat:
                tactic = entry.tactic.name
                for technique in entry.technique or []:
                    technique_ids.append(technique.id)
                    technique_ids.extend([st.id for st in technique.subtechnique or []])
            print(technique_ids)
            pyperclip.copy(str(technique_ids))