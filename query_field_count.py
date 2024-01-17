from detection_rules.rule_loader import RuleCollection
from collections import defaultdict
import pprint

# Load the rules
rules = RuleCollection().default()

# Dictionary to store the count of occurrences for each field
field_count = defaultdict(int)

# Iterate over each rule
for rule in rules:
    # Extract required fields for the current rule
    if hasattr(rule.contents.data, "get_required_fields"):
        required_fields = rule.contents.data.get_required_fields("")

        # Count each field occurrence
        if required_fields:
            for field in required_fields:
                field_name = field['name']
                field_count[field_name] += 1

# Convert defaultdict to regular dictionary for final output
sorted_field_count = sorted(field_count.items(), key=lambda x: x[1], reverse=True)

# Pretty print the sorted dictionary
pp = pprint.PrettyPrinter(indent=4)
pp.pprint(sorted_field_count)