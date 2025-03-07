import glob
import os
import pytoml as toml
import pandas as pd

# List to store file paths and rule IDs
data = []

# Iterate over all TOML files in the directory and its subdirectories
for file in glob.glob('rules/**/*.toml', recursive=True):
    # Load the TOML file
    print(f"Processing {file}")
    try:
        with open(file, 'r') as f:
            toml_data = toml.load(f)
        
        # Extract the rule ID
        rule_id = toml_data.get('rule', {}).get('rule_id', None)
        
        # Append the file path and rule ID to the list
        if rule_id:
            data.append({'file_path': file, 'rule_id': rule_id})
    except (toml.TomlError, IndexError) as e:
        print(f"Error processing {file}: {e}")

# Create a pandas DataFrame from the list
df = pd.DataFrame(data)

# Write the DataFrame to a CSV file
df.to_csv('rules_with_ids.csv', index=False)

print("CSV file 'rules_with_ids.csv' has been created.")

