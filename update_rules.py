import json
import requests
import toml
import os
from uuid import uuid4

kbnuser = os.environ["DR_KIBANA_USER"]
kbnpwd = os.environ["DR_KIBANA_PASSWORD"]
kburl = os.environ["DR_KIBANA_URL"]

def create_rules(createbody, kbnuser,kbnpwd):
    resp = requests.post(
        url="{}/api/detection_engine/rules/_bulk_create".format(kburl),
        json=createbody,
        headers={
            "Content-Type": "application/json",
            "kbn-xsrf": str(uuid4())
        },
        auth=(kbnuser,kbnpwd)
    )
    print(resp)
    for response in resp.json():
        failure = False
        try:
            if response["statusCode"] in range(400, 599):
                response["statusCode"]
                print(resp.json())
                print("=====================================================================")
                print(createbody)
                failure = True
            if failure:
                raise ValueError("Failed to create rule")
        except Exception as err:
            print("Exception: {}".format(err))
            raise ValueError("Failed to create rule")

custom_rules = []
# Get all the custom rules; aka those prefixed with your custom path prefix
for root, dirs, files in os.walk("rules/"):
    for file in files:
        if root.startswith("rules/custom"):
             custom_rules.append(os.path.join(root, file))

# read in toml
toml_rules = []
print(custom_rules)
for rulefile in custom_rules:
    try:
      with open(rulefile, "r") as f:
          rule = f.read()
          t_rule = toml.loads(rule)
          toml_rules.append(t_rule)
    except Exception as err:
        print("Failed to parse {} with error: {}".format(rulefile, err))

updatebody = []
for r in toml_rules:
    rule = r["rule"]
    if "rule_id" not in rule:
        continue
    else:
        updatebody.append(rule)

# bulk request to update
resp = requests.put(
    url="{}/api/detection_engine/rules/_bulk_update".format(kburl),
    json=updatebody,
    headers={
        "Content-Type": "application/json",
        "kbn-xsrf": str(uuid4())
    },
    auth=(kbnuser,kbnpwd)
)
response = resp.json()

if "error" in response:
    print(response["message"])
    exit(1)

createbody = []

for rule_resp in resp.json():
    try:
        if "error" in rule_resp and "not found" in rule_resp["error"]["message"]:
            print(rule_resp["error"]["message"])
            # find rule in body and create the rule
            for r in updatebody:
                if r["rule_id"] in rule_resp["error"]["message"]:
                    createbody.append(r)
    except TypeError:
        print(rule_resp)

created = False
while not created:
    try:
        create_rules(createbody, kbnuser, kbnpwd)
    except Exception:
        pass
    else:
        created = True
