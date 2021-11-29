# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Helper class for Kibana REST API."""

import requests
import json

class Kibana:
    def __init__(self, url):
        self.url = url
        self.headers = {"kbn-xsrf": "true"}

    def task_manager_health(self):
        return requests.get(f"{self.url}/api/task_manager/_health", headers=self.headers)

    def create_siem_index(self):
        return requests.post(f"{self.url}/api/detection_engine/index", headers=self.headers)

    def create_detection_engine_rule(self, rule):
        return requests.post(f"{self.url}/api/detection_engine/rules", headers=self.headers, data=json.dumps(rule))

    def delete_detection_engine_rule(self, rule):
        return requests.delete(f"{self.url}/api/detection_engine/rules?id={rule['id']}", headers=self.headers)

    def find_detection_engine_rules(self):
        return requests.get(f"{self.url}/api/detection_engine/rules/_find", headers=self.headers)

    def create_detection_engine_rules(self, rules):
        return requests.post(f"{self.url}/api/detection_engine/rules/_bulk_create", headers=self.headers, data=json.dumps(rules))

    def delete_detection_engine_rules(self, rules=None):
        if rules is None:
            res = self.find_detection_engine_rules()
            if res.status_code != 200:
                return res
            rules = res.json()["data"]
        rules = [{"id": rule["id"]} for rule in rules]
        return requests.delete(f"{self.url}/api/detection_engine/rules/_bulk_delete", headers=self.headers, data=json.dumps(rules))
