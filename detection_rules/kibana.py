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
        res = requests.get(f"{self.url}/api/task_manager/_health", headers=self.headers)
        res.raise_for_status()
        return res.json()

    def ping(self):
        try:
            self.task_manager_health()
            return True
        except requests.exceptions.ConnectionError:
            return False

    def create_siem_index(self):
        url = f"{self.url}/api/detection_engine/index"
        res = requests.post(url, headers=self.headers)
        res.raise_for_status()
        return res.json()

    def create_detection_engine_rule(self, rule):
        url = f"{self.url}/api/detection_engine/rules"
        res = requests.post(url, headers=self.headers, data=json.dumps(rule))
        res.raise_for_status()
        return res.json()

    def delete_detection_engine_rule(self, rule):
        url = f"{self.url}/api/detection_engine/rules?id={rule['id']}"
        res = requests.delete(url, headers=self.headers)
        res.raise_for_status()
        return res.json()

    def find_detection_engine_rules(self):
        url = f"{self.url}/api/detection_engine/rules/_find?per_page=1000"
        res = requests.get(url, headers=self.headers)
        res.raise_for_status()
        return {rule["id"]: rule for rule in res.json()["data"]}

    def create_detection_engine_rules(self, rules):
        url = f"{self.url}/api/detection_engine/rules/_bulk_create"
        res = requests.post(url, headers=self.headers, data=json.dumps(rules))
        res.raise_for_status()
        return {rule["id"]: rule for rule in res.json()}

    def delete_detection_engine_rules(self, rules=None):
        if rules is None:
            rules = self.find_detection_engine_rules()
        rules = [{"id": rule} for rule in rules]
        url = f"{self.url}/api/detection_engine/rules/_bulk_delete"
        res = requests.delete(url, headers=self.headers, data=json.dumps(rules))
        res.raise_for_status()
        return res.json()

    def find_detection_engine_rules_statuses(self, rules=None):
        if rules is None:
            rules = self.find_detection_engine_rules()
        rules = {"ids": list(rules)}
        url = f"{self.url}/api/detection_engine/rules/_find_statuses?per_page=1000"
        res = requests.post(url, headers=self.headers, data=json.dumps(rules))
        res.raise_for_status()
        return res.json()

    def search_detection_engine_signals(self, body):
        url = f"{self.url}/api/detection_engine/signals/search"
        res = requests.post(url, headers=self.headers, data=json.dumps(body))
        res.raise_for_status()
        return res.json()
