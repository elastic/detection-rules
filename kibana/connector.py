# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Wrapper around requests.Session for HTTP requests to Kibana."""
import json
import threading
import base64
import sys
import uuid

from elasticsearch import Elasticsearch
import requests

_context = threading.local()


class Kibana(object):
    """Wrapper around the Kibana SIEM APIs."""

    CACHED = False

    def __init__(self, cloud_id=None, url=None, verify=True, elasticsearch=None, kibana_space=None):
        """"Open a session to the platform."""
        self.authenticated = False
        self.session = requests.Session()
        self.session.verify = verify

        self.cloud_id = cloud_id
        self.kibana_url = url
        self.elastic_url = None
        self.space = kibana_space
        self.status = None

        if self.cloud_id:
            self.cluster_name, cloud_info = self.cloud_id.split(":")
            self.domain, self.es_uuid, self.kibana_uuid = \
                base64.b64decode(cloud_info.encode("utf-8")).decode("utf-8").split("$")

            self.kibana_url = f"https://{self.kibana_uuid}.{self.domain}:9243"
            self.elastic_url = f"https://{self.es_uuid}.{self.domain}:9243"

        self.session.headers.update({'Content-Type': "application/json", "kbn-xsrf": str(uuid.uuid4())})
        self.elasticsearch = elasticsearch

        if self.space:
            self.kibana_url = "{}/s/{}".format(self.url, self.space)

        if not verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    @property
    def version(self):
        """Get the semantic version."""
        if self.status:
            return self.status.get("version", {}).get("number")

    def url(self, uri):
        """Get the full URL given a URI."""
        assert self.kibana_url is not None
        return f"{self.kibana_url}/{uri.lstrip('/')}"

    def request(self, method, uri, params=None, data=None, error=True):
        """Perform a RESTful HTTP request with JSON responses."""
        params = params or {}
        url = self.url(uri)
        params = {k: v for k, v in params.items()}
        body = None
        if data is not None:
            body = json.dumps(data)

        response = self.session.request(method, url, params=params, data=body)
        if error:
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError:
                print(response.content.decode("utf-8"), file=sys.stderr)
                raise

        if not response.content:
            return

        return response.json()

    def get(self, uri, params=None, data=None, error=True):
        """Perform an HTTP GET."""
        return self.request('GET', uri, data=data, params=params, error=error)

    def put(self, uri, params=None, data=None, error=True):
        """Perform an HTTP PUT."""
        return self.request('PUT', uri, params=params, data=data, error=error)

    def post(self, uri, params=None, data=None, error=True):
        """Perform an HTTP POST."""
        return self.request('POST', uri, params=params, data=data, error=error)

    def patch(self, uri, params=None, data=None, error=True):
        """Perform an HTTP PATCH."""
        return self.request('PATCH', uri, params=params, data=data, error=error)

    def delete(self, uri, params=None, error=True):
        """Perform an HTTP DELETE."""
        return self.request('DELETE', uri, params=params, error=error)

    def login(self, username, password):
        """Authenticate to Kibana using the API to update our cookies."""
        payload = {'username': username,  'password': password}
        path = '/internal/security/login'

        self.post(path, data=payload, error=True)
        self.authenticated = True
        self.status = self.get("/api/status")

        # create ES and force authentication
        if self.elasticsearch is None and self.elastic_url is not None:
            self.elasticsearch = Elasticsearch(hosts=[self.elastic_url], http_auth=(username, password))
            self.elasticsearch.info()

        # make chaining easier
        return self

    def logout(self):
        """Quit the current session."""
        # TODO: implement session logout
        self.elasticsearch = None

    def __del__(self):
        if self.authenticated:
            self.logout()

    def __enter__(self):
        """Use the current Kibana instance for ``with`` syntax."""
        if not hasattr(_context, "stack"):
            _context.stack = []

        # Backup the previous Kibana instance and bind the current one
        _context.stack.append(self)
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        """Use the current Kibana for ``with`` syntax."""
        _context.stack.pop()

    @classmethod
    def current(cls) -> 'Kibana':
        """Get the currently used Kibana stack."""
        stack = getattr(_context, "stack", [])
        if len(stack) == 0:
            raise RuntimeError("No Kibana connector in scope!")

        return stack[-1]
