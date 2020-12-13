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

    def __init__(self, cloud_id=None, kibana_url=None, verify=True, elasticsearch=None, space=None):
        """"Open a session to the platform."""
        self.authenticated = False
        self.session = requests.Session()
        self.session.verify = verify

        self.cloud_id = cloud_id
        self.kibana_url = kibana_url.rstrip('/')
        self.elastic_url = None
        self.space = space if space and space.lower() != 'default' else None
        self.status = None

        if self.cloud_id:
            self.cluster_name, cloud_info = self.cloud_id.split(":")
            self.domain, self.es_uuid, self.kibana_uuid = \
                base64.b64decode(cloud_info.encode("utf-8")).decode("utf-8").split("$")

            kibana_url_from_cloud = f"https://{self.kibana_uuid}.{self.domain}:9243"
            if self.kibana_url and self.kibana_url != kibana_url_from_cloud:
                raise ValueError(f'kibana_url provided ({self.kibana_url}) does not match url derived from cloud_id '
                                 f'{kibana_url_from_cloud}')
            self.kibana_url = kibana_url_from_cloud

            self.elastic_url = f"https://{self.es_uuid}.{self.domain}:9243"

        self.session.headers.update({'Content-Type': "application/json", "kbn-xsrf": str(uuid.uuid4())})
        self.elasticsearch = elasticsearch

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
        # If a space is defined update the URL accordingly
        uri = uri.lstrip('/')
        if self.space:
            uri = "s/{}/{}".format(self.space, uri)
        return f"{self.kibana_url}/{uri}"

    def request(self, method, uri, params=None, data=None, error=True, verbose=True, raw=False, **kwargs):
        """Perform a RESTful HTTP request with JSON responses."""
        params = params or {}
        url = self.url(uri)
        params = {k: v for k, v in params.items()}
        body = None
        if data is not None:
            body = json.dumps(data)

        response = self.session.request(method, url, params=params, data=body, **kwargs)
        if error:
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError:
                if verbose:
                    print(response.content.decode("utf-8"), file=sys.stderr)
                raise

        if not response.content:
            return

        return response.content if raw else response.json()

    def get(self, uri, params=None, data=None, error=True, **kwargs):
        """Perform an HTTP GET."""
        return self.request('GET', uri, data=data, params=params, error=error, **kwargs)

    def put(self, uri, params=None, data=None, error=True, **kwargs):
        """Perform an HTTP PUT."""
        return self.request('PUT', uri, params=params, data=data, error=error, **kwargs)

    def post(self, uri, params=None, data=None, error=True, **kwargs):
        """Perform an HTTP POST."""
        return self.request('POST', uri, params=params, data=data, error=error, **kwargs)

    def patch(self, uri, params=None, data=None, error=True, **kwargs):
        """Perform an HTTP PATCH."""
        return self.request('PATCH', uri, params=params, data=data, error=error, **kwargs)

    def delete(self, uri, params=None, error=True, **kwargs):
        """Perform an HTTP DELETE."""
        return self.request('DELETE', uri, params=params, error=error, **kwargs)

    def login(self, kibana_username, kibana_password):
        """Authenticate to Kibana using the API to update our cookies."""
        payload = {'username': kibana_username, 'password': kibana_password}
        path = '/internal/security/login'

        try:
            self.post(path, data=payload, error=True, verbose=False)
        except requests.HTTPError as e:
            # 7.10 changed the structure of the auth data
            if e.response.status_code == 400 and '[undefined]' in e.response.text:
                payload = {'params': payload, 'currentURL': '', 'providerType': 'basic', 'providerName': 'cloud-basic'}
                self.post(path, data=payload, error=True)
            else:
                raise

        # Kibana will authenticate against URLs which contain invalid spaces
        if self.space:
            self.verify_space(self.space)

        self.authenticated = True
        self.status = self.get("/api/status")

        # create ES and force authentication
        if self.elasticsearch is None and self.elastic_url is not None:
            self.elasticsearch = Elasticsearch(hosts=[self.elastic_url], http_auth=(kibana_username, kibana_password))
            self.elasticsearch.info()

        # make chaining easier
        return self

    def add_cookie(self, cookie):
        """Add cookie to be used for auth (such as from an SSO session)."""
        # the request to /api/status will also add the cookie to the cookie jar upon a successful response
        self.session.headers['cookie'] = cookie
        self.status = self.get('/api/status')
        self.authenticated = True

    def logout(self):
        """Quit the current session."""
        try:
            self.get('/logout', raw=True, error=False)
        except requests.exceptions.ConnectionError:
            # for really short scoping from buildup to teardown, ES will cause a Max retry error
            pass
        self.status = None
        self.authenticated = False
        self.session = requests.Session()
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

    def verify_space(self, space):
        """Verify a space is valid."""
        spaces = self.get('/api/spaces/space')
        space_names = [s['name'] for s in spaces]
        if space not in space_names:
            raise ValueError(f'Unknown Kibana space: {space}')

    def current_user(self):
        """Retrieve info for currently authenticated user."""
        if self.authenticated:
            return self.get('/internal/security/me')
