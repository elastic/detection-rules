# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Wrapper around requests.Session for HTTP requests to Kibana."""
import atexit
import base64
import json
import os
import sys
import threading
import uuid
from importlib import metadata
from typing import List, Optional, Union

import requests
from elasticsearch import Elasticsearch

_context = threading.local()

# Environment variable that, when set to a truthy value, disables the custom
# User-Agent header on outbound Kibana requests. When disabled, no additional
# User-Agent string is sent and the underlying ``requests`` default applies.
USER_AGENT_DISABLE_ENV = "DR_USER_AGENT_DISABLED"

# Static product name identifying requests originating from detection-rules
# (the CLI and the library share this id; we don't distinguish between them).
USER_AGENT_PRODUCT = "detection-rules"


def _get_dist_version(dist: str) -> Optional[str]:
    """Best-effort lookup of an installed distribution version."""
    try:
        return metadata.version(dist)
    except metadata.PackageNotFoundError:
        return None


def _env_disables_user_agent() -> bool:
    """Return True when the disable env var is set to a truthy value."""
    value = os.environ.get(USER_AGENT_DISABLE_ENV, "")
    return value.strip().lower() in ("1", "true", "yes", "on")


def build_user_agent(user_agent: Optional[str] = None) -> Optional[str]:
    """Build the User-Agent for outbound Kibana requests, or None when disabled."""
    if _env_disables_user_agent():
        return None
    if user_agent:
        return user_agent
    from . import __version__

    kibana_version = _get_dist_version("detection-rules-kibana") or __version__
    dr_version = _get_dist_version("detection_rules")
    if dr_version:
        return f"{USER_AGENT_PRODUCT}/{dr_version} (DaC; kibana-lib {kibana_version})"
    return f"{USER_AGENT_PRODUCT}/{kibana_version}"


class Kibana:
    """Wrapper around the Kibana SIEM APIs."""

    def __init__(self, cloud_id=None, kibana_url=None, api_key=None, verify=True, elasticsearch=None, space=None,
                 user_agent=None):
        """"Open a session to the platform."""
        self.authenticated = False

        # Resolve the User-Agent once so it can be re-applied if the session is
        # recreated (e.g. on logout). ``None`` means no custom header is sent.
        self.user_agent = build_user_agent(user_agent)

        self.session = requests.Session()
        self.session.verify = verify
        self._set_user_agent()

        if api_key:
            self.session.headers.update(
                {
                    "kbn-xsrf": "true",
                    "Authorization": f"ApiKey {api_key}",
                }
            )

        self.verify = verify

        self.cloud_id = cloud_id
        self.kibana_url = kibana_url.rstrip('/') if kibana_url else None
        self.elastic_url = None
        self.space = space if space and space.lower() != 'default' else None
        self.status = None

        if self.cloud_id:
            self.cluster_name, cloud_info = self.cloud_id.split(":")
            self.domain, self.es_uuid, self.kibana_uuid = \
                base64.b64decode(cloud_info.encode("utf-8")).decode("utf-8").split("$")

            if self.domain.endswith(':443'):
                self.domain = self.domain[:-4]

            kibana_url_from_cloud = f"https://{self.kibana_uuid}.{self.domain}:9243"
            if self.kibana_url and self.kibana_url != kibana_url_from_cloud:
                raise ValueError(
                    f'kibana_url provided ({self.kibana_url}) does not match url derived from cloud_id '
                    f'{kibana_url_from_cloud}'
                )
            self.kibana_url = kibana_url_from_cloud
            self.elastic_url = f"https://{self.es_uuid}.{self.domain}:9243"

        self.session.headers.update({'Content-Type': "application/json", "kbn-xsrf": str(uuid.uuid4())})
        self.elasticsearch = elasticsearch

        if not self.elasticsearch and self.elastic_url:
            self.elasticsearch = Elasticsearch(
                hosts=[self.elastic_url],
                api_key=api_key,
                verify_certs=self.verify,
            )
            self.elasticsearch.info()

        if not verify:
            from requests.packages.urllib3.exceptions import \
                InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        atexit.register(self.__close)

    def _set_user_agent(self):
        """Apply the custom User-Agent header to the current session, if set."""
        if self.user_agent:
            self.session.headers.update({"User-Agent": self.user_agent})

    @property
    def version(self):
        """Get the semantic version."""
        if self.status:
            return self.status.get("version", {}).get("number")

    @staticmethod
    def ndjson_file_data_prep(lines: List[dict], filename: str) -> tuple[dict, str]:
        """Prepare a request for an ndjson file upload to Kibana."""
        data = ('\n'.join(json.dumps(r) for r in lines) + '\n')
        boundary = '----JustAnotherBoundary'
        bounded_data = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                        f'Content-Type: application/x-ndjson\r\n\r\n{data}\r\n--{boundary}--\r\n').encode('utf-8')
        headers = {'content-type': f'multipart/form-data; boundary={boundary}'}
        return headers, bounded_data

    def url(self, uri):
        """Get the full URL given a URI."""
        assert self.kibana_url is not None
        # If a space is defined update the URL accordingly
        uri = uri.lstrip('/')
        if self.space:
            uri = "s/{}/{}".format(self.space.lower(), uri)
        return f"{self.kibana_url}/{uri}"

    def request(self, method, uri, params=None, data=None, raw_data=None, error=True, verbose=True, raw=False,
                **kwargs) -> Optional[Union[requests.Response, dict]]:
        """Perform a RESTful HTTP request with JSON responses."""
        url = self.url(uri)
        params = params or {}
        body = json.dumps(data) if data is not None else None
        assert not (body and raw_data), "Cannot provide both data and raw_data"

        body = body or raw_data

        response = self.session.request(method, url, params=params, data=body, **kwargs)

        if response.status_code != 200:
            # retry once
            response = self.session.request(method, url, params=params, data=body, **kwargs)

        if error:
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError:
                if response.status_code == 404:
                    raise NotImplementedError(f'API endpoint {uri} not implemented for Kibana version {self.version}')
                if verbose:
                    print(response.content.decode("utf-8"), file=sys.stderr)
                raise

        if not response.content:
            return

        return response if raw else response.json()

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
        self._set_user_agent()
        self.elasticsearch = None

    def __close(self):
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
        space_names = [s['id'] for s in spaces]
        if space not in space_names:
            raise ValueError(f'Unknown Kibana space: {space}')

    def current_user(self):
        """Retrieve info for currently authenticated user."""
        if self.authenticated:
            return self.get('/internal/security/me')
