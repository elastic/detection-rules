# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import datetime
from typing import List, Optional, Type
from uuid import uuid4

import json

from .connector import Kibana
from . import definitions

DEFAULT_PAGE_SIZE = 10


class BaseResource(dict):
    BASE_URI = ""
    ID_FIELD = "id"

    @property
    def id(self):
        return self.get(self.ID_FIELD)

    @classmethod
    def bulk_create_legacy(cls, resources: list):
        for r in resources:
            assert isinstance(r, cls)

        # _bulk_create is being deprecated. Leave for backwards compat only
        # the new API would be import with multiple rules within an ndjson request
        responses = Kibana.current().post(cls.BASE_URI + "/_bulk_create", data=resources)
        return [cls(r) for r in responses]

    def create(self):
        response = Kibana.current().post(self.BASE_URI, data=self)
        self.update(response)
        return self

    @classmethod
    def find(cls, per_page=None, **params) -> iter:
        if per_page is None:
            per_page = DEFAULT_PAGE_SIZE

        # _id is no valid sort field so we sort by name by default
        params.setdefault("sort_field", "name")
        params.setdefault("sort_order", "asc")

        return ResourceIterator(cls, cls.BASE_URI + "/_find", per_page=per_page, **params)

    @classmethod
    def from_id(cls, resource_id) -> 'BaseResource':
        return Kibana.current().get(cls.BASE_URI, params={cls.ID_FIELD: resource_id})

    def put(self):
        response = Kibana.current().put(self.BASE_URI, data=self.to_dict())
        self._update_from(response)
        return self

    def delete(self):
        return Kibana.current().delete(self.BASE_URI, params={"id": self.id})


class ResourceIterator(object):

    def __init__(self, cls: Type[BaseResource], uri: str, per_page: int, **params: dict):
        self.cls = cls
        self.uri = uri
        self.params = params
        self.page = 0
        self.per_page = per_page
        self.fetched = 0
        self.current = None
        self.total = None
        self.batch = []
        self.batch_pos = 0
        self.kibana = Kibana.current()

    def __iter__(self):
        return self

    def _batch(self):
        params = dict(per_page=self.per_page, page=self.page + 1, **self.params)
        response = self.kibana.get(self.uri, params=params, error=True)

        self.page = response["page"]
        self.per_page = response["perPage"]
        self.total = response["total"]
        self.batch = response["data"]
        self.batch_pos = 0
        self.fetched += len(self.batch)

    def __next__(self) -> BaseResource:
        if self.total is None or 0 < self.batch_pos == len(self.batch) == self.per_page:
            self._batch()

        if self.batch_pos < len(self.batch):
            result = self.cls(self.batch[self.batch_pos])
            self.batch_pos += 1
            return result

        raise StopIteration()


class RuleResource(BaseResource):
    BASE_URI = "/api/detection_engine/rules"

    @staticmethod
    def _add_internal_filter(is_internal: bool, params: dict) -> dict:
        custom_filter = f'alert.attributes.tags:"__internal_immutable:{str(is_internal).lower()}"'
        if params.get("filter"):
            params["filter"] = f"({params['filter']}) and ({custom_filter})"
        else:
            params["filter"] = custom_filter
        return params

    @classmethod
    def find_custom(cls, **params):
        params = cls._add_internal_filter(False, params)
        return cls.find(**params)

    @classmethod
    def find_elastic(cls, **params):
        # GET params:
        # * `sort_field`
        # * `sort_order`
        # * `filter` (accepts KQL)
        #       alert.attributes.name:mshta
        #       alert.attributes.enabled:true/false
        #
        # ...
        # i.e. Rule.find_elastic(filter="alert.attributes.name:mshta")
        params = cls._add_internal_filter(True, params)
        return cls.find(**params)

    @classmethod
    def bulk_action(
        cls, action: definitions.RuleBulkActions, rule_ids: Optional[List[str]] = None, query: Optional[str] = None,
        dry_run: Optional[bool] = False, edit_object: Optional[list[definitions.RuleBulkEditActionTypes]] = None,
        include_exceptions: Optional[bool] = False, **kwargs
    ) -> dict | List['RuleResource']:
        """Perform a bulk action on rules using the _bulk_action API."""
        assert not (rule_ids and query), 'Cannot provide both rule_ids and query'

        if action == 'edit':
            assert edit_object, 'edit action requires edit object'

        duplicate = {'include_exceptions': include_exceptions, 'include_expired_exceptions': False}

        params = dict(dry_run=stringify_bool(dry_run))
        data = dict(action=action, edit=edit_object, duplicate=duplicate)
        if query:
            data['query'] = query
        elif rule_ids:
            data['rule_ids'] = rule_ids
        response = Kibana.current().post(cls.BASE_URI + "/_bulk_action", params=params, data=data, **kwargs)

        # export returns ndjson
        if action == 'export':
            response = [cls(r) for r in [json.loads(r) for r in response.text.splitlines()]]

        return response

    @classmethod
    def bulk_enable(
        cls, rule_ids: Optional[List[str]] = None, query: Optional[str] = None, dry_run: Optional[bool] = False
    ) -> (dict, List['RuleResource']):
        """Bulk enable rules using _bulk_action."""
        return cls.bulk_action("enable", rule_ids=rule_ids, query=query, dry_run=dry_run)

    @classmethod
    def bulk_disable(
        cls, rule_ids: Optional[List[str]] = None, query: Optional[str] = None, dry_run: Optional[bool] = False
    ) -> (dict, List['RuleResource']):
        """Bulk disable rules using _bulk_action."""
        return cls.bulk_action("disable", rule_ids=rule_ids, query=query, dry_run=dry_run)

    @classmethod
    def bulk_delete(
        cls, rule_ids: Optional[List[str]] = None, query: Optional[str] = None, dry_run: Optional[bool] = False
    ) -> (dict, List['RuleResource']):
        """Bulk delete rules using _bulk_action."""
        return cls.bulk_action("delete", rule_ids=rule_ids, query=query, dry_run=dry_run)

    @classmethod
    def bulk_duplicate(
        cls, rule_ids: Optional[List[str]] = None, query: Optional[str] = None, dry_run: Optional[bool] = False,
        include_exceptions: Optional[bool] = False
    ) -> (dict, List['RuleResource']):
        """Bulk duplicate rules using _bulk_action."""
        return cls.bulk_action("duplicate", rule_ids=rule_ids, query=query, dry_run=dry_run,
                               include_exceptions=include_exceptions)

    @classmethod
    def bulk_export(
        cls, rule_ids: Optional[List[str]] = None, query: Optional[str] = None
    ) -> (dict, List['RuleResource']):
        """Bulk export rules using _bulk_action."""
        return cls.bulk_action("export", rule_ids=rule_ids, query=query, raw=True)

    @classmethod
    def bulk_edit(
        cls, edit_object: list[definitions.RuleBulkEditActionTypes], rule_ids: Optional[List[str]] = None,
        query: Optional[str] = None, dry_run: Optional[bool] = False
    ) -> (dict, List['RuleResource']):
        """Bulk edit rules using _bulk_action."""
        # setting to error=False because the API returns a 500 with any failures, but includes the success data as well
        return cls.bulk_action(
            "edit", rule_ids=rule_ids, query=query, dry_run=dry_run, edit_object=edit_object, error=False
        )

    def put(self):
        # id and rule_id are mutually exclusive
        rule_id = self.get("rule_id")
        self.pop("rule_id", None)

        try:
            # apparently Kibana doesn't like `rule_id` for existing documents
            return super(RuleResource, self).update()
        except Exception:
            # if it fails, restore the id back
            if rule_id:
                self["rule_id"] = rule_id

            raise

    @classmethod
    def import_rules(
        cls,
        rules: List[dict],
        exceptions: List[List[dict]] = [],
        action_connectors: List[List[dict]] = [],
        overwrite: bool = False,
        overwrite_exceptions: bool = False,
        overwrite_action_connectors: bool = False,
    ) -> (dict, list, List[Optional["RuleResource"]]):
        """Import a list of rules into Kibana using the _import API and return the response and successful imports."""
        url = f'{cls.BASE_URI}/_import'
        params = dict(
            overwrite=stringify_bool(overwrite),
            overwrite_exceptions=stringify_bool(overwrite_exceptions),
            overwrite_action_connectors=stringify_bool(overwrite_action_connectors),
        )
        # add missing ids for exceptions_list entries to satisfy the Kibana API
        for rule in rules:
            for exc in rule.get("exceptions_list", []):
                exc.setdefault("id", str(uuid4()))

        rule_ids = [r['rule_id'] for r in rules]
        flattened_exceptions = [e for sublist in exceptions for e in sublist]
        flattened_actions_connectors = [a for sublist in action_connectors for a in sublist]
        headers, raw_data = Kibana.ndjson_file_data_prep(
            rules + flattened_exceptions + flattened_actions_connectors, "import.ndjson"
        )
        response = Kibana.current().post(url, headers=headers, params=params, raw_data=raw_data)
        errors = response.get("errors", [])
        error_rule_ids = [e['rule_id'] for e in errors]

        # successful rule_ids are not returned, so they must be implicitly inferred from errored rule_ids
        successful_rule_ids = [r for r in rule_ids if r not in error_rule_ids]
        rule_resources = cls.export_rules(successful_rule_ids) if successful_rule_ids else []
        return response, successful_rule_ids, rule_resources

    @classmethod
    def export_rules(cls, rule_ids: Optional[List[str]] = None,
                     exclude_export_details: bool = True) -> List['RuleResource']:
        """Export a list of rules from Kibana using the _export API."""
        url = f'{cls.BASE_URI}/_export'

        if rule_ids:
            rule_ids = {'objects': [{'rule_id': r} for r in rule_ids]}
        else:
            rule_ids = None

        params = dict(exclude_export_details=stringify_bool(exclude_export_details))
        response = Kibana.current().post(url, params=params, data=rule_ids, raw=True)
        data = [json.loads(r) for r in response.text.splitlines()]
        return [cls(r) for r in data]


class ExceptionListResource(BaseResource):
    """Resource for managing exception lists."""

    BASE_URI = "/api/exception_lists"

    @classmethod
    def get(cls, list_id: str, namespace_type: str = "single") -> dict | None:
        """Retrieve an exception list by ``list_id``.

        The API returns ``status_code: 404`` in the body when a list is
        missing, so return ``None`` to make existence checks straightforward.
        """
        params = {"list_id": list_id, "namespace_type": namespace_type}
        response = Kibana.current().get(cls.BASE_URI, params=params, error=False)
        if not response:
            return None
        status_code = response.get("status_code") or response.get("statusCode")
        if status_code == 404:
            return None
        return response

    @classmethod
    def delete(cls, list_id: str, namespace_type: str = "single") -> None:
        """Delete an exception list."""
        params = {"list_id": list_id, "namespace_type": namespace_type}
        Kibana.current().delete(cls.BASE_URI, params=params, error=False)


class ValueListResource(BaseResource):
    """Resource for interacting with value list items."""

    BASE_URI = "/api/lists"

    @classmethod
    def get(cls, list_id: str) -> dict | None:
        """Retrieve a value list by ID.

        The API returns a JSON body with ``status_code: 404`` when the list is
        missing, even though ``error=False`` suppresses HTTP errors. In that
        case return ``None`` so callers can treat the list as nonexistent.
        """
        response = Kibana.current().get(cls.BASE_URI, params={"id": list_id}, error=False)
        if not response:
            return None
        status_code = response.get("status_code") or response.get("statusCode")
        if status_code == 404:
            return None
        return response

    @classmethod
    def delete(cls, list_id: str) -> None:
        """Delete a value list by ID."""
        Kibana.current().delete(cls.BASE_URI, params={"id": list_id}, error=False)

    @classmethod
    def create_index(cls) -> None:
        """Ensure the value list index exists."""
        Kibana.current().post(f"{cls.BASE_URI}/index", error=False)

    @classmethod
    def create(cls, list_id: str, list_type: str, name: str | None = None, description: str | None = None) -> dict:
        """Create a value list."""
        payload = {
            "id": list_id,
            "type": list_type,
            "name": name or list_id,
            "description": description or name or list_id,
        }
        return Kibana.current().post(cls.BASE_URI, data=payload)

    @classmethod
    def import_list_items(cls, list_id: str, text: str, list_type: str) -> dict:
        """Import newline-delimited items into an existing value list.

        The `/api/lists/items/_import` endpoint only adds items to a list that
        already exists and will not implicitly create the list. Callers must
        ensure the value list (and its backing index) are created before
        invoking this helper.
        """
        boundary = "----ElasticBoundary"
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"file\"; filename=\"{list_id}\"\r\n"
            "Content-Type: text/plain\r\n\r\n"
            f"{text}\r\n--{boundary}--\r\n"
        ).encode("utf-8")
        headers = {"content-type": f"multipart/form-data; boundary={boundary}"}
        params = {"list_id": list_id, "type": list_type}
        return Kibana.current().post(
            f"{cls.BASE_URI}/items/_import", params=params, raw_data=body, headers=headers
        )

    @classmethod
    def export_list_items(cls, list_id: str) -> str:
        """Export the contents of a value list as newline-delimited text."""
        response = Kibana.current().post(
            f"{cls.BASE_URI}/items/_export", params={"list_id": list_id}, raw=True
        )
        return response.text


class Signal(BaseResource):
    BASE_URI = "/api/detection_engine/signals"

    def __init__(self):
        raise NotImplementedError("Signals can't be instantiated yet")

    @classmethod
    def search(cls, query_dsl: dict, size: Optional[int] = 10):
        payload = dict(size=size, **query_dsl)
        return Kibana.current().post(f"{cls.BASE_URI}/search", data=payload)

    @classmethod
    def last_signal(cls) -> (int, datetime.datetime):
        query_dsl = {
            "aggs": {
                "lastSeen": {"max": {"field": "@timestamp"}}
            },
            'query': {
                "bool": {
                    "filter": [
                        {"match": {"signal.status": "open"}}
                    ]
                }
            },
            "size": 0,
            "track_total_hits": True
        }
        response = cls.search(query_dsl)
        last_seen = response.get("aggregations", {}).get("last_seen", {}).get("value_as_string")
        num_signals = response.get("hits", {}).get("total", {}).get("value")

        if last_seen is not None:
            last_seen = datetime.datetime.strptime(last_seen, "%Y-%m-%dT%H:%M:%S.%f%z")

        return num_signals, last_seen

    @classmethod
    def all(cls, size: Optional[int] = 10):
        return cls.search({"query": {"bool": {"filter": {"match_all": {}}}}}, size=size)

    @classmethod
    def set_status_many(cls, signal_ids: List[str], status: str) -> dict:
        return Kibana.current().post(f"{cls.BASE_URI}/status", data={"signal_ids": signal_ids, "status": status})

    @classmethod
    def close_many(cls, signal_ids: List[str]):
        return cls.set_status_many(signal_ids, "closed")

    @classmethod
    def open_many(cls, signal_ids: List[str]):
        return cls.set_status_many(signal_ids, "open")


def stringify_bool(obj: bool) -> str:
    """Convert a boolean to a string."""
    assert isinstance(obj, bool), f"Expected a boolean, got {type(obj)}"
    return str(obj).lower()
