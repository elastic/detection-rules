# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import datetime
from typing import List, Optional, Type
from uuid import uuid4

import json

from .connector import Kibana
from requests import HTTPError
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
    ) -> tuple[dict, list["RuleResource"]]:
        """Import a list of rules into Kibana using the _import API.

        The helper now returns the full :class:`RuleResource` objects for
        successful imports instead of just the rule IDs.  This makes it easier
        for callers to access the rule names and any other metadata without
        performing additional lookups.  Callers can still derive the IDs from
        the returned resources if needed.
        """
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

        # Successful rule IDs are not returned directly by the API.  We infer
        # them by subtracting the errored IDs from the original list and then
        # fetch the full rule resources for the remaining IDs.
        successful_rule_ids = [r for r in rule_ids if r not in error_rule_ids]
        successful_rules = cls.export_rules(successful_rule_ids) if successful_rule_ids else []
        return response, successful_rules

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
        """Retrieve an exception list by its ``list_id``.

        The API returns ``status_code: 404`` when a list is
        missing, so return ``None`` to make existence checks straightforward.
        It returns the list content without any status_code if found.
        """
        params = {"list_id": list_id, "namespace_type": namespace_type}
        response = Kibana.current().get(cls.BASE_URI, params=params, error=False)
        if not response:
            raise RuntimeError(
                f"Unexpected empty response when fetching exception list {list_id}"
            )
        # If the status_code exists, its either 404 or some other error
        status = response.get("status_code")
        if status == 404:
            # Indicate the list is missing
            return None
        elif status:
            # Raise an HTTPError with status and message (fallback included)
            msg = response.get("message", f"Error querying exception list via API for list_id {list_id}")
            raise HTTPError(f"HTTP {status}: {msg}")
        return response

    @classmethod
    def delete(cls, list_id: str, namespace_type: str = "single") -> None:
        """Delete an exception list. Silently succeed if the list is missing."""
        params = {"list_id": list_id, "namespace_type": namespace_type}
        response = Kibana.current().delete(cls.BASE_URI, params=params, error=False)
        if not response:
            return
        status = response.get("status_code")
        if status == 404:
            # list already missing
            return
        elif status:
            msg = response.get("message", f"Error deleting exception list via API for list_id {list_id}")
            raise HTTPError(f"HTTP {status}: {msg}")


class ValueListResource(BaseResource):
    """Resource for interacting with value list items."""

    BASE_URI = "/api/lists"

    @classmethod
    def get(cls, list_id: str) -> dict | None:
        """Retrieve a value list by ID.

        The API returns a JSON body with ``status_code: 404`` when the list is
        missing. In that case return ``None`` so callers can treat the list as
        nonexistent. Other error status codes raise an HTTPError. If no status
        code is present the list was found and its JSON representation is
        returned.
        """
        response = Kibana.current().get(cls.BASE_URI, params={"id": list_id}, error=False)
        if not response:
            raise RuntimeError(f"Unexpected empty response when fetching value list {list_id}")
        # If the status_code exists, its either 404 or some other error
        status = response.get("status_code")
        if status == 404:
            # Indicate the list is missing
            return None
        if status:
            # Raise an HTTPError with status and message (fallback included)
            msg = response.get("message", f"Error querying value list via API for id {list_id}")
            raise HTTPError(f"HTTP {status}: {msg}")
        return response

    @classmethod
    def delete(cls, list_id: str) -> None:
        """Delete a value list by ID. Silently succeed if the list is missing."""
        response = Kibana.current().delete(cls.BASE_URI, params={"id": list_id}, error=False)
        if not response:
            return
        status = response.get("status_code")
        if status == 404:
            # list already missing
            return
        elif status:
            msg = response.get("message", f"Error deleting value list via API for id {list_id}")
            raise HTTPError(f"HTTP {status}: {msg}")

    @classmethod
    def create_index(cls) -> None:
        """Ensure the value list index exists."""
        response = Kibana.current().post(f"{cls.BASE_URI}/index", error=False)
        if not response:
            raise RuntimeError("Unexpected empty response when creating value list index")
        status = response.get("status_code")
        if status == 409:
            # index already exists
            return
        elif status:
            msg = response.get("message", "Error creating value list index")
            raise HTTPError(f"HTTP {status}: {msg}")

    @classmethod
    def create(cls, list_id: str, list_type: str, name: str | None = None, description: str | None = None) -> dict:
        """Create a value list."""
        payload = {
            "id": list_id,
            "type": list_type,
            "name": name or list_id,
            "description": description or name or list_id,
        }
        response = Kibana.current().post(cls.BASE_URI, data=payload)
        return response

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
        response = Kibana.current().post(
            f"{cls.BASE_URI}/items/_import", params=params, raw_data=body, headers=headers
        )
        if not response:
            raise RuntimeError("Unexpected empty response when importing value list items")
        errors = response.get("errors")
        if not errors:
            # If no errors, the response is the value list
            return response
        # Build a readable error summary from the API response
        if not isinstance(errors, list):
            raise HTTPError("Value list import failed: malformed error response")
        lines = []
        for e in errors:
            e = e or {}
            eid = e.get("id", "<unknown>")
            err = e.get("error") or {}
            msg = err.get("message", "Unknown error")
            code = err.get("status_code", "unknown")
            lines.append(f"{eid}: ({code}) {msg}")
        details = "\n - " + "\n - ".join(lines)
        raise HTTPError(f"Value list import failed with {len(errors)} errors:{details}")

    @classmethod
    def export_list_items(cls, list_id: str) -> str:
        """Export the contents of a value list as newline-delimited text."""
        response = Kibana.current().post(
            f"{cls.BASE_URI}/items/_export", params={"list_id": list_id}, raw=True
        )
        return response.text

    @classmethod
    def find_list_items(cls, list_id: str, *, cursor: str | None = None, per_page: int = 1000) -> dict:
        """Retrieve items from a value list using ``/api/lists/items/_find``.

        Parameters correspond to the REST API. ``cursor`` and ``per_page``
        support paginating through large lists. The response contains a
        ``data`` array and a ``cursor`` for the next page.
        """
        params = {"list_id": list_id, "per_page": per_page}
        if cursor:
            params["cursor"] = cursor
        response = Kibana.current().get(f"{cls.BASE_URI}/items/_find", params=params)
        return response

    @classmethod
    def delete_list_item(cls, item_id: str) -> None:
        """Delete a single value list item by its ``id``. Silently succeed if the item is missing."""
        response = Kibana.current().delete(f"{cls.BASE_URI}/items", params={"id": item_id}, error=False)
        if not response:
            raise RuntimeError(f"Unexpected empty response when deleting value list item {item_id}")
        status = response.get("status_code")
        if status == 404:
            # item already missing
            return
        elif status:
            msg = response.get("message", f"Error deleting value list item via API for id {item_id}")
            raise HTTPError(f"HTTP {status}: {msg}")

    @classmethod
    def delete_list_items(cls, list_id: str) -> None:
        """Remove all items from a value list without deleting the list itself.

        Lists referenced by exception items cannot be deleted outright. When
        overwriting a list we first fetch all existing items and delete them one
        by one to avoid duplicate entries on re-import.
        """
        response = cls.find_list_items(list_id, per_page=10_000)
        for item in response.get("data", []):
            item_id = item.get("id")
            if item_id:
                cls.delete_list_item(item_id)


class TimelineTemplateResource(BaseResource):
    """Resource for managing timeline templates."""

    BASE_URI = "/api/timeline"

    @classmethod
    def get(cls, timeline_id: str) -> dict | None:
        """Retrieve a timeline template by its ``templateTimelineId``.

        Returns ``None`` if the template cannot be found. The API returns
        ``status_code: 404`` when a timeline is missing, so this method
        checks for that and returns ``None``. Other error status codes raise
        a RuntimeError. If no status code is present the timeline was found
        and its JSON representation is returned.
        """

        response = Kibana.current().get(
            cls.BASE_URI, params={"template_timeline_id": timeline_id},
            error=False
        )
        if not response:
            raise RuntimeError(
                f"Unexpected empty response when fetching timeline {timeline_id}"
            )
        status = response.get("status_code")
        if status == 404:
            return None
        elif status:
            raise RuntimeError(
                response.get("message", f"Error querying timeline via API for id {timeline_id}")
            )
        return response

    @classmethod
    def resolve_saved_object_id(cls, timeline_id: str) -> str | None:
        """Resolve the saved object ID for a timeline template by its ``templateTimelineId``.

        The timeline export API requires the saved object ID rather than the
        ``templateTimelineId`` stored on rules. This method queries the
        timeline resolve API to retrieve the saved object ID.
        Returns ``None`` if the timeline cannot be found. The API returns
        ``status_code: 404`` when a timeline is missing, so this method
        checks for that and returns ``None``. Other error status codes raise
        the HTTP error. If no status code is present the timeline was found
        and its saved object ID is returned.
        """

        response = Kibana.current().get(
            f"{cls.BASE_URI}/resolve",
            params={"template_timeline_id": timeline_id},
            error=False
        )
        if not response:
            raise RuntimeError(
                f"Unexpected empty response when resolving timeline {timeline_id}"
            )
        status = response.get("status_code")
        if status == 404:
            return None
        elif status:
            msg = response.get("message", f"Error querying timeline resolve API for id {timeline_id}: {response}")
            raise HTTPError(f"HTTP {status}: {msg}")
        timeline = response.get("timeline") or response.get("data")
        if not timeline:
            raise RuntimeError(f"Malformed response from timeline resolve API for id {timeline_id}: {response}")
        saved_id = timeline.get("savedObjectId")
        return saved_id

    @classmethod
    def export_template(cls, timeline_id: str) -> dict:
        """Export a timeline template referenced by ``timeline_id``.
        The export API requires the saved object ID rather than the
        ``templateTimelineId`` stored on rules. This method first resolves
        the saved object ID and then invokes the export API.
        Raises RuntimeError if the timeline cannot be found.
        Raises HTTPError if the timeline resolve API returns an error status code.
        """
        # Resolve the saved object ID for the timeline template
        saved_id = cls.resolve_saved_object_id(timeline_id)
        if not saved_id:
            raise RuntimeError(f"timeline {timeline_id} missing savedObjectId field")

        # Export the timeline template using the saved object ID
        response = Kibana.current().post(
            f"{cls.BASE_URI}/_export",
            params={"file_name": timeline_id},
            data={"ids": [saved_id]}
        )
        if not response:
            raise RuntimeError(f"Unexpected empty response when exporting timeline {timeline_id}")
        status = response.get("status_code")
        if status:
            msg = response.get("message", f"Error exporting timeline via API for id {timeline_id}")
            raise HTTPError(f"HTTP {status}: {msg}")
        return response

    @classmethod
    def import_template(cls, text: str) -> None:
        """Import a timeline template from its ndjson representation.

        The import API requires ``version`` along with ``created`` and ``updated``
        timestamps.  When these fields are absent (for example when templates
        were exported with stripping options), sensible defaults are supplied so
        the payload is accepted by Kibana.
        """

        payload = json.loads(text)
        payload.setdefault("version", "1")
        payload.setdefault("templateTimelineVersion", 1)
        now_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
        payload.setdefault("created", now_ms)
        payload.setdefault("updated", now_ms)
        headers, raw_data = Kibana.ndjson_file_data_prep([payload], "timeline.ndjson")
        response = Kibana.current().post(f"{cls.BASE_URI}/_import", headers=headers, raw_data=raw_data)
        if not response:
            raise RuntimeError("Unexpected empty response when importing timeline")
        success = bool(response.get("success"))
        if success:
            return None
        # Build a readable error summary from the API response
        errors = response.get("errors") or []
        if not isinstance(errors, list):
            raise HTTPError("Timeline import failed: unexpected error format from API")
        if not errors:
            raise HTTPError("Timeline import failed with no error details provided")
        lines = []
        for e in errors:
            e = e or {}
            eid = e.get("id", "<unknown>")
            err = e.get("error") or {}
            msg = err.get("message", "Unknown error")
            code = err.get("status_code", "unknown")
            lines.append(f"{eid}: ({code}) {msg}")
        details = "\n - " + "\n - ".join(lines)
        raise HTTPError(f"Timeline import failed:{details}")

    @classmethod
    def delete(cls, timeline_id: str) -> None:
        """Delete a timeline template by its ``templateTimelineId``.
        Silently succeed if the template is missing."""

        saved_id = cls.resolve_saved_object_id(timeline_id)
        if not saved_id:
            # timeline already missing
            return
        response = Kibana.current().delete(
            cls.BASE_URI,
            data={"savedObjectIds": [saved_id]},
            error=False
        )
        if not response:
            # Doesnt return anything if successful
            return None
        status = response.get("status_code")
        if status == 404:
            # timeline already missing
            return
        elif status:
            msg = response.get("message", f"Error deleting timeline via API for id {timeline_id}")
            raise HTTPError(f"HTTP {status}: {msg}")


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
