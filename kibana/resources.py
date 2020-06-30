# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

from .connector import Kibana
import abc
import datetime
from dataclasses import dataclass, field, fields
from dataclasses_json import dataclass_json, config, DataClassJsonMixin
from typing import List, Optional, Type, TypeVar

DEFAULT_PAGE_SIZE = 10


class DataClassJsonPatch(abc.ABC):
    """Temporary class to hold DataClassJsonMixin that we want to overwrite."""

    def to_dict(self, *args, **kwargs) -> dict:
        return {k: v for k, v in DataClassJsonMixin.to_dict(self, *args, **kwargs).items() if v is not None}


ResourceDataClass = TypeVar('T')


def resource(cls: ResourceDataClass) -> ResourceDataClass:
    cls = dataclass(cls)
    cls = dataclass_json(cls)
    # apparently dataclass_json/DataClassJsonMixin completely overwrites this method upon class construction
    # which is a little weird, because it means you can't define your own to override it.
    # but we want a custom implementation that skips nulls. so we need to overwrite it DataClassJsonPatch.to_dict 
    # overwrite this method, to drop keys set to None
    cls.to_dict = DataClassJsonPatch.to_dict
    return cls


class RestEndpoint:
    BASE_URI = ""


@resource
class BaseResource(RestEndpoint):

    def _update_from(self, other):
        # copy over the attributes from the new one
        if not isinstance(other, BaseResource) and isinstance(other, dict):
            other = self.from_dict(other)

        vars(self).update(vars(other))

    def create(self):
        response = Kibana.current().post(self.BASE_URI, data=self.to_dict())
        self._update_from(response)
        return self

    @classmethod
    def find(cls, per_page=None, **params) -> iter:
        if per_page is None:
            per_page = DEFAULT_PAGE_SIZE

        params.setdefault("sort_field", "_id")
        params.setdefault("sort_order", "asc")

        return ResourceIterator(cls, cls.BASE_URI + "/_find", per_page=per_page, **params)

    @classmethod
    def from_id(cls, resource_id, id_field="id") -> 'BaseResource':
        return Kibana.current().get(cls.BASE_URI, params={id_field: resource_id})

    def update(self):
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
            result = self.cls.from_dict(self.batch[self.batch_pos])
            self.batch_pos += 1
            return result

        raise StopIteration()


@resource
class Rule(BaseResource):
    BASE_URI = "/api/detection_engine/rules"

    description: str
    from_: str = field(metadata=config(field_name="from"))
    interval: str
    name: str
    risk_score: int
    severity: str
    to_: str = field(metadata=config(field_name="to"))
    type_: str = field(metadata=config(field_name="type"))

    enabled: Optional[bool] = None
    filters: Optional[List[dict]] = None
    id: str = None
    language: Optional[str] = None
    rule_id: Optional[str] = None
    tags: Optional[List[str]] = None
    query: Optional[str] = None

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

    def update(self):
        # id and rule_id are mutually exclusive
        rule_id = self.rule_id
        self.rule_id = None

        try:
            # apparently Kibana doesn't like `rule_id` for existing documents
            return super(Rule, self).update()
        except Exception:
            # if it fails, restore the id back
            self.rule_id = rule_id
            raise


class Signal(RestEndpoint):
    BASE_URI = "/api/detection_engine/signals"

    def __init__(self):
        raise NotImplementedError("Signals can't be instantiated yet")

    @classmethod
    def search(cls, query_dsl: dict):
        return Kibana.current().post(f"{cls.BASE_URI}/search", data=query_dsl)

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
    def all(cls):
        return cls.search({"query": {"bool": {"filter": {"match_all": {}}}}})

    @classmethod
    def set_status_many(cls, signal_ids: List[str], status: str) -> dict:
        return Kibana.current().post(f"{cls.BASE_URI}/status", data={"signal_ids": signal_ids, "status": status})

    @classmethod
    def close_many(cls, signal_ids: List[str]):
        return cls.set_status_many(signal_ids, "closed")

    @classmethod
    def open_many(cls, signal_ids: List[str]):
        return cls.set_status_many(signal_ids, "open")
