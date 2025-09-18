# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cached_property
from multiprocessing.pool import ThreadPool
from typing import Any

import elasticsearch
from elasticsearch import Elasticsearch
from kibana import Kibana  # type: ignore[reportMissingTypeStubs]
from marshmallow import ValidationError
from requests import HTTPError

from .config import load_current_package_version
from .misc import ClientError, get_elasticsearch_client, get_kibana_client, getdefault
from .rule import TOMLRule, TOMLRuleContents
from .rule_validators import ESQLValidator
from .schemas import definitions


@dataclass
class RemoteValidationResult:
    """Dataclass for remote validation results."""

    rule_id: definitions.UUIDString
    rule_name: str
    contents: dict[str, Any]
    rule_version: int
    stack_version: str
    query_results: dict[str, Any]
    engine_results: dict[str, Any]


class RemoteConnector:
    """Base client class for remote validation and testing."""

    MAX_RETRIES = 5

    def __init__(self, parse_config: bool = False, **kwargs: Any) -> None:
        es_args = ["cloud_id", "ignore_ssl_errors", "elasticsearch_url", "es_user", "es_password", "timeout"]
        kibana_args = ["cloud_id", "ignore_ssl_errors", "kibana_url", "api_key", "space"]

        if parse_config:
            es_kwargs = {arg: getdefault(arg)() for arg in es_args}
            kibana_kwargs = {arg: getdefault(arg)() for arg in kibana_args}

            try:
                if "max_retries" not in es_kwargs:
                    es_kwargs["max_retries"] = self.MAX_RETRIES
                self.es_client = get_elasticsearch_client(**es_kwargs, **kwargs)
            except ClientError:
                self.es_client = None

            try:
                self.kibana_client = get_kibana_client(**kibana_kwargs, **kwargs)
            except HTTPError:
                self.kibana_client = None

    def auth_es(  # noqa: PLR0913
        self,
        *,
        cloud_id: str | None = None,
        ignore_ssl_errors: bool | None = None,
        elasticsearch_url: str | None = None,
        es_user: str | None = None,
        es_password: str | None = None,
        timeout: int | None = None,
        **kwargs: Any,
    ) -> Elasticsearch:
        """Return an authenticated Elasticsearch client."""
        if "max_retries" not in kwargs:
            kwargs["max_retries"] = self.MAX_RETRIES
        self.es_client = get_elasticsearch_client(
            cloud_id=cloud_id,
            ignore_ssl_errors=ignore_ssl_errors,
            elasticsearch_url=elasticsearch_url,
            es_user=es_user,
            es_password=es_password,
            timeout=timeout,
            **kwargs,
        )
        return self.es_client

    def auth_kibana(
        self,
        *,
        api_key: str,
        cloud_id: str | None = None,
        kibana_url: str | None = None,
        space: str | None = None,
        ignore_ssl_errors: bool = False,
        **kwargs: Any,
    ) -> Kibana:
        """Return an authenticated Kibana client."""
        self.kibana_client = get_kibana_client(
            cloud_id=cloud_id,
            ignore_ssl_errors=ignore_ssl_errors,
            kibana_url=kibana_url,
            api_key=api_key,
            space=space,
            **kwargs,
        )
        return self.kibana_client


class RemoteValidator(RemoteConnector):
    """Client class for remote validation."""

    def __init__(self, parse_config: bool = False) -> None:
        super().__init__(parse_config=parse_config)

    @cached_property
    def get_validate_methods(self) -> list[str]:
        """Return all validate methods."""
        exempt = ("validate_rule", "validate_rules")
        return [m for m in self.__dir__() if m.startswith("validate_") and m not in exempt]

    def get_validate_method(self, name: str) -> Callable[..., Any]:
        """Return validate method by name."""
        if name not in self.get_validate_methods:
            raise ValueError(f"Validate method {name} not found")
        return getattr(self, name)

    @staticmethod
    def prep_for_preview(contents: TOMLRuleContents) -> dict[str, Any]:
        """Prepare rule for preview."""
        end_time = datetime.now(UTC).isoformat()
        dumped = contents.to_api_format().copy()
        dumped.update(timeframeEnd=end_time, invocationCount=1)
        return dumped

    def engine_preview(self, contents: TOMLRuleContents) -> dict[str, Any]:
        """Get results from detection engine preview API."""
        dumped = self.prep_for_preview(contents)
        if not self.kibana_client:
            raise ValueError("No Kibana client found")
        return self.kibana_client.post("/api/detection_engine/rules/preview", json=dumped)  # type: ignore[reportReturnType]

    def validate_rule(self, contents: TOMLRuleContents) -> RemoteValidationResult:
        """Validate a single rule query."""
        method = self.get_validate_method(f"validate_{contents.data.type}")
        query_results = method(contents)
        engine_results = self.engine_preview(contents)
        rule_version = contents.autobumped_version
        stack_version = load_current_package_version()
        if not rule_version:
            raise ValueError("No rule version found")

        return RemoteValidationResult(
            contents.data.rule_id,
            contents.data.name,
            contents.to_api_format(),
            rule_version,
            stack_version,
            query_results,
            engine_results,
        )

    def validate_rules(self, rules: list[TOMLRule], threads: int = 5) -> dict[str, RemoteValidationResult]:
        """Validate a collection of rules via threads."""
        responses = {}

        def request(c: TOMLRuleContents) -> None:
            try:
                responses[c.data.rule_id] = self.validate_rule(c)
            except ValidationError as e:
                responses[c.data.rule_id] = e.messages  # type: ignore[reportUnknownMemberType]

        pool = ThreadPool(processes=threads)
        _ = pool.map(request, [r.contents for r in rules])
        pool.close()
        pool.join()

        return responses  # type: ignore[reportUnknownVariableType]

    def validate_esql(self, contents: TOMLRuleContents, index_replacement: bool = False) -> dict[str, Any]:
        """Validate query for "esql" rule types. Optionally replace indices and use ESQLValidator."""
        query = contents.data.query  # type: ignore[reportAttributeAccessIssue]
        rule_id = contents.data.rule_id
        if not self.es_client:
            raise ValueError("No ES client found")
        if not self.kibana_client:
            raise ValueError("No Kibana client found")

        if index_replacement:
            try:
                validator = ESQLValidator(contents.data.query)  # type: ignore[reportIncompatibleMethodOverride]
                response = validator.remote_validate_rule_contents(self.kibana_client, self.es_client, contents)
            except Exception as exc:
                if isinstance(exc, elasticsearch.BadRequestError):
                    raise ValidationError(f"ES|QL query failed: {exc} for rule: {rule_id}, query: \n{query}") from exc
                raise Exception(f"ES|QL query failed for rule: {rule_id}, query: \n{query}") from exc  # noqa: TRY002
        else:
            headers = {"accept": "application/json", "content-type": "application/json"}
            body = {"query": f"{query} | LIMIT 0"}
            if not self.es_client:
                raise ValueError("No ES client found")
            try:
                response = self.es_client.perform_request(
                    "POST",
                    "/_query",
                    headers=headers,
                    params={"pretty": True},
                    body=body,
                )
            except Exception as exc:
                if isinstance(exc, elasticsearch.BadRequestError):
                    raise ValidationError(f"ES|QL query failed: {exc} for rule: {rule_id}, query: \n{query}") from exc
                raise Exception(f"ES|QL query failed for rule: {rule_id}, query: \n{query}") from exc  # noqa: TRY002

        return response.body

    def validate_eql(self, contents: TOMLRuleContents) -> dict[str, Any]:
        """Validate query for "eql" rule types."""
        query = contents.data.query  # type: ignore[reportAttributeAccessIssue]
        rule_id = contents.data.rule_id
        index = contents.data.index  # type: ignore[reportAttributeAccessIssue]
        time_range = {"range": {"@timestamp": {"gt": "now-1h/h", "lte": "now", "format": "strict_date_optional_time"}}}
        body: dict[str, Any] = {"query": query}

        if not self.es_client:
            raise ValueError("No ES client found")

        if not index:
            raise ValueError("Indices not found")

        try:
            response = self.es_client.eql.search(index=index, body=body, ignore_unavailable=True, filter=time_range)  # type: ignore[reportUnknownArgumentType]
        except Exception as exc:
            if isinstance(exc, elasticsearch.BadRequestError):
                raise ValidationError(f"EQL query failed: {exc} for rule: {rule_id}, query: \n{query}") from exc
            raise Exception(f"EQL query failed for rule: {rule_id}, query: \n{query}") from exc  # noqa: TRY002

        return response.body

    @staticmethod
    def validate_query(_: Any, __: TOMLRuleContents) -> dict[str, str]:
        """Validate query for "query" rule types."""
        return {"results": "Unable to remote validate query rules"}

    @staticmethod
    def validate_threshold(_: Any, __: TOMLRuleContents) -> dict[str, str]:
        """Validate query for "threshold" rule types."""
        return {"results": "Unable to remote validate threshold rules"}

    @staticmethod
    def validate_new_terms(_: Any, __: TOMLRuleContents) -> dict[str, str]:
        """Validate query for "new_terms" rule types."""
        return {"results": "Unable to remote validate new_terms rules"}

    @staticmethod
    def validate_threat_match(_: Any, __: TOMLRuleContents) -> dict[str, str]:
        """Validate query for "threat_match" rule types."""
        return {"results": "Unable to remote validate threat_match rules"}

    @staticmethod
    def validate_machine_learning(_: Any, __: TOMLRuleContents) -> dict[str, str]:
        """Validate query for "machine_learning" rule types."""
        return {"results": "Unable to remote validate machine_learning rules"}
