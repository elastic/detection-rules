# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from dataclasses import dataclass
from datetime import datetime
from functools import cached_property
from multiprocessing.pool import ThreadPool
from typing import Dict, List, Optional

import elasticsearch
from elasticsearch import Elasticsearch
from marshmallow import ValidationError
from requests import HTTPError

from kibana import Kibana

from .misc import ClientError, getdefault, get_elasticsearch_client, get_kibana_client, load_current_package_version
from .rule import TOMLRule, TOMLRuleContents
from .schemas import definitions


@dataclass
class RemoteValidationResult:
    """Dataclass for remote validation results."""
    rule_id: definitions.UUIDString
    rule_name: str
    contents: dict
    rule_version: int
    stack_version: str
    query_results: Optional[dict]
    engine_results: Optional[dict]


class RemoteConnector:
    """Base client class for remote validation and testing."""

    MAX_RETRIES = 5

    def __init__(self, parse_config: bool = False, **kwargs):
        es_args = ['cloud_id', 'ignore_ssl_errors', 'elasticsearch_url', 'es_user', 'es_password', 'timeout']
        kibana_args = [
            'cloud_id', 'ignore_ssl_errors', 'kibana_url', 'kibana_user', 'kibana_password', 'space', 'kibana_cookie',
            'provider_type', 'provider_name'
        ]

        if parse_config:
            es_kwargs = {arg: getdefault(arg)() for arg in es_args}
            kibana_kwargs = {arg: getdefault(arg)() for arg in kibana_args}

            try:
                if 'max_retries' not in es_kwargs:
                    es_kwargs['max_retries'] = self.MAX_RETRIES
                self.es_client = get_elasticsearch_client(**es_kwargs, **kwargs)
            except ClientError:
                self.es_client = None

            try:
                self.kibana_client = get_kibana_client(**kibana_kwargs, **kwargs)
            except HTTPError:
                self.kibana_client = None

    def auth_es(self, *, cloud_id: Optional[str] = None, ignore_ssl_errors: Optional[bool] = None,
                elasticsearch_url: Optional[str] = None, es_user: Optional[str] = None,
                es_password: Optional[str] = None, timeout: Optional[int] = None, **kwargs) -> Elasticsearch:
        """Return an authenticated Elasticsearch client."""
        if 'max_retries' not in kwargs:
            kwargs['max_retries'] = self.MAX_RETRIES
        self.es_client = get_elasticsearch_client(cloud_id=cloud_id, ignore_ssl_errors=ignore_ssl_errors,
                                                  elasticsearch_url=elasticsearch_url, es_user=es_user,
                                                  es_password=es_password, timeout=timeout, **kwargs)
        return self.es_client

    def auth_kibana(self, *, cloud_id: Optional[str] = None, ignore_ssl_errors: Optional[bool] = None,
                    kibana_url: Optional[str] = None, kibana_user: Optional[str] = None,
                    kibana_password: Optional[str] = None, space: Optional[str] = None,
                    kibana_cookie: Optional[str] = None, provider_type: Optional[str] = None,
                    provider_name: Optional[str] = None, **kwargs) -> Kibana:
        """Return an authenticated Kibana client."""
        self.kibana_client = get_kibana_client(cloud_id=cloud_id, ignore_ssl_errors=ignore_ssl_errors,
                                               kibana_url=kibana_url, kibana_user=kibana_user,
                                               kibana_password=kibana_password, space=space,
                                               kibana_cookie=kibana_cookie, provider_type=provider_type,
                                               provider_name=provider_name, **kwargs)
        return self.kibana_client


class RemoteValidator(RemoteConnector):
    """Client class for remote validation."""

    def __init__(self, parse_config: bool = False):
        super(RemoteValidator, self).__init__(parse_config=parse_config)

    @cached_property
    def get_validate_methods(self) -> List[str]:
        """Return all validate methods."""
        exempt = ('validate_rule', 'validate_rules')
        methods = [m for m in self.__dir__() if m.startswith('validate_') and m not in exempt]
        return methods

    def get_validate_method(self, name: str) -> callable:
        """Return validate method by name."""
        assert name in self.get_validate_methods, f'validate method {name} not found'
        return getattr(self, name)

    @staticmethod
    def prep_for_preview(contents: TOMLRuleContents) -> dict:
        """Prepare rule for preview."""
        end_time = datetime.utcnow().isoformat()
        dumped = contents.to_api_format().copy()
        dumped.update(timeframeEnd=end_time, invocationCount=1)
        return dumped

    def engine_preview(self, contents: TOMLRuleContents) -> dict:
        """Get results from detection engine preview API."""
        dumped = self.prep_for_preview(contents)
        return self.kibana_client.post('/api/detection_engine/rules/preview', json=dumped)

    def validate_rule(self, contents: TOMLRuleContents) -> RemoteValidationResult:
        """Validate a single rule query."""
        method = self.get_validate_method(f'validate_{contents.data.type}')
        query_results = method(contents)
        engine_results = self.engine_preview(contents)
        rule_version = contents.autobumped_version
        stack_version = load_current_package_version()
        return RemoteValidationResult(contents.data.rule_id, contents.data.name, contents.to_api_format(),
                                      rule_version, stack_version, query_results, engine_results)

    def validate_rules(self, rules: List[TOMLRule], threads: int = 5) -> Dict[str, RemoteValidationResult]:
        """Validate a collection of rules via threads."""
        responses = {}

        def request(c: TOMLRuleContents):
            try:
                responses[c.data.rule_id] = self.validate_rule(c)
            except ValidationError as e:
                responses[c.data.rule_id] = e.messages

        pool = ThreadPool(processes=threads)
        pool.map(request, [r.contents for r in rules])
        pool.close()
        pool.join()

        return responses

    def validate_esql(self, contents: TOMLRuleContents) -> dict:
        query = contents.data.query
        rule_id = contents.data.rule_id
        headers = {"accept": "application/json", "content-type": "application/json"}
        body = {'query': f'{query} | LIMIT 0'}
        try:
            response = self.es_client.perform_request('POST', '/_query', headers=headers, params={'pretty': True},
                                                      body=body)
        except Exception as exc:
            if isinstance(exc, elasticsearch.BadRequestError):
                raise ValidationError(f'ES|QL query failed: {exc} for rule: {rule_id}, query: \n{query}')
            else:
                raise Exception(f'ES|QL query failed for rule: {rule_id}, query: \n{query}') from exc

        return response.body

    def validate_eql(self, contents: TOMLRuleContents) -> dict:
        """Validate query for "eql" rule types."""
        query = contents.data.query
        rule_id = contents.data.rule_id
        index = contents.data.index
        time_range = {"range": {"@timestamp": {"gt": 'now-1h/h', "lte": 'now', "format": "strict_date_optional_time"}}}
        body = {'query': query}
        try:
            response = self.es_client.eql.search(index=index, body=body, ignore_unavailable=True, filter=time_range)
        except Exception as exc:
            if isinstance(exc, elasticsearch.BadRequestError):
                raise ValidationError(f'EQL query failed: {exc} for rule: {rule_id}, query: \n{query}')
            else:
                raise Exception(f'EQL query failed for rule: {rule_id}, query: \n{query}') from exc

        return response.body

    @staticmethod
    def validate_query(self, contents: TOMLRuleContents) -> dict:
        """Validate query for "query" rule types."""
        return {'results': 'Unable to remote validate query rules'}

    @staticmethod
    def validate_threshold(self, contents: TOMLRuleContents) -> dict:
        """Validate query for "threshold" rule types."""
        return {'results': 'Unable to remote validate threshold rules'}

    @staticmethod
    def validate_new_terms(self, contents: TOMLRuleContents) -> dict:
        """Validate query for "new_terms" rule types."""
        return {'results': 'Unable to remote validate new_terms rules'}

    @staticmethod
    def validate_threat_match(self, contents: TOMLRuleContents) -> dict:
        """Validate query for "threat_match" rule types."""
        return {'results': 'Unable to remote validate threat_match rules'}

    @staticmethod
    def validate_machine_learning(self, contents: TOMLRuleContents) -> dict:
        """Validate query for "machine_learning" rule types."""
        return {'results': 'Unable to remote validate machine_learning rules'}
