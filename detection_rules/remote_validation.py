# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from functools import cached_property
from multiprocessing.pool import ThreadPool
from typing import List, Optional

import elasticsearch
from elasticsearch import Elasticsearch
from marshmallow import ValidationError
from requests import HTTPError

from kibana import Kibana

from .misc import ClientError, getdefault, get_elasticsearch_client, get_kibana_client
from .rule import (
    AnyRuleData, ESQLRuleData, QueryRuleData, ThresholdQueryRuleData, ThreatMatchRuleData, MachineLearningRuleData,
    EQLRuleData, NewTermsRuleData, TOMLRule
)


class RemoteConnector:
    """Base client class for remote validation and testing."""

    def __init__(self, parse_config: bool = False):
        es_args = ['cloud_id', 'ignore_ssl_errors', 'elasticsearch_url', 'es_user', 'es_password', 'timeout']
        kibana_args = [
            'cloud_id', 'ignore_ssl_errors', 'kibana_url', 'kibana_user', 'kibana_password', 'space', 'kibana_cookie',
            'provider_type', 'provider_name'
        ]

        if parse_config:
            es_kwargs = {arg: getdefault(arg)() for arg in es_args}
            kibana_kwargs = {arg: getdefault(arg)() for arg in kibana_args}

            try:
                self.es_client = get_elasticsearch_client(**es_kwargs)
            except ClientError:
                self.es_client = None

            try:
                self.kibana_client = get_kibana_client(**kibana_kwargs)
            except HTTPError:
                self.kibana_client = None

    def auth_es(self, *, cloud_id: Optional[str] = None, ignore_ssl_errors: Optional[bool] = None,
                elasticsearch_url: Optional[str] = None, es_user: Optional[str] = None,
                es_password: Optional[str] = None, timeout: Optional[int] = None) -> Elasticsearch:
        """Return an authenticated Elasticsearch client."""
        self.es_client = get_elasticsearch_client(cloud_id=cloud_id, ignore_ssl_errors=ignore_ssl_errors,
                                                  elasticsearch_url=elasticsearch_url, es_user=es_user,
                                                  es_password=es_password, timeout=timeout)
        return self.es_client

    def auth_kibana(self, *, cloud_id: Optional[str] = None, ignore_ssl_errors: Optional[bool] = None,
                    kibana_url: Optional[str] = None, kibana_user: Optional[str] = None,
                    kibana_password: Optional[str] = None, space: Optional[str] = None,
                    kibana_cookie: Optional[str] = None, provider_type: Optional[str] = None,
                    provider_name: Optional[str] = None) -> Kibana:
        """Return an authenticated Kibana client."""
        self.kibana_client = get_kibana_client(cloud_id=cloud_id, ignore_ssl_errors=ignore_ssl_errors,
                                               kibana_url=kibana_url, kibana_user=kibana_user,
                                               kibana_password=kibana_password, space=space,
                                               kibana_cookie=kibana_cookie, provider_type=provider_type,
                                               provider_name=provider_name)
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

    def validate_rule(self, data: AnyRuleData):
        """Validate a single rule query."""
        method = self.get_validate_method(f'validate_{data.type}')
        return method(data)

    def validate_rules(self, rules: List[TOMLRule], threads: int = 50):
        """Validate a collection of rules via threads."""
        responses = {}

        def request(d: AnyRuleData):
            try:
                responses[d.rule_id] = self.validate_rule(d)
            except ValidationError as e:
                responses[d.rule_id] = e.messages

        pool = ThreadPool(processes=threads)
        pool.map(request, [r.contents.data for r in rules])
        pool.close()
        pool.join()

        return responses

    def validate_esql(self, data: ESQLRuleData):
        headers = {"accept": "application/json", "content-type": "application/json"}
        body = {'query': f'{data.query} | LIMIT 0'}
        try:
            response = self.es_client.perform_request('POST', '/_query', headers=headers, params={'pretty': True},
                                                      body=body)
        except elasticsearch.BadRequestError as exc:
            raise ValidationError(f'ES|QL query failed: {exc}')

        return response.body

    def validate_query(self, data: QueryRuleData):
        """Validate query for "query" rule types."""

    def validate_threshold(self, data: ThresholdQueryRuleData):
        """Validate query for "threshold" rule types."""

    def validate_eql(self, data: EQLRuleData):
        """Validate query for "eql" rule types."""

    def validate_new_terms(self, data: NewTermsRuleData):
        """Validate query for "new_terms" rule types."""

    def validate_threat_match(self, data: ThreatMatchRuleData):
        """Validate query for "threat_match" rule types."""

    def validate_machine_learning(self, data: MachineLearningRuleData):
        """Validate query for "machine_learning" rule types."""
        # TODO ???
