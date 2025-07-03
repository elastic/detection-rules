# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Misc support."""

import os
import re
import time
import unittest
import uuid
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import IO, Any, NoReturn

import click
import requests
from elasticsearch import AuthenticationException, Elasticsearch
from kibana import Kibana  # type: ignore[reportMissingTypeStubs]

from .utils import add_params, cached, load_etc_dump

LICENSE_HEADER = """
Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
or more contributor license agreements. Licensed under the Elastic License
2.0; you may not use this file except in compliance with the Elastic License
2.0.
""".strip()

LICENSE_LINES = LICENSE_HEADER.splitlines()
PYTHON_LICENSE = "\n".join("# " + line for line in LICENSE_LINES)
JS_LICENSE = """
/*
{}
 */
""".strip().format("\n".join(" * " + line for line in LICENSE_LINES))


ROOT_DIR = Path(__file__).parent.parent


class ClientError(click.ClickException):
    """Custom CLI error to format output or full debug stacktrace."""

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        super().__init__(message)
        self.original_error = original_error
        self.original_error_type = type(original_error).__name__ if original_error else ""

    def show(self, file: IO[Any] | None = None, err: bool = True) -> None:
        """Print the error to the console."""
        msg = f"{click.style(f'CLI Error ({self.original_error_type})', fg='red', bold=True)}: {self.format_message()}"
        click.echo(msg, err=err, file=file)


def raise_client_error(  # noqa: PLR0913
    message: str,
    exc: Exception | None = None,
    debug: bool | None = False,
    ctx: click.Context | None = None,
    file: IO[Any] | None = None,
    err: bool = False,
) -> NoReturn:
    config_debug = bool(ctx and ctx.ensure_object(dict) and ctx.obj.get("debug"))  # type: ignore[reportUnknownArgumentType]
    debug = debug if debug is not None else config_debug

    if debug:
        click.echo(click.style("DEBUG: ", fg="yellow") + message, err=err, file=file)
        raise ClientError(message, original_error=exc)
    raise ClientError(message, original_error=exc)


def nested_get(_dict: dict[str, Any] | None, dot_key: str | None, default: Any | None = None) -> Any:
    """Get a nested field from a nested dict with dot notation."""
    if _dict is None or dot_key is None:
        return default
    if "." in dot_key:
        dot_key_parts = dot_key.split(".")
        this_key = dot_key_parts.pop(0)
        return nested_get(_dict.get(this_key, default), ".".join(dot_key_parts), default)
    return _dict.get(dot_key, default)


def nested_set(_dict: dict[str, Any], dot_key: str, value: Any) -> None:
    """Set a nested field from a key in dot notation."""
    keys = dot_key.split(".")
    for key in keys[:-1]:
        _dict = _dict.setdefault(key, {})

    _dict[keys[-1]] = value


def nest_from_dot(dots: str, value: Any) -> Any:
    """Nest a dotted field and set the innermost value."""
    fields = dots.split(".")

    if not fields:
        return {}

    nested = {fields.pop(): value}

    for field_ in reversed(fields):
        nested = {field_: nested}

    return nested


def schema_prompt(name: str, value: Any | None = None, is_required: bool = False, **options: Any) -> Any:  # noqa: PLR0911, PLR0912, PLR0915
    """Interactively prompt based on schema requirements."""
    field_type = options.get("type")
    pattern: str | None = options.get("pattern")
    enum = options.get("enum", [])
    minimum = int(options["minimum"]) if "minimum" in options else None
    maximum = int(options["maximum"]) if "maximum" in options else None
    min_item = int(options.get("min_items", 0))
    max_items = int(options.get("max_items", 9999))

    default = options.get("default")
    if default is not None and str(default).lower() in ("true", "false"):
        default = str(default).lower()

    if "date" in name:
        default = time.strftime("%Y/%m/%d")

    if name == "rule_id":
        default = str(uuid.uuid4())

    if len(enum) == 1 and is_required and field_type != "array":
        return enum[0]

    def _check_type(_val: Any) -> bool:  # noqa: PLR0911
        if field_type in ("number", "integer") and not str(_val).isdigit():
            print(f"Number expected but got: {_val}")
            return False
        if pattern:
            match = re.match(pattern, _val)
            if not match or len(match.group(0)) != len(_val):
                print(f"{_val} did not match pattern: {pattern}!")
                return False
        if enum and _val not in enum:
            print("{} not in valid options: {}".format(_val, ", ".join(enum)))
            return False
        if minimum and (type(_val) is int and int(_val) < minimum):
            print(f"{_val!s} is less than the minimum: {minimum!s}")
            return False
        if maximum and (type(_val) is int and int(_val) > maximum):
            print(f"{_val!s} is greater than the maximum: {maximum!s}")
            return False
        if type(_val) is str and field_type == "boolean" and _val.lower() not in ("true", "false"):
            print(f"Boolean expected but got: {_val!s}")
            return False
        return True

    def _convert_type(_val: Any) -> Any:
        if field_type == "boolean" and type(_val) is not bool:
            _val = _val.lower() == "true"
        return int(_val) if field_type in ("number", "integer") else _val

    prompt = (
        "{name}{default}{required}{multi}".format(
            name=name,
            default=f' [{default}] ("n/a" to leave blank) ' if default else "",
            required=" (required) " if is_required else "",
            multi=" (multi, comma separated) " if field_type == "array" else "",
        ).strip()
        + ": "
    )

    while True:
        result = value or input(prompt) or default
        if result == "n/a":
            result = None

        if not result:
            if is_required:
                value = None
                continue
            return None

        if field_type == "array":
            result_list = result.split(",")

            if not (min_item < len(result_list) < max_items):
                if is_required:
                    value = None
                    break
                return []

            for value in result_list:
                if not _check_type(value):
                    if is_required:
                        value = None  # noqa: PLW2901
                        break
                    return []
            if is_required and value is None:
                continue
            return [_convert_type(r) for r in result_list]
        if _check_type(result):
            return _convert_type(result)
        if is_required:
            value = None
            continue
        return None


def get_kibana_rules_map(repo: str = "elastic/kibana", branch: str = "master") -> dict[str, Any]:
    """Get list of available rules from the Kibana repo and return a list of URLs."""

    timeout = 30  # secs

    # ensure branch exists
    r = requests.get(f"https://api.github.com/repos/{repo}/branches/{branch}", timeout=timeout)
    r.raise_for_status()

    url = (
        "https://api.github.com/repos/{repo}/contents/x-pack/{legacy}plugins/{app}/server/lib/"
        "detection_engine/rules/prepackaged_rules?ref={branch}"
    )

    r = requests.get(url.format(legacy="", app="security_solution", branch=branch, repo=repo), timeout=timeout)
    r.raise_for_status()

    gh_rules = r.json()

    # pre-7.9 app was siem
    if isinstance(gh_rules, dict) and gh_rules.get("message", "") == "Not Found":  # type: ignore[reportUnknownMemberType]
        gh_rules = requests.get(url.format(legacy="", app="siem", branch=branch, repo=repo), timeout=timeout).json()

    # pre-7.8 the siem was under the legacy directory
    if isinstance(gh_rules, dict) and gh_rules.get("message", "") == "Not Found":  # type: ignore[reportUnknownMemberType]
        gh_rules = requests.get(
            url.format(legacy="legacy/", app="siem", branch=branch, repo=repo), timeout=timeout
        ).json()

    if isinstance(gh_rules, dict) and gh_rules.get("message", "") == "Not Found":  # type: ignore[reportUnknownMemberType]
        raise ValueError(f"rules directory does not exist for {repo} branch: {branch}")

    if not isinstance(gh_rules, list):
        raise TypeError("Expected to receive a list")

    results: dict[str, Any] = {}

    for r in gh_rules:  # type: ignore[reportUnknownMemberType]
        if "name" not in r:
            raise ValueError("Name value is expected")

        name = r["name"]  # type: ignore[reportUnknownMemberType]

        if not isinstance(name, str):
            raise TypeError("String value is expected for name")

        if name.endswith(".json"):
            key = Path(name).name
            val = r["download_url"]  # type: ignore[reportUnknownMemberType]
            results[key] = val

    return results


def get_kibana_rules(
    repo: str = "elastic/kibana",
    branch: str = "master",
    verbose: bool = True,
    threads: int = 50,
    rule_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Retrieve prepackaged rules from kibana repo."""
    from multiprocessing.pool import ThreadPool

    kibana_rules: dict[str, Any] = {}

    if verbose:
        thread_use = f" using {threads} threads" if threads > 1 else ""
        click.echo(f"Downloading rules from {repo} {branch} branch in kibana repo{thread_use} ...")

    rule_paths = [os.path.splitext(os.path.basename(p))[0] for p in (rule_paths or [])]  # noqa: PTH119, PTH122
    rules_mapping = (
        [(n, u) for n, u in get_kibana_rules_map(repo=repo, branch=branch).items() if n in rule_paths]
        if rule_paths
        else get_kibana_rules_map(repo=repo, branch=branch).items()
    )

    def download_worker(rule_info: tuple[str, str]) -> None:
        n, u = rule_info
        kibana_rules[n] = requests.get(u, timeout=30).json()

    pool = ThreadPool(processes=threads)
    _ = pool.map(download_worker, rules_mapping)
    pool.close()
    pool.join()

    return kibana_rules


@cached
def load_current_package_version() -> str:
    """Load the current package version from config file."""
    data = load_etc_dump(["packages.yaml"])
    return data["package"]["name"]


def get_default_config() -> Path | None:
    return next(ROOT_DIR.glob(".detection-rules-cfg.*"), None)


@cached
def parse_user_config() -> dict[str, Any]:
    """Parse a default config file."""
    import eql  # type: ignore[reportMissingTypeStubs]

    config_file = get_default_config()
    config = {}

    if config_file and config_file.exists():
        config = eql.utils.load_dump(str(config_file))  # type: ignore[reportUnknownMemberType]
        click.secho(f"Loaded config file: {config_file}", fg="yellow")

    return config


def discover_tests(start_dir: str = "tests", pattern: str = "test*.py", top_level_dir: str | None = None) -> list[str]:
    """Discover all unit tests in a directory."""

    tests: list[str] = []

    def list_tests(s: unittest.TestSuite) -> None:
        for test in s:
            if isinstance(test, unittest.TestSuite):
                list_tests(test)
            else:
                tests.append(test.id())

    loader = unittest.defaultTestLoader
    suite = loader.discover(start_dir, pattern=pattern, top_level_dir=top_level_dir or str(ROOT_DIR))
    list_tests(suite)
    return tests


def getdefault(name: str) -> Callable[[], Any]:
    """Callback function for `default` to get an environment variable."""
    envvar = f"DR_{name.upper()}"
    config = parse_user_config()
    return lambda: os.environ.get(envvar, config.get(name))


def get_elasticsearch_client(  # noqa: PLR0913
    cloud_id: str | None = None,
    elasticsearch_url: str | None = None,
    es_user: str | None = None,
    es_password: str | None = None,
    ctx: click.Context | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> Elasticsearch:
    """Get an authenticated elasticsearch client."""

    if not (cloud_id or elasticsearch_url):
        raise_client_error("Missing required --cloud-id or --elasticsearch-url")

    # don't prompt for these until there's a cloud id or elasticsearch URL
    basic_auth: tuple[str, str] | None = None
    if not api_key:
        es_user = es_user or click.prompt("es_user")
        es_password = es_password or click.prompt("es_password", hide_input=True)
        if not es_user or not es_password:
            raise ValueError("Both username and password must be provided")
        basic_auth = (es_user, es_password)

    hosts = [elasticsearch_url] if elasticsearch_url else None
    timeout = kwargs.pop("timeout", 60)
    kwargs["verify_certs"] = not kwargs.pop("ignore_ssl_errors", False)

    try:
        client = Elasticsearch(
            hosts=hosts, cloud_id=cloud_id, http_auth=basic_auth, timeout=timeout, api_key=api_key, **kwargs
        )
        # force login to test auth
        _ = client.info()
    except AuthenticationException as e:
        error_msg = f"Failed authentication for {elasticsearch_url or cloud_id}"
        raise_client_error(error_msg, e, ctx=ctx, err=True)
    else:
        return client


def get_kibana_client(
    *,
    api_key: str | None = None,
    kibana_user: str | None = None,
    kibana_password: str | None = None,
    cloud_id: str | None = None,
    kibana_url: str | None = None,
    space: str | None = None,
    ignore_ssl_errors: bool = False,
    **kwargs: Any,
) -> Kibana:
    """Get an authenticated Kibana client."""
    if not (cloud_id or kibana_url):
        raise_client_error("Missing required --cloud-id or --kibana-url")

    verify = not ignore_ssl_errors
    return Kibana(
        cloud_id=cloud_id,
        kibana_url=kibana_url,
        api_key=api_key,
        username=kibana_user,
        password=kibana_password,
        space=space,
        verify=verify,
        **kwargs,
    )


client_options = {
    "kibana": {
        "kibana_url": click.Option(["--kibana-url"], default=getdefault("kibana_url")),
        "cloud_id": click.Option(["--cloud-id"], default=getdefault("cloud_id"), help="ID of the cloud instance."),
        "api_key": click.Option(["--api-key"], default=getdefault("api_key")),
        "kibana_user": click.Option(["--kibana-user", "-ku"], default=getdefault("kibana_user")),
        "kibana_password": click.Option(["--kibana-password", "-kp"], default=getdefault("kibana_password")),
        "space": click.Option(["--space"], default=None, help="Kibana space"),
        "ignore_ssl_errors": click.Option(["--ignore-ssl-errors"], default=getdefault("ignore_ssl_errors")),
    },
    "elasticsearch": {
        "cloud_id": click.Option(["--cloud-id"], default=getdefault("cloud_id")),
        "api_key": click.Option(["--api-key"], default=getdefault("api_key")),
        "elasticsearch_url": click.Option(["--elasticsearch-url"], default=getdefault("elasticsearch_url")),
        "es_user": click.Option(["--es-user", "-eu"], default=getdefault("es_user")),
        "es_password": click.Option(["--es-password", "-ep"], default=getdefault("es_password")),
        "timeout": click.Option(["--timeout", "-et"], default=60, help="Timeout for elasticsearch client"),
        "ignore_ssl_errors": click.Option(["--ignore-ssl-errors"], default=getdefault("ignore_ssl_errors")),
    },
}
kibana_options = list(client_options["kibana"].values())
elasticsearch_options = list(client_options["elasticsearch"].values())


def add_client(client_types: list[str], add_to_ctx: bool = True, add_func_arg: bool = True) -> Callable[..., Any]:
    """Wrapper to add authed client."""

    def _wrapper(func: Callable[..., Any]) -> Callable[..., Any]:
        client_ops_dict: dict[str, click.Option] = {}
        client_ops_keys: dict[str, list[str]] = {}
        for c_type in client_types:
            ops = client_options[c_type]
            client_ops_dict.update(ops)
            client_ops_keys[c_type] = list(ops)

        if not client_ops_dict:
            client_types_str = ", ".join(client_types)
            raise ValueError(f"Unknown client: {client_types_str} in {func.__name__}")

        client_ops = list(client_ops_dict.values())

        @wraps(func)
        @add_params(*client_ops)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:  # noqa: PLR0912
            ctx: click.Context | None = next((a for a in args if isinstance(a, click.Context)), None)
            es_client_args = {k: kwargs.pop(k, None) for k in client_ops_keys.get("elasticsearch", [])}
            #                                      shared args like cloud_id
            kibana_client_args = {k: kwargs.pop(k, es_client_args.get(k)) for k in client_ops_keys.get("kibana", [])}

            if "elasticsearch" in client_types:
                # for nested ctx invocation, no need to re-auth if an existing client is already passed
                elasticsearch_client: Elasticsearch | None = kwargs.get("elasticsearch_client")
                try:
                    if elasticsearch_client and elasticsearch_client.info():
                        pass
                    else:
                        elasticsearch_client = get_elasticsearch_client(**es_client_args)
                except AuthenticationException:
                    elasticsearch_client = get_elasticsearch_client(**es_client_args)

                if add_func_arg:
                    kwargs["elasticsearch_client"] = elasticsearch_client
                if ctx and add_to_ctx:
                    ctx.obj["es"] = elasticsearch_client

            if "kibana" in client_types:
                # for nested ctx invocation, no need to re-auth if an existing client is already passed
                kibana_client: Kibana | None = kwargs.get("kibana_client")
                if kibana_client:
                    try:
                        with kibana_client:
                            if kibana_client.version:
                                pass  # kibana_client is valid and can be used directly
                    except (requests.HTTPError, AttributeError):
                        kibana_client = get_kibana_client(**kibana_client_args)
                else:
                    # Instantiate a new Kibana client if none was provided or if the provided one is not usable
                    kibana_client = get_kibana_client(**kibana_client_args)

                if add_func_arg:
                    kwargs["kibana_client"] = kibana_client
                if ctx and add_to_ctx:
                    ctx.obj["kibana"] = kibana_client

            return func(*args, **kwargs)

        return _wrapped

    return _wrapper
