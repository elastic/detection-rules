# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Opt-in performance comparison for related integration version resolution."""

import os
import statistics
import timeit
import unittest
from collections import OrderedDict
from typing import Any

from semver import Version

from detection_rules.config import load_current_package_version
from detection_rules.integrations import find_compatible_version_range, load_integrations_manifests


def _benchmark_find_least_compatible_version(
    package: str,
    integration: str,
    current_stack_version: str,
    packages_manifest: dict[str, Any],
) -> str:
    """Snapshot of pre-#5601 ``find_least_compatible_version`` for benchmarking only."""
    from detection_rules.integrations import _satisfies_kibana_range

    integration_manifests = dict(sorted(packages_manifest[package].items(), key=lambda x: Version.parse(x[0])))
    stack_version = Version.parse(current_stack_version, optional_minor_and_patch=True)

    major_versions = sorted(
        {Version.parse(manifest_version).major for manifest_version in integration_manifests},
        reverse=True,
    )
    for max_major in major_versions:
        major_integration_manifests = {
            k: v for k, v in integration_manifests.items() if Version.parse(k).major == max_major
        }

        for version, manifest in OrderedDict(
            sorted(major_integration_manifests.items(), key=lambda x: Version.parse(x[0]))
        ).items():
            version_requirement = manifest["conditions"]["kibana"]["version"]
            if _satisfies_kibana_range(stack_version, version_requirement):
                return f"^{version}"

    raise ValueError(f"no compatible version for integration {package}:{integration}")


@unittest.skipUnless(os.environ.get("RUN_INTEGRATION_PERF"), "set RUN_INTEGRATION_PERF=1 to run")
class TestRelatedIntegrationsVersionPerformance(unittest.TestCase):
    """Compare legacy stack-dependent lookup vs stack-invariant OR range."""

    @classmethod
    def setUpClass(cls):
        cls.manifests = load_integrations_manifests()
        cls.packages = ["endpoint", "aws", "windows"]
        cls.stacks = ["8.19.0", "9.4.0", load_current_package_version()]
        cls.repeat = 7
        cls.number = 500

    @staticmethod
    def _median_ms(timings: list[float]) -> float:
        return statistics.median(timings) * 1000

    def test_benchmark_old_vs_new(self):
        """Print median timings for legacy vs OR-range resolution on real manifests."""
        rows: list[tuple[str, str, float, float, float]] = []

        for package in self.packages:
            if package not in self.manifests:
                self.skipTest(f"{package} not in integration manifests")

            new_timings = timeit.repeat(
                lambda: find_compatible_version_range(package, self.manifests),
                repeat=self.repeat,
                number=self.number,
            )
            new_median = self._median_ms(new_timings)

            for stack in self.stacks:
                old_timings = timeit.repeat(
                    lambda p=package, s=stack: _benchmark_find_least_compatible_version(
                        p, p, s, self.manifests
                    ),
                    repeat=self.repeat,
                    number=self.number,
                )
                old_median = self._median_ms(old_timings)
                ratio = new_median / old_median if old_median else float("inf")
                rows.append((package, stack, old_median, new_median, ratio))

        print("\nrelated_integrations version resolution (median ms per call)")
        print(f"{'package':<12} {'stack':<10} {'old_ms':>10} {'new_ms':>10} {'new/old':>10}")
        for package, stack, old_median, new_median, ratio in rows:
            print(f"{package:<12} {stack:<10} {old_median:>10.4f} {new_median:>10.4f} {ratio:>10.2f}")

        for _package, _stack, old_median, new_median, ratio in rows:
            if ratio > 10:
                self.fail(
                    f"new implementation >10x slower than legacy for {_package} @ {_stack}: "
                    f"old={old_median:.4f}ms new={new_median:.4f}ms ratio={ratio:.2f}"
                )
