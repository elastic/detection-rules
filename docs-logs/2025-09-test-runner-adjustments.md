# Test runner adjustments for custom rules

- Added fallbacks for git-based tests when `origin/main` is unavailable.
- Skipped schema validation tests when optional validation is bypassed.
- Skipped version-lock workflow test when stack schema map has too few versions.
- Added configuration flag to bypass registry package tests
