# Contributing to Detection Rules

Thank you for your interest in contributing to Detection Rules. We've crafted this document to make it simple and easy for you to contribute. We recommend that you read these contribution guidelines carefully so that you spend less time working on GitHub issues and PRs and can be more productive contributing to this repository.

If you want to be rewarded for your contributions, sign up for the [Elastic Contributor Program](https://www.elastic.co/community/contributor). Each time you make a valid contribution, you’ll earn points that increase your chances of winning prizes and being recognized as a top contributor.

These guidelines will also help you post meaningful issues that will be more easily understood, considered, and resolved. These guidelines are here to help you whether you are creating a new rule, opening an issue to report a false positive, or requesting a feature.

## Table of Contents

- [Contributing to Detection Rules](#contributing-to-detection-rules)
  - [Table of Contents](#table-of-contents)
  - [Effective issue creation in Detection Rules](#effective-issue-creation-in-detection-rules)
    - [Why we create issues before contributing code or new rules](#why-we-create-issues-before-contributing-code-or-new-rules)
    - [What a good issue looks like](#what-a-good-issue-looks-like)
    - ["My issue isn't getting enough attention"](#my-issue-isnt-getting-enough-attention)
    - ["I want to help!"](#i-want-to-help)
  - [How we use Git and GitHub](#how-we-use-git-and-github)
    - [Forking](#forking)
    - [Branching](#branching)
    - [Commit messages](#commit-messages)
    - [What goes into a Pull Request](#what-goes-into-a-pull-request)
  - [Our approach to detection engineering](#our-approach-to-detection-engineering)
    - [Rule metadata](#rule-metadata)
    - [Using Elastic Common Schema (ECS)](#using-elastic-common-schema-ecs)
    - [Creating a rule with the CLI](#creating-a-rule-with-the-cli)
    - [Testing a rule with the CLI](#testing-a-rule-with-the-cli)
  - [Writing style](#writing-style)
  - [Signing the contributor license agreement](#signing-the-contributor-license-agreement)
  - [Submitting a Pull Request](#submitting-a-pull-request)
    - [What to expect from a code review](#what-to-expect-from-a-code-review)
    - [How we handle merges](#how-we-handle-merges)


## Effective issue creation in Detection Rules

### Why we create issues before contributing code or new rules

We generally create issues in GitHub before contributing code or new rules. This helps front-load the conversation before the rules. There are many rules that will make sense in one or two environments, but don't work as well in general. Some rules are overfitted to a particular indicator or tool. By creating an issue first, it creates an opportunity to bounce our ideas off each other to see what's feasible and what ways to approach detection.

By contrast, starting with a pull request makes it more difficult to revisit the approach. Many PRs are treated as mostly done and shouldn't need much work to get merged. Nobody wants to receive PR feedback that says "start over" or "closing: won't merge." That's discouraging to everyone, and we can avoid those situations if we have the discussion together earlier in the development process. It might be a mental switch for you to start the discussion earlier, but it makes us all more productive and and our rules more effective.


### What a good issue looks like

We have a few types of issue templates to [choose from](https://github.com/elastic/detection-rules/issues/new/choose). If you don't find a template that matches or simply want to ask a question, create a blank issue and add the appropriate labels.

* **Bug report**: Create a report to help us improve (not pertaining to rules)
* **Feature request**: Suggest an idea for this project (not pertaining to rules)
* **New rule**: Suggestions and ideas for new rules for the Detection Engine
* **Rule deprecation**: Recommend deprecating a rule that doesn't work or isn't useful anymore
* **Tune existing rule**: Suggest changes to make to an existing rule to address false positives or negatives

When requesting a **New rule**, please create an issue of the **New rule** type. The issue contains a handful of questions about the targeted behavior and the approach to detection:

* What are the matching MITRE ATT&CK® technique and tactics?
* What data sources are needed?
* Does a detection need fields that aren't listed in Elastic Common Schema (ECS) yet?
* Is the technique behavior-based, or is it based on indicators of compromise?

### "My issue isn't getting enough attention"

First of all, **sorry about that!** We want you to have a great time with Detection Rules.

We'll tag issues and pull requests with the target release if applicable. If a rule is blocked by a feature, we'll add a label to reflect that. With all of the issues, we need to prioritize according to impact and difficulty, so some issues can be neglected while we work on more pressing issues.

Of course, feel free to bump your issues if you think they've been neglected for a prolonged period.

Issues and pull requests will be marked as `stale` after 60 days of inactivity. After 7 more days of incactivity, they will be closed automatically.

If an issue or pull request is marked `stale` and/or closed, this does not mean it is not important, just that there may be more work than available resources over a given time. We feel that it is a better experience to generate activity responding to a stale issue or letting it close, than to let something remain open and neglected for longer periods of time.

If your issue or pull request is closed from inactivity and you feel this is an error, please feel free to re-open it with comments and we will try our best to respond with justification to close or to get it the proper attention.

### "I want to help!"

**Now we're talking**. If you have a bug fix or new rule that you would like to contribute to Detection Rules, please **find or open an issue about it before you start working on it.** Talk about what you would like to do. It may be that somebody is already working on it, or that there are particular issues that you should know about before implementing the change.

We get asked from time-to-time if there are any rules that the community can help with, absolutely! Check out the rules with the ["help wanted" label](https://github.com/elastic/detection-rules/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22+). Don't feel like these are your only options, any issue is up for grabs by the community, but these are rules that are good ideas and we would love to have some additional hands on.

We enjoy working with contributors to get their code accepted. There are many approaches to fixing a problem and it is important to find the best approach before writing too much code.


## How we use Git and GitHub

### Forking

We follow the [GitHub forking model](https://help.github.com/articles/fork-a-repo/) for collaborating on Detection Rules rules. This model assumes that you have a remote called `upstream` which points to the official Detection Rules repo, which we'll refer to in later code snippets.

### Branching

This repository follows a similar approach to other repositories within the [Elastic](https://github.com/elastic) organization, with a few exceptions that make our life easier. One way this repository is simpler is the lack of major version breaking changes. This means we have less backport commits to worry about and makes us a little more productive.

**7.13 and later**

The branching workflow we currently follow for Detection Rules:

* All changes for the next release of rules are made to the `main` branch
* During feature freeze for a release, we will create a branch from `main` for the release version `{majorVersion.minorVersion}`. This means that we can continue contributing to `main`, even during feature freeze, and it will target `{majorVersion.minorVersion+1}`
* Rules are automatically backported to old branches (starting at `7.13`) if the `backport: auto` label is set on GitHub. This is done automatically for all PRs that merge to main `main` with the label `backport: auto`.
* To opt-out of a backport, add the label `backport: skip`. GitHub will automatically remove the `backport: auto` label from the PR when this label is set
* From 7.13 to 8.1, you can use Fleet to [download prebuilt rules](https://www.elastic.co/guide/en/security/current/rules-ui-management.html#download-prebuilt-rules) for your stack, and subsequent releases will follow the instructions at [Update prebuilt rules](https://www.elastic.co/guide/en/security/current/rules-ui-management.html#update-prebuilt-rules)
* Changes to rules in an already-released branch will be included in an update to the "Prebuilt Security Detection Rules" integration

**Prior to 7.13**

The branching workflow we used to follow for Detection Rules:

* All changes for the next release of rules are made to the `main` branch
* During feature freeze for a release, we will create a branch from `main` for the release version `{majorVersion.minorVersion}`. This means that we can continue contributing to `main`, even during feature freeze, and it will just target `{majorVersion.minorVersion+1}`
* For bug fixes and other changes targeting the pending release during feature freeze, we will make those contributions to `{majorVersion.minorVersion}`. Periodically, we will then backport those changes from `{majorVersion.minorVersion}` to `main`

### Commit messages

* Feel free to make as many commits as you want, while working on a branch.
* Please use your commit messages to include helpful information on your changes. Commit messages that look like `update` are unhelpful to reviewers. Try to be clear and concise with the changes in a commit. For example: `Add Sysmon support to MsBuild network rule`. Here's a [good blog](https://chris.beams.io/posts/git-commit/) on general best practices for commit messages.


### What goes into a Pull Request

* Please include an explanation of your changes in your PR description.
* Links to relevant issues, external resources, or related PRs are very important and useful.
* Please try to explain *how* and *why* your rule works. Can you explain what makes the logic sound? Does it actually detect what it's supposed to? If you include the screenshot, please make sure to crop out any sensitive information!
* Please try to capture the expectations for noise levels: is the rule prone to false positives or false negatives?
* See [Submitting a Pull Request](#submitting-a-pull-request) for more info.


## Our approach to detection engineering

Contributions to Detection Rules are ultimately integrated with the Detection Engine within the Security Application of Kibana. The rules in this repository[*](#maturity-note) will be bundled in the next release and available to all users with access to the Detection Engine. For that reason, we want to keep the bar high and avoid rules that lead to high volumes of false-positives (FPs) or have significant performance impact on a cluster. You can use *Exceptions* in the Detection Engine to add allowlist exceptions when a rule generates an FP. That gives some tolerance of FPs, but we still want to keep numbers as low as we can.

For more information on our approach to writing threat-based detection logic, please read our [philosophy](PHILOSOPHY.md) page.

<a id="maturity-note">\* Note:</a> Specifically, rules that contain `maturity = "production"` will be included in the next stack release.


### Rule metadata

Detection logic in itself is not enough to be useful to practitioners. Rules need to contain more information, like a name, description, and severity levels within the metadata. Try to be thorough with the metadata you provide for a rule. Some of the information is required for a rule to run, other information is provided to the user enabling the rule, and some information is also invaluable context to users that triage the alerts generated by a rule.

Some of the required metadata captured in a rule file:

| field                | required | description                                                                     |
| -------------------- | -------- | ------------------------------------------------------------------------------- |
| **description**      |     ✓    | Brief one-two sentence description for what the rule detects                    |
| **enabled**          |          | Default status of the rule, automatically enabled if `true`                     |
| **false_positives**  |          | Array of markdown strings for guidance on triaging false positives              |
| **filters**          |          | Array of query DSL filters to `and` with the query                              |
| **from**             |          | Relative start time for a rule (e.g. `now-6m`)                                  |
| **index**            |          | List of index patterns that stores the needed events                            |
| **interval**         |          | Interval between executions of the rule                                         |
| **language**         |     ✓    | Query language for language-based rules (e.g. `kuery`, `lucene`, `eql`)         |
| **max_signals**      |     ✓    | Cutoff for the maximum number of signals in an execution before dropped results |
| **name**             |     ✓    | A short title for the rule                                                      |
| **note**             |          | Additional triage notes or details on the rule beyond `description`             |
| **query**            |     ✓    | The query language code for rules of type `query`                               |
| **risk_score**       |          | Integer to rank the risk relative to other rules. Leave blank if unknown        |
| **rule_id**          |     ✓    | Automatically generated UUID for the rule                                       |
| **severity**         |     ✓    | Severity of the matching results (e.g., `low`, `medium`, `high`, `critical`)     |
| **tags**             |          | Array of tags for grouping the rule (e.g., `APM`, `Linux`, `Packetbeat`, ...)    |
| **threat**           |     ✓    | Mapping to a threat framework, such as MITRE ATT&CK®                            |
| **to**               |          | Relative end time of a rule (e.g. `now`)                                        |
| **type**             |     ✓    | Execution type of the rule (`query` or `machine_learning`)                      |


### Using Elastic Common Schema (ECS)

Our rules should be written generically when possible. We use [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html) to standardize data before ingesting into Elasticsearch. ECS gives a set of field sets, field names and categories to standardize events across various tools. By writing rules using ECS fields and values, you can reuse the same logic regardless of data source. ECS is an ongoing effort, and we may encounter fields that aren't present yet. If you need to make any requests to ECS, see the [elastic/ecs](https://github.com/elastic/ecs) GitHub repository.

If the relevant [categorization values](https://www.elastic.co/guide/en/ecs/current/ecs-category-field-values-reference.html) are already defined for ECS, we use these to narrow down the event type before adding the query. Typically, the query starts with the broadest grouping possible and gets narrower for each clause. For example, we might write `event.category:process and event.type:start and process.name:net.exe and process.args:group`. First, we match process events with `event.category`, then narrow to creation events with `event.type`. Of the process creation events, we're looking for the process `net.exe` with `process.name` and finally we check the arguments `group` by looking at `process.args`. This flow has little effect on the generated Elasticsearch query, but is the most intuitive to read for rule developers.

Sometimes, it might not make sense for ECS to standardize a field, value, or category. Occasionally, we may encounter fields that specific to a single use-case or vendor. When that happens, we add an exception in [detection_rules/etc/non-ecs-schema.json](detection_rules/etc/non-ecs-schema.json). We automatically detect beats by looking at the index patterns used in a rule. If we see `winlogbeat-*`, for example, then we can validate the rule against ECS + Winlogbeat. When using a particular beat, please use `event.module` and `data_stream.dataset` to make the rule more precise and to better nudge the validation logic. Similar to our logic flow for ECS categorization, we recommend searches progress from `event.module` → `data_stream.dataset` → `event.action` → `<additional criteria>`.

When a Pull Request is missing a necessary ECS change, please add an issue to [elastic/ecs](https://github.com/elastic/ecs) and link it from the pull request. We don't want to leave PRs blocked for too long, so if the ECS issue isn't progressing, then we can add a note and use the vendor- or beat-specific fields. We'll create another issue, reminding us to update the rule logic to switch to the ECS field when it becomes available. To maximize compatibility, we may add an `or` clause for a release or two to handle the different permutatations. After a few releases, we'll remove this and strictly require the ECS fields.

### Creating a rule with the CLI

We manage our repository with a command line tool that automatically creates TOML files, validates rules, and bundles all rules for the Detection Engine. There's a lot of metadata for each rule, and manually copying and pasting rule files is error prone and tedious. To create a new rule, run the command below, which iterates through the required metadata, and prompts for each field.


For example, to create a new rule file for `rules/windows/defense_evasion_msbuild_child.toml`, run the command

```console
$ python -m detection_rules create-rule rules/windows/defense_evasion_msbuild_child.toml
```


The command will prompt you for each required field in the metadata
```
Rule type (machine_learning, query, saved_id): query
actions (multi, comma separated):
description (required): Look for child processes of MsBuild
enabled [false] ("n/a" to leave blank):
from [now-6m] ("n/a" to leave blank):
false_positives (multi, comma separated):
filters (multi, comma separated):
interval [5m] ("n/a" to leave blank):
exceptions_list (multi, comma separated):
max_signals [100] ("n/a" to leave blank):
meta:
name (required): Suspicious Child of MsBuild
note:
references (multi, comma separated):
risk_score [21] ("n/a" to leave blank)  (required):
rule_id [90d0c543-e197-46d8-934d-0320b2c83486] ("n/a" to leave blank)  (required):
severity [low] ("n/a" to leave blank)  (required): medium
tags (multi, comma separated): Windows
throttle:
timeline_id:
timeline_title:
to [now] ("n/a" to leave blank):
threat (multi, comma separated):
index (multi, comma separated): winlogbeat-*
language [kuery] ("n/a" to leave blank)  (required): kuery
query (required): event.category:process and process.parent.name:msbuild.exe
ecs_version (multi, comma separated): 1.4.0
```

Pending no errors, you'll see this output upon success
```
Rule Suspicious Child of MsBuild saved to rules/windows/defense_evasion_msbuild_child.toml
Did not set the following values because they are un-required when set to the default value
 - from
 - interval
 - max_signals
 - to
```


### Testing a rule with the CLI

When a rule is ready, it can be tested with unit tests. Detection Rules has several tests that run locally to validate rules in the repository. These tests make sure that rules are syntactically correct, use ECS or Beats schemas correctly, and ensure that metadata is also validated. There are also internal tests to make sure that the tools and functions to manager the repository are working as expected.

To run tests, simply run the command `test` with the CLI
```console
$ python -m detection_rules test

============================================================= test session starts ==============================================================
collected 73 items

tests/test_all_rules.py::TestValidRules::test_all_rule_files PASSED                                                                                               [  1%]
tests/test_all_rules.py::TestValidRules::test_all_rule_queries_optimized PASSED                                                                                   [  2%]
tests/test_all_rules.py::TestValidRules::test_all_rules_as_rule_schema PASSED                                                                                     [  4%]
tests/test_all_rules.py::TestValidRules::test_all_rules_tuned PASSED                                                                                              [  5%]
...
tests/kuery/test_parser.py::ParserTests::test_number_exists PASSED                                                                                                [ 98%]
tests/kuery/test_parser.py::ParserTests::test_number_wildcard_fail PASSED                                                                                         [100%]

========================================================================== 73 passed in 45.47s ==========================================================================
```


## Writing style

Our rules are much more than queries. We capture a lot of metadata within the rules, such as severity, index pattterns, and noise level. We also have several fields that are user-readable text, such as `name`, `description`, `false_positives`, `investigation_notes`, and `name`. Those fields, which are populated with English text[*](#i18n-note), should follow the [Elastic UI writing guidelines](https://elastic.github.io/eui/#/guidelines/writing). We want our text to be *clear* and *concise*, *consistent* and *conversational*.

<a id="i18n-note">\* Note</a>: We currently don't have i18n support for Detection Rules.


## Signing the contributor license agreement

Please make sure you've signed the [Contributor License Agreement](http://www.elastic.co/contributor-agreement/). We're not asking you to assign copyright to us, but to give us the right to distribute your code without restriction. We ask this of all contributors in order to assure our users of the origin and continuing existence of the code. You only need to sign the CLA once.


## Submitting a Pull Request

Push your local changes to your forked copy of the repository and submit a Pull Request. In the Pull Request, describe what your changes do and mention the number of the issue where discussion has taken place, e.g., "Closes #123".

Always submit your pull against `main` unless you are making changes for the pending release during feature freeze (see [Branching](#branching) for our branching strategy).

Then sit back and wait. We will probably have a discussion in the pull request and may request changes before merging. We're not trying to get in the way, but want to work with you to get your contributions in Detection Rules.


### What to expect from a code review

After a pull is submitted, it needs to get to review. If you have commit permissions on the Detection Rules repo you will probably perform these steps while submitting your Pull Request. If not, a member of the Elastic organization will do them for you, though you can help by suggesting a reviewer for your changes if you've interacted with someone while working on the issue.

Most likely, we will want to have a conversation in the pull request. We want to encourage contributions, but we also want to keep in mind how changes may affect other Elastic users. Please understand that even if a rule is working in your environment, it still may not be a good fit for all users of Elastic Security.

### How we handle merges

We recognize that Git commit messages are a history of all changes to the repository. We want to make this history easy to read and as concise and clear as possible. When we merge a pull request, we squash commits using GitHub's "Squash and Merge" method of merging. This keeps a clear history to the repository, since we rarely need to know about the commits that happen *within* a working branch for a pull request.

The exception to this rule is backport PRs. We want to maintain that commit history, because the commits within a release branch have already been squashed. If we were to squash again to a single commit, we would just see a commit "Backport changes from `{majorVersion.minorVersion}`" show up in main. This would obscure the changes. For backport pull requests, we will either "Create a Merge Commit" or "Rebase and Merge." For more information, see [Branching](#branching) for our branching strategy.
