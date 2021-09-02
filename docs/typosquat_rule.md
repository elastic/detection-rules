# Generating detection rule to alert on traffic to typosquatting or homonym domains

## What does the rule do?

This rule helps detect spoofing attacks on domains that you want to protect.


## Steps

### 1. Run [dnstwist](https://github.com/elceef/dnstwist) on the domain you want to watch

Eg: `dnstwist --format json elastic.co | jq`

This should give you a json file consisting of potentially malicious lookalike domains for your domain.

### 2. Index the lookalike domains into Elasticsearch and generate the rule file

In order to detect network activity on the lookalike domains using a threat match rule, you would first need to index these domains into an Elasticsearch index. The following CLI command not only does this, but also generates the rule file which you will then import into Kibana:

`python -m detection_rules create-dnstwist-index [OPTIONS] INPUT_FILE`

### 3. Import the rule into Kibana

Import the ndjson rule file generated in the previous step, into Kibana, via the Detection rules UI.

### 4. Detect potentially malicious network activity targeting your organization!