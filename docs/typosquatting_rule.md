# Generating detection rule to alert on traffic to typosquatting or homonym domains

## What does the rule do?

This rule helps detect spoofing attacks on domains that you want to protect.


## Steps

### 1. Run [dnstwist](https://github.com/elceef/dnstwist) on the domain you want to watch

Eg: `dnstwist --format json elastic.co | jq`

This should give you a json file consisting of potentially malicious lookalike domains for your domain.

### 2. Index the lookalike domains into Elasticsearch

In order to detect network activity on the lookalike domains using a threat match rule, you would first need to index these domains into an Elasticsearch index using the following CLI command:

`python -m detection_rules typosquat create-dnstwist-index [OPTIONS] INPUT_FILE`

### 3. Prep rule to alert on generated indexes

Run the following CLI command to generate the typosquat rule file, which you will then import into Kibana.

`python -m detection_rules typosquat prep-rule [OPTIONS] AUTHOR`


### 4. Import the rule into Kibana

Import the ndjson rule file generated in the previous step, into Kibana, via the Detection rules UI. 

### 5. Detect potentially malicious network activity targeting your organization!


## Note

- You DO NOT need to re-import the rule file each time you have an additional domain to track. For each new domain, you'd run Step 1 to generate the json file consisting of lookalike domains for that domain, followed by the CLI command in Step 2 to index these domains into a new index. This index will automatically be picked up by the rule you imported the very first time.

- For advanced users, the threat indicator indices (`dnstwist-*`) also contain additional context about the lookalike domains, such as fuzzer information. You can query these indices if you would like to get such context about domains that have been alerted on.
