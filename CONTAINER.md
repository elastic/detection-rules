# `detection_rules` Container

## Build

The container image can be built using `docker` with:
```bash
$ git clone https://github.com/elastic/detection-rules
$ cd detection-rules
$ docker build . -t detection_rules
# alternatively the Makefile can be used
$ make image
```

## Running the container

The container can be run using the below `docker` command:
```bash
$ docker run -ti detection_rules
```

The entrypoint directly points to `detection_rules` `__main__.py`, so the above command can be directly used with arguments:
```bash
$ docker run -ti detection_rules kibana --kibana-url [...] -ku user -kp 'xxxx' search-alerts
```

In case a [`.detection-rules-cfg.json`](CLI.md#setup-a-config-file) is available, it can be mount inside the container as below:
```bash
$ docker run -v /path/to/.detection-rules-cfg.json:/opt/detection-rules/.detection-rules-cfg.json -ti detection_rules kibana search-alerts
```

## Working with Rules

Rule directories can be mount in the container and used directly with `detection_rules` utilities:
```bash
$ docker run -v /tmp/test-rules/:/opt/detection-rules/rules -ti detection_rules kibana --kibana-url [...] -ku user -kp 'xxxx' upload-rule --directory /opt/detection-rules/rules
```

