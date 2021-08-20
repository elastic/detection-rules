FROM python:3.8-slim

ENV PATH="/opt/bin:${PATH}"
ENV PYTHONPATH="/opt/detection-rules/:${PYTHONPATH}"

RUN mkdir -p /opt/detection-rules \
    mkdir -p /opt/bin

# Dependencies
COPY requirements.txt /opt/detection-rules/requirements.txt
RUN pip install -r /opt/detection-rules/requirements.txt

# Requirements
COPY kibana /opt/detection-rules/kibana
COPY rta /opt/detection-rules/rta
COPY kql /opt/detection-rules/kql
COPY etc /opt/detection-rules/etc
COPY detection_rules /opt/detection-rules/detection_rules

# Entrypoint
RUN echo '#!/bin/sh' > /opt/bin/detection_rules && \
    echo '/usr/bin/env python -m detection_rules "${@}"' >> /opt/bin/detection_rules && \
    chmod 755 /opt/bin/detection_rules

# Rules directory - added last as it is the most updated part
COPY rules /opt/detection-rules/rules

ENTRYPOINT ["/opt/bin/detection_rules"]

VOLUME ["/rules/"]
