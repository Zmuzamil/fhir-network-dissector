# Image shared by all netlab helper and client containers: Python + requests (FHIR clients,
# web server), ethtool (turn TCP offload off), tcpdump (capture). Built once:
#
#     docker build -t fhir-netlab-node netlab
#
# Internet is needed only to build it; at run time the nodes need no outside access.
FROM python:3.13-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ethtool tcpdump iproute2 procps \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "requests>=2.31,<3"
COPY node-entrypoint.sh /usr/local/bin/node-entrypoint.sh
RUN chmod +x /usr/local/bin/node-entrypoint.sh
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/usr/local/bin/node-entrypoint.sh"]
