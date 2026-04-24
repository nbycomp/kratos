FROM fluent/fluentd:v1.17-debian-1

USER root

# Native build tools are required for gems with C extensions pulled by
# fluent-plugin-opentelemetry (for example bigdecimal).
RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential \
  && rm -rf /var/lib/apt/lists/* \
  && fluent-gem install grpc --no-document \
  && fluent-gem install fluent-plugin-opentelemetry --no-document

USER fluent
