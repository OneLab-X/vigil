#!/bin/sh
# Use a customer-provided Google credential file (service-account key or Workload Identity
# Federation config) only if one is mounted; otherwise ADC falls back to the metadata server.
if [ -s /secrets/gcp-credentials.json ]; then export GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-credentials.json; fi
exec "$@"
