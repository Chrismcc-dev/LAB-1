set -euo pipefail

trivy image \
  --scanners vuln \
  --pkg-types os,library \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --format table \
  --exit-code 1 \
  node-hello:ci-scan
