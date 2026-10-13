#!/usr/bin/env bash
# One-shot: reproduce artefacts and serve the dashboard.
set -euo pipefail
cd "$(dirname "$0")/.."
python -m syntactica.cli report
echo "Serving dashboard at http://localhost:8000  (Ctrl-C to stop)"
cd dashboard && python -m http.server 8000
