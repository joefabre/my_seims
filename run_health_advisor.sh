#!/bin/bash
# HealthBot AI Health Advisor — launcher
set -e

cd "$(dirname "$0")"

if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo "Warning: ANTHROPIC_API_KEY not set. AI chat will show setup instructions."
  echo "Get your key at https://console.anthropic.com and run:"
  echo "  export ANTHROPIC_API_KEY=your-key-here"
  echo ""
fi

if ! command -v python3 &>/dev/null; then
  echo "Error: python3 not found. Install Python 3.9+ first."
  exit 1
fi

if [ ! -d ".venv_health" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv_health
fi

source .venv_health/bin/activate
pip install -q -r requirements_health.txt

PORT=${PORT:-5001}
echo ""
echo "Starting HealthBot on http://127.0.0.1:$PORT"
echo "Press Ctrl+C to stop."
echo ""

if command -v open &>/dev/null; then
  (sleep 1.5 && open "http://127.0.0.1:$PORT") &
elif command -v xdg-open &>/dev/null; then
  (sleep 1.5 && xdg-open "http://127.0.0.1:$PORT") &
fi

python3 health_advisor.py --port "$PORT"
