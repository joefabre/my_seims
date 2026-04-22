#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
echo ""
echo "  my_seims — macOS SIEM"
echo "  Installing dependencies..."
pip3 install -r "$DIR/requirements.txt" --quiet

echo "  Starting server at http://localhost:5001"
echo ""
python3 "$DIR/app.py"
