#!/bin/bash
# Security Audit — Claude Code Commands installer

set -e

DEST="$HOME/.claude/commands"
SRC="$(cd "$(dirname "$0")/commands" && pwd)"

echo "Security Audit — Claude Code Commands"
echo "======================================"
echo ""

# Check Claude Code is installed
if ! command -v claude &>/dev/null; then
  echo "WARNING: Claude Code CLI not found."
  echo "Install it from https://claude.ai/code before using these commands."
  echo ""
fi

# Create destination directory if needed
mkdir -p "$DEST"

# Install commands
cp "$SRC"/security-audit-*.md "$DEST/"

COUNT=$(ls "$SRC"/security-audit-*.md | wc -l | tr -d ' ')
echo "Installed $COUNT commands to $DEST"
echo ""
echo "Available commands:"
for f in "$SRC"/security-audit-*.md; do
  NAME=$(basename "$f" .md)
  DESC=$(grep '^description:' "$f" | head -1 | sed 's/description: *"//' | sed 's/".*//' | cut -c1-70)
  printf "  /%-35s %s\n" "$NAME" "$DESC"
done
echo ""
echo "Usage:"
echo "  /security-audit-full /path/to/your/project"
echo "  /security-audit-owasp-top10 /path/to/your/project"
echo ""
echo "Done. Open Claude Code in your project and run /security-audit-full to start."
