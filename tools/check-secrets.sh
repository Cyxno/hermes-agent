#!/bin/bash
# tools/check-secrets.sh — scan git-tracked/staged bestanden op secretpatronen.
# Gebruik: tools/check-secrets.sh            (scan gestagede bestanden, of alle bij --all)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

MODE="${1:-staged}"
if [[ $MODE == "--all" ]]; then
  mapfile -t FILES < <(git ls-files --cached --others --exclude-standard)
else
  mapfile -t FILES < <(git diff --cached --name-only; git ls-files -o --exclude-standard)
fi

PATTERNS=(
  'sk-[A-Za-z0-9_-]{16,}'
  'OPENROUTER_API_KEY=[^$<[:space:]]'
  'bot[0-9]{7,}:[A-Za-z0-9_-]{30,}'
  '[0-9]{8,10}:[A-Za-z0-9_-]{35}'
  'BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY'
  'Authorization: Bearer [A-Za-z0-9._-]{16,}'
  '(api[_-]?key|apikey|token|password|passwd|secret)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9+/_-]{16,}'
)

rc=0
for f in "${FILES[@]}"; do
  [[ -f $f ]] || continue
  [[ $f == tools/check-secrets.sh ]] && continue  # de scanner bevat zijn eigen patronen
  for p in "${PATTERNS[@]}"; do
    if grep -nIE "$p" -- "$f" 2>/dev/null | grep -vE '\.env\.example|<[^>]*>|your[-_]?key|PLACEHOLDER| Voorbeeld|voorbeeld|read_text|environ|getenv|_FILE|REDACTED|sk-abcdefghij|startswith\("OPENROUTER_API_KEY'; then
      echo "VERDACHT PATROON '$p' in: $f" >&2
      rc=1
    fi
  done
done

if (( rc == 0 )); then
  echo "secretscan: geen problemen gevonden (${#FILES[@]} bestanden)"
fi
exit $rc
