#!/usr/bin/env bash
# Fails when prisma/schema.prisma and prisma/migrations disagree, ignoring the explicit
# allowlist of hand-written SQL objects in prisma/drift-allowlist.txt.
# Usage: SHADOW_DATABASE_URL=postgresql://... scripts/check-migration-drift.sh
set -euo pipefail
cd "$(dirname "$0")/.."
: "${SHADOW_DATABASE_URL:?set SHADOW_DATABASE_URL}"
diff_sql=$(pnpm exec prisma migrate diff \
  --from-migrations prisma/migrations \
  --to-schema-datamodel prisma/schema.prisma \
  --shadow-database-url "$SHADOW_DATABASE_URL" \
  --script 2>/dev/null)
allow=$(grep -vE '^\s*(#|$)' prisma/drift-allowlist.txt || true)
remaining=$(printf '%s\n' "$diff_sql" | grep -vE '^\s*(--|$)' | grep -vxF -f <(printf '%s\n' "$allow") || true)
if [ -n "$remaining" ]; then
  echo "Schema drift: schema.prisma has changes without a migration:" >&2
  printf '%s\n' "$remaining" >&2
  exit 1
fi
echo "No migration drift (allowlisted hand-written objects ignored)."
