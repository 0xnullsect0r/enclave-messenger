#!/usr/bin/env bash
# README.md carries a copy of ops/compose/compose.yml between two markers.
#   ci/readme-compose.sh           write the current file into README.md
#   ci/readme-compose.sh --check   fail if the copy is out of date
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
python3 - "$ROOT" "${1:-}" <<'PY'
import sys
root, mode = sys.argv[1], sys.argv[2]
readme = open(f"{root}/README.md").read()
compose = open(f"{root}/ops/compose/compose.yml").read()
begin = "<!-- BEGIN ops/compose/compose.yml"
end = "<!-- END ops/compose/compose.yml -->"
b = readme.index(begin)
b = readme.index("\n", b) + 1
e = readme.index(end)
want = "```yaml\n" + compose.rstrip("\n") + "\n```\n"
if mode == "--check":
    if readme[b:e] != want:
        sys.exit("README.md's copy of ops/compose/compose.yml is out of date: run ci/readme-compose.sh")
    print("README compose copy is current")
else:
    open(f"{root}/README.md", "w").write(readme[:b] + want + readme[e:])
    print("README.md updated")
PY
