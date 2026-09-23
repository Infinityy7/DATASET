"""Build a compact lookup index from the pinned MITRE ATT&CK STIX release."""

import hashlib
import json
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "enterprise-attack-19.2.json"
OUTPUT = ROOT / "attack_technique_index.jsonl"
EXPECTED_SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
SOURCE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json"


def main() -> None:
    if not SOURCE.exists():
        urllib.request.urlretrieve(SOURCE_URL, SOURCE)
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == EXPECTED_SHA256
    bundle = json.loads(SOURCE.read_text())
    rows = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
        if not ref:
            continue
        rows.append({
            "technique_id": ref["external_id"],
            "name": obj["name"],
            "tactics": sorted({p["phase_name"] for p in obj.get("kill_chain_phases", [])
                               if p.get("kill_chain_name") == "mitre-attack"}),
            "platforms": sorted(obj.get("x_mitre_platforms", [])),
            "reference_url": ref["url"],
            "release": "Enterprise ATT&CK v19.2",
        })
    rows.sort(key=lambda row: row["technique_id"])
    assert len(rows) == len({row["technique_id"] for row in rows})
    with OUTPUT.open("w") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    print(len(rows), hashlib.sha256(OUTPUT.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
