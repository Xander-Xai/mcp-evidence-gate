"""Standalone v1 SBOM contract fixture validator; intentionally not Core logic."""
import hashlib, json
from pathlib import Path

ROOT = Path(__file__).parent

def sha256(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

def evaluate(case):
    artifact = ROOT / case["artifact"]
    if case["sbom"] is None:
        return {"state": "INCONCLUSIVE", "reason": "sbom_missing"}
    sbom_path = ROOT / case["sbom"]
    try:
        doc = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"state": "INCONCLUSIVE", "reason": "sbom_unparseable"}
    supported = doc.get("bomFormat") == "CycloneDX" and doc.get("specVersion") in {"1.4", "1.5"}
    components = doc.get("components")
    if not supported or not isinstance(components, list) or not components:
        return {"state": "INCONCLUSIVE", "reason": "sbom_unparseable"}
    expected = sha256(artifact)
    actual = doc.get("metadata", {}).get("component", {}).get("hashes", [{}])[0].get("content")
    if actual != expected.removeprefix("sha256:"):
        return {"state": "BLOCKED", "reason": "artifact-sbom binding mismatch", "binding_expected": expected, "actual": "sha256:" + str(actual)}
    return {"state": "COMPLETE", "reason": "identity PASS; package inventory parsed; evidence complete", "artifact_digest": expected, "sbom_digest": sha256(sbom_path), "packages": len(components)}

def main():
    cases = json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))
    actual = []
    for case in cases:
        result = evaluate(case)
        row = {"id": case["id"], "expected": case["expected"], **result}
        actual.append(row)
        print(json.dumps(row, ensure_ascii=False, sort_keys=True))
    assert all(x["state"] == x["expected"] for x in actual), actual
    (ROOT / "actual-results.json").write_text(json.dumps(actual, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("SBOM_FIXTURE_VALIDATION=PASS")

if __name__ == "__main__":
    main()
