from pathlib import Path
NAMES={"requirements.txt","pyproject.toml","package.json","package-lock.json","poetry.lock","Pipfile","Cargo.toml","go.mod","pom.xml","build.gradle"}
def dependency_scan(root):
    root=Path(root); items=[]
    for f in root.rglob("*"):
        if f.is_file() and f.name in NAMES and not any(p in f.parts for p in {".venv","venv","node_modules",".git"}):
            try: lines=[x for x in f.read_text(encoding="utf-8",errors="ignore").splitlines() if x.strip() and not x.strip().startswith("#")]; items.append({"file":str(f.relative_to(root)),"entries":len(lines),"status":"FOUND"})
            except Exception as e: items.append({"file":str(f.relative_to(root)),"entries":0,"status":"ERROR: "+str(e)})
    return {"summary":f"Found {len(items)} dependency manifest(s). This local check does not claim vulnerability status.","items":items}
