from pathlib import Path
IGNORE={".git",".venv","venv","node_modules","__pycache__",".pytest_cache","dist","build"}
EXT={".py":"Python",".js":"JavaScript",".ts":"TypeScript",".java":"Java",".c":"C",".cpp":"C++",".cs":"C#",".go":"Go",".rs":"Rust",".kt":"Kotlin",".swift":"Swift",".html":"HTML",".css":"CSS"}
DEPS={"requirements.txt","pyproject.toml","package.json","package-lock.json","poetry.lock","Pipfile","Cargo.toml","go.mod","pom.xml","build.gradle"}
def scan_project(root):
    root=Path(root)
    if not root.exists(): return {"file_count":0,"languages":[],"test_file_count":0,"dependency_file_count":0,"entry_points":[],"project_files":[]}
    fs=[x for x in root.rglob("*") if x.is_file() and not any(p in IGNORE for p in x.parts)]
    tests=[x for x in fs if "test" in x.name.lower() or "spec" in x.name.lower()]
    deps=[x for x in fs if x.name in DEPS]
    entries=[n for n in ["app.py","main.py","server.py","index.js","index.ts","main.cpp","main.c","Program.cs"] if (root/n).exists()]
    return {"file_count":len(fs),"languages":sorted({EXT[x.suffix.lower()] for x in fs if x.suffix.lower() in EXT}),"test_file_count":len(tests),"dependency_file_count":len(deps),"entry_points":entries,"project_files":sorted({x.name for x in fs if x.name in DEPS or x.name.lower() in {"readme.md","dockerfile",".env.example"}})}
