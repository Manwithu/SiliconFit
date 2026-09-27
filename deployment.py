from pathlib import Path
def deployment_assessment(root):
    root=Path(root); checks=[{"name":"Project exists","status":"PASS" if root.exists() else "WARN","detail":str(root)}]
    for name,label,detail in [("README.md","README","Add setup and deployment instructions."),(".env.example","Environment template","Document required variables without committing secrets."),("Dockerfile","Dockerfile","Optional for projects that do not use containers.")]:
        ok=(root/name).exists(); checks.append({"name":label,"status":"PASS" if ok else "WARN","detail":("Found "+name+".") if ok else detail})
    py=(root/"requirements.txt").exists() or (root/"pyproject.toml").exists(); checks.append({"name":"Python dependency manifest","status":"PASS" if py else "WARN","detail":"Dependency metadata found." if py else "No Python dependency manifest detected."})
    return {"checks":checks,"suggested_path":"Use a clean environment, install dependencies, configure secrets through the deployment platform, run tests, build, deploy, then perform a health check."}
