def recommend_stack(problem,app_type,priorities,target):
    p=(problem or "").lower(); out=[]
    def add(name,fit,env,why,tradeoffs,cmd): out.append({"name":name,"fit":fit,"environment":env,"why":why,"tradeoffs":tradeoffs,"command":cmd})
    if app_type=="AI/ML" or any(k in p for k in ["machine learning","deep learning","model","computer vision","nlp"]):
        add("Python + PyTorch","Strong fit","Python 3.11+; Windows/Linux; GPU optional","Large ML ecosystem and experimentation.","Packaging and GPU dependencies need care.","python -m venv .venv")
        add("Python + scikit-learn","Strong fit for classical ML","Python 3.11+; CPU-friendly","Simple classical ML and evaluation.","Not intended for large deep-learning workloads.","pip install scikit-learn")
    elif app_type=="Web/API":
        add("Python + FastAPI","Strong fit","Python 3.11+; local/Linux container","Fast API development with typed interfaces.","Production deployment needs server/container configuration.","pip install fastapi uvicorn")
        add("TypeScript + Node.js","Strong fit","Node.js LTS; Windows/Linux/cloud","Good web/full-stack ecosystem.","Requires Node package management.","npm init -y")
    elif app_type=="Desktop":
        add("Python + PySide6","Strong fit","Windows/Linux/macOS","Cross-platform Qt desktop development.","Packaging needs additional work.","pip install pyside6")
        add("C# + .NET","Strong fit","Windows/Linux","Strong desktop tooling.","UI framework choice affects portability.","dotnet new")
    elif app_type=="Embedded/IoT": add("C/C++","Strong fit","Target vendor toolchain","Direct hardware control and predictable resources.","Requires careful memory and portability engineering.","Use target SDK/toolchain")
    else:
        add("Python","General-purpose fit","Python 3.11+","Fast prototyping and broad libraries.","Not ideal for every latency-sensitive workload.","python -m venv .venv")
        add("TypeScript","General-purpose fit","Node.js LTS","Useful for web services and tooling.","Node/npm ecosystem management.","npm init -y")
    if "security" in priorities:
        for x in out: x["why"]+=" Validate security with tests, dependency checks and static analysis."
    if "Performance" in priorities:
        for x in out: x["why"]+=" Measure the real workload before making performance claims."
    return out[:3]
