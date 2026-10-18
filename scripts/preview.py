"""Local UI/API preview only. Active testing requires the isolated Compose deployment."""

import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
if not (root / ".env").exists():
    raise SystemExit("Run python scripts/setup_env.py first.")
for line in (root / ".env").read_text(encoding="utf-8").splitlines():
    if line and not line.startswith("#") and "=" in line:
        key, value = line.split("=", 1)
        os.environ.setdefault(key, value)
(root / "data").mkdir(exist_ok=True)
os.environ["DATABASE_URL"] = "sqlite:///" + str(root / "data" / "preview.db").replace(
    "\\", "/"
)
os.environ["FRONTEND_DIR"] = str(root / "frontend" / "dist")
os.environ.pop("EXECUTION_GATEWAY_URL", None)
os.environ.pop("MODEL_GATEWAY_URL", None)
sys.path.insert(0, str(root / "backend"))
import uvicorn

uvicorn.run("app.main:app", host="127.0.0.1", port=8000)
