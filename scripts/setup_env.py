"""Create local secrets once; never overwrite an existing .env."""

import base64
import os
import secrets
from pathlib import Path

destination = Path(__file__).resolve().parents[1] / ".env"
with destination.open("x", encoding="utf-8") as f:
    f.write(
        "\n".join(
            [
                "APP_TOKEN=" + secrets.token_urlsafe(32),
                "INTERNAL_TOKEN=" + secrets.token_urlsafe(32),
                "ENCRYPTION_KEY=" + base64.urlsafe_b64encode(os.urandom(32)).decode(),
                "POSTGRES_PASSWORD=" + secrets.token_urlsafe(32),
                "MODEL_MAX_USD_PER_MILLION_TOKENS=0",
                "MODEL_CLOUD_BASE_URLS=",
                "MODEL_LOCAL_BASE_URLS=",
                "",
            ]
        )
    )
print("Created .env. Copy APP_TOKEN into the local UI. Keep this file private.")
