import os
import time

import httpx


def main():
    while True:
        try:
            with httpx.Client(trust_env=False, timeout=1900) as client:
                response = client.post(
                    os.environ["EXECUTION_GATEWAY_URL"] + "/internal/tick",
                    headers={"X-Internal-Token": os.environ["INTERNAL_TOKEN"]},
                )
                response.raise_for_status()
        except Exception as exc:
            print("Gateway unavailable:", type(exc).__name__, flush=True)
        time.sleep(2)


if __name__ == "__main__":
    main()
