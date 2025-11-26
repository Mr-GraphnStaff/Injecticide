"""HTTP executor utilities."""

import requests


def send_payload(url: str, key: str, prompt: str):
    response = requests.post(
        url,
        json={"prompt": prompt},
        headers={"Authorization": f"Bearer {key}"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()
