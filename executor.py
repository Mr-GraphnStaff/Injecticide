import requests

def send_payload(url, key, prompt):
    res = requests.post(
        url,
        json={"prompt": prompt},
        headers={"Authorization": f"Bearer {key}"}
    )
    return res.json()