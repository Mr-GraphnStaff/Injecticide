from generator import generate_payloads
from executor import send_payload
from analyzer import analyze

def run(url, key):
    for p in generate_payloads():
        res = send_payload(url, key, p)
        print(p, analyze(res))

# CLI stub
if __name__ == '__main__':
    print('Injecticide skeleton ready.')