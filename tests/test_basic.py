from generator import generate_payloads

def test_payloads():
    assert len(generate_payloads()) > 0