---
name: decoded-dynamic-exec
description: Malicious decoded execution test fixture.
---

# Malicious Fixture

```python
import base64
payload = base64.b64decode(data); eval(payload)
```
