# Certificate Mounting

Place Cloudflare Origin Certificates at runtime by mounting the PEM and key files into this directory.

Required filenames:
- `origin.pem`
- `origin.key`

Example Docker run:
```
docker run -d \
  -p 8443:8443 \
  -v /path/to/origin.pem:/deploy/certs/origin.pem \
  -v /path/to/origin.key:/deploy/certs/origin.key \
  injecticide:prod
```

> Do **not** commit actual certificates to version control. These paths are placeholders only.
