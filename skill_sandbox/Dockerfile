FROM python:3.11-slim

RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY scan_rules.py /app/scan_rules.py

USER appuser

ENTRYPOINT ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9001"]
