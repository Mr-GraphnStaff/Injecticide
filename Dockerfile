# Injecticide Dockerfile optimized for FastAPI deployment
FROM node:18 AS frontend-build
WORKDIR /app/frontend
COPY webapp/frontend/package*.json ./
RUN npm install
COPY webapp/frontend .
RUN npm run build

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install build dependencies (kept minimal for ARM64 compatibility)
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Copy compiled frontend assets
COPY --from=frontend-build /app/frontend/dist /app/static/dist

# Expose the FastAPI port
EXPOSE 8000

# Start the API server
CMD ["uvicorn", "webapp.api:app", "--host", "0.0.0.0", "--port", "8000"]
