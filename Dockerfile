# Base stage with Python
FROM python:3.11-slim as backend

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install additional web dependencies
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    websockets \
    python-multipart \
    aiofiles \
    jinja2 \
    python-jose[cryptography] \
    passlib[bcrypt] \
    redis \
    celery

# Copy application code
COPY . .

# Node stage for building frontend
FROM node:18-alpine as frontend

WORKDIR /app/frontend

# Copy package files
COPY webapp/frontend/package*.json ./
RUN npm ci

# Copy frontend source
COPY webapp/frontend/ .
RUN npm run build

# Final stage
FROM python:3.11-slim

WORKDIR /app

# Copy from backend stage
COPY --from=backend /app /app

# Copy built frontend
COPY --from=frontend /app/frontend/dist /app/webapp/static

# Expose ports
EXPOSE 8000

# Run the application
CMD ["uvicorn", "webapp.app:app", "--host", "0.0.0.0", "--port", "8000"]
