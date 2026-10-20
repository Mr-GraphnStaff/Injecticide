FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && groupadd --gid 10001 research \
    && useradd --uid 10001 --gid 10001 --no-create-home research \
    && mkdir /data && chown research:research /data
COPY . /app/research_mcp
USER 10001:10001
EXPOSE 8200
CMD ["python", "-m", "research_mcp.server"]
