FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (git for automatic git push)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir pyyaml

# Copy script and default config
COPY nginx_log_to_csv.py nginx_log_to_csv.yaml ./

# Default work directory for mounted logs and outputs
WORKDIR /data

# By default run the converter; arguments (input/output/etc.) are passed at runtime
ENTRYPOINT ["python", "/app/nginx_log_to_csv.py"]

