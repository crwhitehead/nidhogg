FROM python:3.8-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -r nidhogg && useradd -r -g nidhogg -m -d /home/nidhogg nidhogg

# Set up working directory
WORKDIR /app

RUN pip install --no-cache-dir python-magic crosshair-tool requests beautifulsoup4

# Copy the Nidhogg source code
COPY nidhogg/ /app/nidhogg/
COPY setup.py /app/
COPY pyproject.toml /app/
COPY examples/ /app/examples/

# Install Nidhogg and its dependencies
RUN pip install --no-cache-dir -e .

# Create directories for analysis and results
RUN mkdir -p /data/input /data/output && \
    chown -R nidhogg:nidhogg /data

# Copy the scanning script
COPY scan_package.py /app/

# Copy and set the entrypoint script
COPY docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh && \
    chown -R nidhogg:nidhogg /app

# Switch to non-root user
USER nidhogg

# Set the entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]