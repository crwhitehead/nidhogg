FROM python:3.8-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Copy the Nidhogg source code
COPY nidhogg/ /app/nidhogg/
COPY setup.py /app/
COPY pyproject.toml /app/

# Install Nidhogg and its dependencies
RUN pip install --no-cache-dir python-magic crosshair-tool requests 

RUN pip install --no-cache-dir -e .

# Create directories for analysis and results
RUN mkdir -p /data/input /data/output

# Copy the scanning script
COPY scan_package.py /app/

# By default, containers run as root but we can specify a safer user
# For the sake of file permissions we'll keep root for now
# but in production consider creating a dedicated user

ENTRYPOINT ["python", "/app/scan_package.py"]