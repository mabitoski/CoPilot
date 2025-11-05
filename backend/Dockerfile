FROM debian:12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python

# Update package lists and install all dependencies in one layer for efficiency
RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    python3.11 \
    python3-pip \
    python3.11-venv \
    python3.11-dev \
    wkhtmltopdf \
    libmagic1 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create and activate virtual environment
RUN python3.11 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install setuptools in one step
RUN /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel

WORKDIR /opt/copilot/backend

# Copy only requirements first for better caching
COPY requirements.txt ./

# Install Python dependencies
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Install Playwright dependencies and browsers
RUN playwright install-deps && \
    playwright install

# Copy application source
COPY . .
COPY wait-for-it.sh /usr/wait-for-it.sh
RUN chmod +x /usr/wait-for-it.sh

# Create file-store folder
RUN mkdir -p file-store

# Expose ports
EXPOSE 5000

ENV SERVER_IP=0.0.0.0

# Connector Credentials
# ! SETTING UP YOUR CONNECTORS DEMOs https://www.youtube.com/@taylorwalton_socfortress/videos! #
ENV WAZUH_INDEXER_URL=https://1.1.1.1:9200 \
    WAZUH_INDEXER_USERNAME=admin \
    WAZUH_INDEXER_PASSWORD=admin \
    WAZUH_MANAGER_URL=https://1.1.1.1 \
    WAZUH_MANAGER_USERNAME=dummy \
    WAZUH_MANAGER_PASSWORD=dummy \
    GRAYLOG_URL=http://1.1.1.1 \
    GRAYLOG_USERNAME=dummy \
    GRAYLOG_PASSWORD=dummy \
    SHUFFLE_URL=https://1.1.1.1 \
    SHUFFLER_API_KEY=dummy \
    DFIR_IRIS_URL=https://1.1.1.1 \
    DFIR_IRIS_API_KEY=dummy \
    VELOCIRAPTOR_URL=https://1.1.1.1 \
    VELOCIRAPTOR_API_KEY_PATH=dummy \
    SUBLIME_URL=http://1.1.1.1 \
    SUBLIME_API_KEY=dummy \
    INFLUXDB_URL=http://1.1.1.1 \
    INFLUXDB_API_KEY=dummy \
    INFLUXDB_ORG_AND_BUCKET=dummy,dummy \
    ASKSOCFORTRESS_URL=https://knowledge.socfortress.co \
    ASKSOCFORTRESS_API_KEY=dummy \
    SOCFORTRESSTHREATINTEL_URL=https://intel.socfortress.co/search \
    SOCFORTRESSTHREATINTEL_API_KEY=dummy \
    CORTEX_URL=http://1.1.1.1 \
    CORTEX_API_KEY=dummy \
    GRAFANA_URL=http://1.1.1.1 \
    GRAFANA_USERNAME=dummy \
    GRAFANA_PASSWORD=dummy \
    WAZUH_WORKER_PROVISIONING_URL=http://1.1.1.1 \
    EVENT_SHIPPER_URL=graylog_host \
    GELF_INPUT_PORT=gelf_port \
    ALERT_CREATION_PROVISIONING_URL=http://1.1.1.1

ARG COPILOT_API_KEY
ENV COPILOT_API_KEY=$COPILOT_API_KEY

# Run your application
# Use wait-for-it.sh to wait for the MySQL service to be ready before starting your application
CMD ["/usr/wait-for-it.sh", "copilot-mysql:3306", "--", "/opt/venv/bin/python", "copilot.py"]
