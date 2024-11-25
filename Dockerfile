# FROM debian:bullseye-slim
FROM python:3.13.0-slim-bullseye

# Dependencies installation (cron, wget)
RUN apt-get update && \
    apt-get install -y \
    cron \
    wget \
    curl \
    gnupg \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Manually download and install filebeat
RUN wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.16.0-amd64.deb && \
    dpkg -i filebeat-8.16.0-amd64.deb && \
    rm filebeat-8.16.0-amd64.deb

# Create dir for filebeat configuration file
RUN mkdir -p /etc/filebeat

# Create state directory
RUN mkdir -p /var/lib/ecs/state

# Copy template configuration file to container
COPY filebeat.yml /etc/filebeat/filebeat.yml

WORKDIR /app

# Install script dependencies
COPY . .
RUN pip install -r ./requirements.txt
RUN chmod +x ./shadowserver_ecs_logger.py

# Execute script at the start of the day
ENV SHADOWSERVER_ECS_LOGGER_CRON="0 0 * * *"

# Create cron file to execute python script based on cron expression passed as a Env Var
# Execute cron and filebeat at container startup
CMD echo "SHELL=/bin/bash" > /etc/cron.d/shadowserver-script-cron && \
    echo "${SHADOWSERVER_ECS_LOGGER_CRON} root /usr/local/bin/python3 /app/shadowserver_ecs_logger.py /app/config.ini >> /var/log/script.log 2>&1" >> /etc/cron.d/shadowserver-script-cron && \
    chmod 0644 /etc/cron.d/shadowserver-script-cron && \
    crontab /etc/cron.d/shadowserver-script-cron && \
    chmod go-w /etc/filebeat/filebeat.yml && \
    service cron start && \
    filebeat -e -c /etc/filebeat/filebeat.yml
