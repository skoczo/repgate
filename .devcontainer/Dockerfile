# devcontainer with graphviz
FROM debian:bookworm-slim

# Install graphviz and other system tools
RUN apt-get update && apt-get install -y \
    graphviz \
    make \
    build-essential \
    procps \
    && rm -rf /var/lib/apt/lists/*

# install Chrome browser
RUN apt-get update && apt-get install -y \
    wget \
    ca-certificates \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*
