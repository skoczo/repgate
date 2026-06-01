# devcontainer with graphviz
FROM debian:bookworm-slim

# Install graphviz and other system tools
RUN apt-get update && apt-get install -y \
    graphviz \
    make \
    build-essential \
    procps \
    && rm -rf /var/lib/apt/lists/*