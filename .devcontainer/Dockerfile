# devcontainer with graphviz
# use some light debian image and install go > 1.25.x and graphviz
FROM debian:bookworm-slim

# Install graphviz
RUN apt-get update 
RUN apt-get install -y graphviz make build-essential procps

# Install Go
RUN apt-get install -y wget
RUN wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

RUN apt-get install npm -y