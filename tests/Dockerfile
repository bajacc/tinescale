FROM golang:tip-bullseye

# Set up working directory
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    iproute2 \
    ca-certificates \
    iputils-ping \
    traceroute \
    curl \
    wget \
    iproute2 \
    tcpdump \
    wireguard-tools \
    dnsutils \
    net-tools \
 && apt-get clean

# Copy Go project
COPY . .

# Build tinescale binary
RUN go build -o tinescale ./cmd/tinescale && cp tinescale /usr/local/bin/

COPY tests/entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]