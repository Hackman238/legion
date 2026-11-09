# Legion Dockerfile - web interface, headless CLI and MCP server (no desktop UI)
FROM kalilinux/kali-rolling:latest

# Install system dependencies: Python, Nmap and a browser for screenshots
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-pip python3-venv \
    nmap git curl \
    chromium chromium-driver \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /opt/legion

# Copy Legion source code
COPY . /opt/legion

# Install Python dependencies
RUN pip3 install --break-system-packages --upgrade pip && \
    pip3 install --break-system-packages -r requirements.txt

# Project files, logs and settings live here; mount a volume to keep them
ENV LEGION_HOME=/data
VOLUME ["/data"]

# The web interface listens on 5000 and must bind all interfaces to be reachable from the host
EXPOSE 5000
CMD ["python3", "legion.py", "--web", "--web-bind-all"]

# Usage notes:
# - Web UI (scans need raw sockets, hence --cap-add):
#   docker run --rm -p 5000:5000 -v legion-data:/data --cap-add=NET_RAW --cap-add=NET_ADMIN legion
# - Headless CLI:
#   docker run --rm -v "$PWD:/work" legion python3 legion.py --headless --input-file /work/targets.txt \
#       --staged-scan --output-file /work/results.json
# - MCP server:
#   docker run --rm -i legion python3 legion.py --mcp-server
