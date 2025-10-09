# Legion Dockerfile - Recommended for Kali 2025+ and modern Linux
FROM kalilinux/kali-rolling:latest

# Install system dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-pip python3-setuptools python3-pyqt6 python3-pyqt6.qt6webkit \
    python3-pyqt6.qt6svg python3-pyqt6.qt6network python3-pyqt6.qt6widgets \
    python3-pyqt6.qt6gui python3-pyqt6.qt6core \
    libgl1-mesa-glx libglib2.0-0 libx11-6 xauth x11-apps \
    git curl \
    chromium chromium-driver \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /opt/legion

# Copy Legion source code
COPY . /opt/legion

# Install Python dependencies
RUN pip3 install --upgrade pip && \
    pip3 install -r requirements.txt

# Expose X11 for GUI
ENV DISPLAY=:0

# Default command: run Legion GUI (with optional MCP server)
# To use MCP: docker run ... legion python3 legion.py --mcp-server
# To use GUI: ensure X11 forwarding is set up (see README for details)
CMD ["python3", "legion.py"]

# Usage notes:
# - For GUI: run with X11 forwarding, e.g.:
#   docker run -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --network=host -it legion
# - For MCP/AI: add --mcp-server to CMD or entrypoint as needed
