# Release image: builds Legion from the public repo at a pinned ref.
# Build from this directory:  docker build -t legion .
# Another ref:                docker build --build-arg LEGION_REF=<sha-or-branch> -t legion .
# Headless smoke:  docker run --rm legion python legion.py --help
# Web UI (NO auth is built in - keep it on localhost/trusted networks only):
#   docker run --rm -p 127.0.0.1:5000:5000 legion python legion.py --web --web-port 5000 --web-bind-all
# Qt GUI needs an X server / XQuartz display forwarded.
# For the full Kali operator toolchain use the repo-root Dockerfile instead.
# Raw-socket scans need extra privilege, e.g. --cap-add NET_RAW --cap-add NET_ADMIN.
FROM python:3.15-slim

ARG LEGION_REF=1aa3c59d2edb78aa57bf39b2bfa379ad3b916ca9

ENV DEBIAN_FRONTEND=noninteractive \
    QT_QPA_PLATFORM=offscreen \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        git nmap xsltproc \
        libegl1 libgl1 libfontconfig1 libglib2.0-0 libxkbcommon0 \
        libdbus-1-3 libxcb-cursor0 \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/Hackman238/legion.git /legion \
    && git -C /legion fetch --depth 1 origin "${LEGION_REF}" \
    && git -C /legion checkout --detach FETCH_HEAD
WORKDIR /legion
RUN pip install --upgrade pip && pip install -r requirements.txt
RUN chmod +x startLegion.sh deps/*.sh scripts/*.sh 2>/dev/null || true

RUN useradd --create-home --shell /bin/sh legion \
    && chown -R legion:legion /legion
USER legion

CMD ["python", "legion.py"]
