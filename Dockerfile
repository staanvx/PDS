FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    ca-certificates \
    git \
    unzip \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN wget -O /tmp/subfinder.zip https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && unzip /tmp/subfinder.zip -d /tmp/subfinder \
    && mv /tmp/subfinder/subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm -rf /tmp/subfinder /tmp/subfinder.zip

COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen || uv sync

RUN pip install --no-cache-dir git+https://github.com/laramies/theHarvester.git

COPY app ./app
COPY input ./input

RUN mkdir -p /app/output

CMD ["uv", "run", "python", "app/main.py"]
