FROM python:3.14-slim-trixie

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# A virtualenv keeps pip off the system interpreter, which it warns about as root.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
# The registered client and its private key are kept here. Mount a volume to
# reuse them across runs; without one every run registers a new client.
ENV XDG_STATE_HOME=/state
CMD ["python", "agent.py"]
