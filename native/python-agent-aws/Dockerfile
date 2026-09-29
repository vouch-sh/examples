FROM python:3.14-slim-trixie

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
# The registered client and its private key are kept here. Mount a volume to
# reuse them across runs; without one every run registers a new client.
ENV XDG_STATE_HOME=/state
CMD ["python", "agent.py"]
