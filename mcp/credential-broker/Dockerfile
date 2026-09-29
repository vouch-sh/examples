FROM python:3.14-slim-trixie

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
# The broker's registered client and its private key are kept here. Mount a
# volume to reuse them across restarts; without one each new container
# registers a new client on its first credential request.
ENV XDG_STATE_HOME=/state

EXPOSE 3000
CMD ["python", "server.py"]
