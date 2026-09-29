FROM python:3.14-slim-trixie

WORKDIR /app

# A virtualenv keeps pip off the system interpreter, which it warns about as root.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
CMD ["python", "device_flow.py"]
