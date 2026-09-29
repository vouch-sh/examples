FROM python:3.14-slim-trixie

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py migrate --run-syncdb

EXPOSE 3000
# runserver is a development server; uvicorn serves the ASGI app.
CMD ["uvicorn", "asgi:application", "--host", "0.0.0.0", "--port", "3000"]
