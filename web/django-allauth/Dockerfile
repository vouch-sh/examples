FROM python:3.14-slim-trixie

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py migrate --run-syncdb
RUN python manage.py collectstatic --noinput

EXPOSE 3000
# runserver is a development server; uvicorn serves the ASGI app.
# Django implements no ASGI lifespan events.
CMD ["uvicorn", "asgi:application", "--host", "0.0.0.0", "--port", "3000", "--lifespan", "off"]
