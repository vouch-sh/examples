FROM python:3.14-slim-trixie

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# settings.py refuses to load without SECRET_KEY. These build steps sign nothing, so
# they get a throwaway key scoped to each RUN; the image and container never see it.
RUN SECRET_KEY=build-only-not-used-at-runtime python manage.py migrate --run-syncdb
RUN SECRET_KEY=build-only-not-used-at-runtime python manage.py collectstatic --noinput

EXPOSE 3000
# runserver is a development server; uvicorn serves the ASGI app.
# Django implements no ASGI lifespan events.
CMD ["uvicorn", "asgi:application", "--host", "0.0.0.0", "--port", "3000", "--lifespan", "off"]
