FROM python:3.14-slim-trixie

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py migrate --run-syncdb

EXPOSE 3000
CMD ["python", "manage.py", "runserver", "0.0.0.0:3000"]
