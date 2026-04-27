FROM python:3.9-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir flask psycopg2-binary prometheus-client

CMD ["python", "main.py"]
