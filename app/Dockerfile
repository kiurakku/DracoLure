FROM python:3.11-slim

WORKDIR /app

# Install runtime deps first so the layer caches across code changes.
RUN pip install --no-cache-dir \
    "Flask>=3.0" "psycopg2-binary>=2.9" "prometheus-client>=0.20" "gunicorn>=21.2"

COPY . .

EXPOSE 5000 8000

CMD ["python", "main.py"]
