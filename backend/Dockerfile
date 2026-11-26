FROM python:3.11-slim

# Cegah Python menulis file .pyc dan pastikan log langsung tampil ke stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependensi sistem minimal untuk kompilasi/koneksi PostgreSQL dan healthcheck curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install dependensi Python terlebih dahulu untuk memanfaatkan Docker layer cache
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# Salin seluruh kode backend
COPY . /app

EXPOSE 8000

# Default entrypoint produksi; docker-compose.app.yml dapat menimpa dengan --reload saat dev
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
