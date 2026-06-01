FROM python:3.11-slim
RUN pip install flask -q && apt-get update -qq && apt-get install -y --no-install-recommends curl -qq && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app.py .
CMD ["python", "app.py"]
