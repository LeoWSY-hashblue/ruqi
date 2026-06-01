FROM python:3.11-slim
WORKDIR /app
RUN useradd --create-home --uid 10001 appuser
COPY app.py .
USER appuser
CMD ["python", "app.py"]
