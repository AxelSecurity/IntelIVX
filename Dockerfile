FROM mcr.microsoft.com/playwright/python:v1.60.0-jammy

WORKDIR /app

# Tesseract OCR per rilevamento testo in immagini (brand impersonation visiva)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-ita \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY url_analyzer/ ./url_analyzer/

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

EXPOSE 8081

CMD ["uvicorn", "url_analyzer.main:app", "--host", "0.0.0.0", "--port", "8081"]
