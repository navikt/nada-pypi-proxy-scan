FROM python:3.11

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt
COPY package-scan-script.py .

USER 65534

CMD ["python", "/app/package-scan-script.py"]
