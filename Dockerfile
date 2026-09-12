FROM python:3.13-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py stalwart_client.py dns_health.py ./
USER 65534
EXPOSE 3000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "3000"]
