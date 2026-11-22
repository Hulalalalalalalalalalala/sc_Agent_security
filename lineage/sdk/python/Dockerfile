FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY lct_sdk.py example_agent.py /app/
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/app/example_agent.py", "--port", "9001"]
