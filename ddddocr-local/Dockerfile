FROM python:3.12-slim
RUN pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ ddddocr
COPY server.py /app/server.py
WORKDIR /app
CMD ["python", "server.py", "9898"]
