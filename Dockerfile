FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
RUN useradd -m -u 1000 bot && mkdir /data && chown bot:bot /data
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src/ .
USER bot
ENV DATA_DIR=/data
VOLUME /data
CMD ["python", "run.py"]
