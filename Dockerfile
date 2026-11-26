FROM python:3.12-slim
WORKDIR /srv
COPY app/ app/
ENV BG_DB=/data/breakglass.db PORT=8080
VOLUME /data
USER 10001
EXPOSE 8080
CMD ["python","app/breakglass.py"]
