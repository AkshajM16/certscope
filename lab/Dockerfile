FROM python:3.14.1-alpine3.21
RUN addgroup -S lab && adduser -S -G lab lab
COPY server.py /app/server.py
COPY certs /certs
RUN chown -R lab:lab /certs && chmod -R go-rwx /certs
USER lab
EXPOSE 443
CMD ["python", "/app/server.py"]
