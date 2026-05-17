FROM python:3.12-slim

RUN pip install --upgrade pip && pip install --no-cache-dir mitmproxy PyYAML

COPY addon/ /addon/

VOLUME ["/root/.mitmproxy", "/logs", "/etc/leash"]

EXPOSE 8080

CMD ["mitmdump", \
     "--mode", "regular", \
     "--listen-port", "8080", \
     "--listen-host", "0.0.0.0", \
     "-s", "/addon/allowlist_logger.py"]
