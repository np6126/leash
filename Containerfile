FROM python:3.12-slim

# mitmproxy pinned: floating builds risk silently importing breaking hook
# changes on every --no-cache rebuild. Bump deliberately, with verification
# that the addon's http_connect / request / response / responseheaders hooks
# still fire end-to-end (see addon/allowlist_logger.py).
RUN pip install --upgrade pip && pip install --no-cache-dir mitmproxy==12.2.3 PyYAML

COPY addon/ /addon/

VOLUME ["/root/.mitmproxy", "/logs", "/etc/leash"]

EXPOSE 8080

CMD ["mitmdump", \
     "--mode", "regular", \
     "--listen-port", "8080", \
     "--listen-host", "0.0.0.0", \
     "-s", "/addon/allowlist_logger.py"]
