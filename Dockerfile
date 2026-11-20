FROM python:3.12-slim

LABEL org.opencontainers.image.title="AI Tarpit" \
      org.opencontainers.image.description="Honeypot disrupting and slowing down AI-agent attacks" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/rbidou/aitarpit"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
# Install the runtime dependencies only; the project itself is run from the source tree.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 tarpit && mkdir -p /data /config && chown tarpit /data
COPY aitarpit.py test.py README.md LICENSE ./
COPY aitarpit ./aitarpit
COPY tester ./tester
USER tarpit

# Config is read from /config/aitarpit.json; the SQLite database should point to /data.
# The admin listener must be bound to 0.0.0.0 inside the container to be published -
# publish it on the host loopback only:  -p 127.0.0.1:8443:8443
VOLUME ["/data"]
EXPOSE 8080 8443
ENTRYPOINT ["python", "aitarpit.py"]
CMD ["run", "-c", "/config/aitarpit.json"]
