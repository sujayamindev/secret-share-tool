FROM python:3.12-slim

# Don't run the app as root. If something in the app or a dependency were
# exploited, the attacker gets an unprivileged user inside the container
# rather than root. The UID is fixed so the host's ./data directory can be
# chown'ed to match it (see README, "Deployment").
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# SQLite file lives here, volume-mounted in docker-compose so data survives container restarts
RUN mkdir -p /app/data && chown app:app /app/data

USER app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
