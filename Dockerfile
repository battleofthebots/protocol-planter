FROM ghcr.io/battleofthebots/botb-base-image:latest

COPY scripts/server.py /

EXPOSE 13942/tcp

USER user
CMD python3 /server.py

# Check if python script is still running
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD ps -e | grep -q "python3"