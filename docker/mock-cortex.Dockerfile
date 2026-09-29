# Cortex API simulator used by the integration tests. NOT a Cortex replacement.
FROM python:3.12-slim
COPY tests/mock_cortex/server.py /mock/server.py
EXPOSE 9001
USER nobody
ENTRYPOINT ["python", "/mock/server.py", "--port", "9001"]
