# IRIS app/worker image + iris_cortex_module (+ the generic web-extensions patch when missing).
#
#   docker build -f docker/Dockerfile -t iriswebapp_app_cortex:v2.4.29 .
#   # stacking on another module image (e.g. iris-email-module):
#   docker build -f docker/Dockerfile --build-arg BASE_IMAGE=iriswebapp_app_email:v2.4.29 -t iriswebapp_app_cortex:v2.4.29 .
#
ARG BASE_IMAGE=ghcr.io/dfir-iris/iriswebapp_app:v2.4.29
FROM ${BASE_IMAGE}

COPY . /opt/iris-cortex-module

RUN pip install --no-cache-dir /opt/iris-cortex-module \
    && if [ ! -f /iriswebapp/app/iris_engine/web_extensions.py ]; then \
         (command -v patch >/dev/null || (apt-get update && apt-get install -y --no-install-recommends patch \
            && rm -rf /var/lib/apt/lists/*)) \
         && patch -p2 -d /iriswebapp < /opt/iris-cortex-module/docker/0001-iris-v2.4.29-web-extensions-loader.patch; \
       else echo "web extensions loader already present, patch skipped"; fi \
    && python -c "import iris_cortex_module.core.results"
