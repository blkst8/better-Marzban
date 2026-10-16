ARG PYTHON_VERSION=3.12
# Xray pinned: 26.x removed mKCP header & seed (breaks existing VLESS-mKCP inbounds).
# Bump only after migrating those inbounds to finalmask/udp.
ARG XRAY_VERSION=24.12.31

FROM python:$PYTHON_VERSION-slim AS build
ARG XRAY_VERSION

ENV PYTHONUNBUFFERED=1

WORKDIR /code

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl unzip gcc python3-dev libpq-dev iproute2 \
    && curl -L -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" \
    && mkdir -p /usr/local/share/xray \
    && unzip -o /tmp/xray.zip -d /usr/local/share/xray \
    && chmod +x /usr/local/share/xray/xray \
    && ln -sf /usr/local/share/xray/xray /usr/local/bin/xray \
    && rm -rf /var/lib/apt/lists/* /tmp/xray.zip

COPY ./requirements.txt /code/
RUN python3 -m pip install --upgrade pip "setuptools<81" \
    && pip install --no-cache-dir --upgrade -r /code/requirements.txt \
    && python3 -c "from pkg_resources import get_distribution, DistributionNotFound; get_distribution('APScheduler')"

FROM python:$PYTHON_VERSION-slim

ENV PYTHON_LIB_PATH=/usr/local/lib/python${PYTHON_VERSION%.*}/site-packages
WORKDIR /code

RUN rm -rf $PYTHON_LIB_PATH/*

COPY --from=build $PYTHON_LIB_PATH $PYTHON_LIB_PATH
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /usr/local/share/xray /usr/local/share/xray

COPY . /code

RUN ln -s /code/marzban-cli.py /usr/bin/marzban-cli \
    && chmod +x /usr/bin/marzban-cli \
    && marzban-cli completion install --shell bash

CMD ["bash", "-c", "alembic upgrade head; python main.py"]
