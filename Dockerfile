ARG SOURCE_REGISTRY=""
ARG TAG=""

FROM ${SOURCE_REGISTRY}python:3.12.9-alpine3.21
# Switch to full alpine when https://github.com/astral-sh/uv/issues/6890 is resolved
# FROM ${SOURCE_REGISTRY}alpine:3.21

ARG NAME="resc_backend"
ARG DESCRIPTION="Repository Scanner Backend"
ARG VERSION=${VERSION}
ARG RUN_AS_USER="apiuser"
ARG RUN_AS_GROUP="apiuser"
ARG UID=10001
ARG GID=10002

# Initialize AAB inner layer
# TODO add any files under rootfs that are needed for proxy settings
COPY rootfs/ /
RUN if [ -e init.sh ] ; then chmod +x /init.sh ; sh /init.sh; fi

ENV UV_INSTALL_DIR='/usr/bin'

# Back to Normal operations
RUN sh /uv-installer.sh \
    && apk upgrade \
    && apk add --no-cache curl git nginx build-base linux-headers \
    && apk add --no-cache --virtual .build-deps pcre-dev gcc musl-dev python3-dev libffi-dev unixodbc-dev openssl-dev \
    && curl -O https://download.microsoft.com/download/7/6/d/76de322a-d860-4894-9945-f0cc5d6a45f8/msodbcsql18_18.4.1.1-1_amd64.apk \
    && curl -O https://download.microsoft.com/download/7/6/d/76de322a-d860-4894-9945-f0cc5d6a45f8/mssql-tools18_18.4.1.1-1_amd64.apk \
    && curl -O https://download.microsoft.com/download/7/6/d/76de322a-d860-4894-9945-f0cc5d6a45f8/msodbcsql18_18.4.1.1-1_amd64.sig \
    && curl -O https://download.microsoft.com/download/7/6/d/76de322a-d860-4894-9945-f0cc5d6a45f8/mssql-tools18_18.4.1.1-1_amd64.sig \
    && apk add gnupg \
    && curl https://packages.microsoft.com/keys/microsoft.asc  | gpg --import - \
    && gpg --verify msodbcsql18_18.4.1.1-1_amd64.sig msodbcsql18_18.4.1.1-1_amd64.apk \
    && gpg --verify mssql-tools18_18.4.1.1-1_amd64.sig mssql-tools18_18.4.1.1-1_amd64.apk \
    && apk add --allow-untrusted msodbcsql18_18.4.1.1-1_amd64.apk \
    && apk add --allow-untrusted mssql-tools18_18.4.1.1-1_amd64.apk \
    && apk add g++ unixodbc-dev \
    && mkdir /resc_backend

COPY ./ /resc_backend
# COPY alembic.ini db.env requirements.txt pyproject.toml LICENSE.md MANIFEST.in SECURITY.md /resc_backend/
# COPY alembic /resc_backend/alembic
# COPY src /resc_backend/src
# COPY test_data /resc_backend/test_data

RUN addgroup -g $GID $RUN_AS_GROUP \
    && adduser -D -u $UID -G $RUN_AS_GROUP $RUN_AS_USER \
    && chown -R $RUN_AS_USER:$RUN_AS_GROUP ./resc_backend

USER $RUN_AS_USER

ENV PATH=$PATH:/home/apiuser/.local/bin

WORKDIR /resc_backend

# Install python for alpine when #6890 is resolved.
# RUN uv python install 3.12
RUN uv venv --python 3.12 \
    && uv add -r requirements.txt \
    && uv add pyodbc==5.1.0 \
    && uv pip install -e .

USER root

RUN apk --purge del gnupg .build-deps

USER $RUN_AS_USER
