FROM python:3.12-alpine AS poc-base

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY scan_util.py ./
ENTRYPOINT [ "python", "scan_util.py" ]
