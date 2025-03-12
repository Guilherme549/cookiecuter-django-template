FROM python:3.10

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
RUN apt-get update && apt-get install -y \
    python3-dev \
    default-libmysqlclient-dev \
    software-properties-common

COPY ./pyproject.toml /app/pyproject.toml
RUN pip install .

COPY . /app
