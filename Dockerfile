FROM python:3.12-slim

# debian:trixie-slim in python:3.12-slim ships a high-severity liblzma5;
# pull the debian-security fix (5.8.1-1+deb13u2) into the image.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get dist-clean

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py index.html ./
EXPOSE 5002
CMD ["python", "app.py"]
