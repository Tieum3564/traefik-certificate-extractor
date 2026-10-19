# Use Python on Alpine Linux as base image
FROM python:alpine

# Create working directory
RUN mkdir -p /app
WORKDIR /app

# Copy requirements.txt to force Docker not to use the cache
COPY requirements.txt /app

# Install app dependencies
RUN pip3 install -r requirements.txt

# Copy app source
COPY . /app

# Define entrypoint of the app
ENV ACME_FILE=data/acme.json
ENTRYPOINT ["python3", "-u", "extractor.py", "-d", "certs"]

	# Check that the extractor remains the container's main process
	HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
		CMD python3 -c "import sys; sys.exit(0 if b'extractor.py' in open('/proc/1/cmdline', 'rb').read() else 1)"
