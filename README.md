# Traefik Certificate Extractor

Forked from [DanielHuisman/traefik-certificate-extractor](https://github.com/DanielHuisman/traefik-certificate-extractor)

Tool to extract Let's Encrypt certificates from one or more Traefik ACME storage files. Can automatically restart containers using the docker API.

## Installation
```shell
git clone https://github.com/Tieum3564/traefik-certificate-extractor.git
cd traefik-certificate-extractor
```

## Usage
```shell
usage: extractor.py [-h] [-c CERTIFICATE [CERTIFICATE ...]] [-d DIRECTORY] [-f] [-r] [--dry-run]
                    [--include [INCLUDE [INCLUDE ...]] | --exclude
                    [EXCLUDE [EXCLUDE ...]]]

Extract traefik letsencrypt certificates.

optional arguments:
  -h, --help            show this help message and exit
  -c CERTIFICATE [CERTIFICATE ...], --certificate CERTIFICATE [CERTIFICATE ...]
                        ACME files to watch (default ACME_FILE or acme.json)
  -d DIRECTORY, --directory DIRECTORY
                        output folder
  -f, --flat            outputs all certificates into one folder
  -r, --restart_container
                        uses the docker API to restart containers that are
                        labeled accordingly
  --dry-run             Don't write files and do not start docker containers.
  --include [INCLUDE [INCLUDE ...]]
  --exclude [EXCLUDE [EXCLUDE ...]]
```
For local runs, the default input is `./acme.json` and the output directory is the current directory. Set `ACME_FILE` to override the single default input. Explicit `-c` paths replace that default. Docker defaults to `./data/acme.json` and writes to `./certs`.

Pass multiple paths after a single `-c` option:

```shell
python extractor.py -c /opt/traefik/acme.json /opt/other-traefik/acme.json -d ./certs
```

The output directory passed with `-d` must already exist. All input files must exist and be readable. Each file can independently use a legacy ACME v1/v2 format with `Account` at the root, or the Traefik v2/v3 format organized by certificate resolver (for example, `letsencrypt`). All resolvers in a file are read; empty certificate lists and `Certificates: null` are supported. `--include` and `--exclude` apply across all sources and retain certificate-level matching against main names and SANs.

All input files are monitored, including files in different directories and files replaced atomically. After two seconds without a matching change, all sources are read and checked before writing certificates. Extraction starts on file changes, not immediately at startup. Unreadable or malformed inputs abort the batch before writes; monitoring continues so a later update can recover.

If multiple sources would write the same domain, an error lists the domain and source paths, and only that domain's output is skipped. Non-conflicting domains are still extracted. In the default layout, only main domain directories are output targets. In flat mode (`-f`), main names and SANs are output targets, so a shared SAN is skipped without blocking other names on either certificate. Existing files for a conflicting domain are not deleted or overwritten and may be stale. Removing a conflict allows extraction on the next matching change.

`--dry-run` checks every input and reports conflicts without writing files or restarting containers. With `-r`, each matching container is restarted at most once per successful batch; skipped domains do not trigger restarts.

## Logs

Application logs are written immediately to stderr, one message per line, with a human-readable local date, UTC offset and severity level. Docker captures these messages without requiring unbuffered Python output.

```text
2026-10-19 14:30:00+0200 [INFO] Starting certificate extraction
2026-10-19 14:30:00+0200 [INFO] Reading ACME file: /app/data/acme.json
2026-10-19 14:30:00+0200 [INFO] Selected 1 certificate(s) from /app/data/acme.json
2026-10-19 14:30:00+0200 [INFO] Extracted certificate for: example.com (output: /app/certs/example.com)
2026-10-19 14:30:00+0200 [INFO] Certificate extraction finished: 1 domain(s) extracted in 0.012s
```

Logs also report watched paths, output settings, file changes, container restarts and extraction errors. Dry runs are explicitly marked. Certificate contents and private keys are never logged. The timezone follows the runtime environment, which may default to UTC inside Docker.

## Docker
Docker Hub image name: [tymat3564/certsextractor](https://hub.docker.com/r/tymat3564/certsextractor/).
Example run:
```shell
docker run --name extractor -d \
  -v /opt/traefik:/app/data \
  -v ./certs:/app/certs \
  -v /var/run/docker.socket:/var/run/docker.sock \
  tymat3564/certsextractor:latest -r
```
Mount the whole folder containing the traefik certificate file (`acme.json`) as `/app/data`. The extracted certificates are going to be written to `/app/certs`.

To watch multiple sources, mount their directories and provide explicit paths. The default `/app/data/acme.json` is not required when `-c` is supplied:

```shell
docker run --name extractor -d \
  -v /opt/traefik-one:/app/source-one:ro \
  -v /opt/traefik-two:/app/source-two:ro \
  -v ./certs:/app/certs \
  tymat3564/certsextractor:latest \
  -c /app/source-one/acme.json /app/source-two/acme.json
```

Build an image from this checkout with `docker build -t tymat3564/certsextractor:latest .`. After authenticating to Docker Hub with `docker login`, publish it with `docker push tymat3564/certsextractor:latest`.

The docker socket is used to find any containers with this label: `com.github.SnowMB.traefik-certificate-extractor.restart_domain=<DOMAIN>`.
If the domains of an extracted certificate and the restart domain matches, the container is restarted. Multiple domains can be given seperated by `,`.

### Docker Compose Example

The runnable example in [docker-compose/compose.yaml](docker-compose/compose.yaml) builds this checkout and extracts certificates from two ACME sources. Both source directories are read-only bind mounts; the output directory is a writable bind mount. Mount directories rather than individual files so atomic ACME file replacements remain visible.

Set these environment variables in your shell, or define them in `docker-compose/.env` using [docker-compose/.env.example](docker-compose/.env.example) as the template:

```shell
export ACME_ONE_DIR=/opt/traefik-one
export ACME_ONE_FILE=acme.json
export ACME_TWO_DIR=/opt/traefik-two
export ACME_TWO_FILE=acme.json
export CERTIFICATES_DIR=/opt/extracted-certificates
```

Use absolute host directory paths. Create all three directories before starting the service, and ensure both ACME files exist and are readable. `ACME_ONE_FILE` and `ACME_TWO_FILE` are filenames relative to their respective source directories and default to `acme.json` when omitted. Protect the output directory: it contains private keys.

From the repository root:

```shell
docker compose -f docker-compose/compose.yaml config
docker compose -f docker-compose/compose.yaml up -d --build
docker compose -f docker-compose/compose.yaml logs -f extractor
```

These variables configure Compose interpolation, not a multi-file runtime environment variable. Compose passes both container paths through `--certificate`, replacing the image's single-file `ACME_FILE` default. To add another source, add its directory bind mount and container file path to `command`.

The service extracts after an input file changes, not at startup. Conflicting output domains are logged and skipped; existing files for them remain untouched. Replace the example `--include` domains with your own, or remove the option and its values to extract all domains.

This example enables `-r` and bind-mounts `/var/run/docker.sock` to restart containers labeled with `com.github.SnowMB.traefik-certificate-extractor.restart_domain=example.com`. Change the label's domain to match an extracted certificate. The host Docker socket must exist and be accessible to the extractor; adjust the bind source if your daemon uses another socket path.

Docker socket access grants broad control over the daemon and can allow host-level compromise. Only run trusted images with this access. Remove both `-r` and the socket mount to disable container restarts.

Stop the example with `docker compose -f docker-compose/compose.yaml down`. Bind-mounted output remains on the host.

## Tests

```shell
python -m pip install -r requirements.txt
python -m unittest discover -v
```

## Output
```
certs/
    example.com/
        cert.pem
        chain.pem
        fullchain.pem
        privkey.pem
    sub.example.nl/
        cert.pem
        chain.pem
        fullchain.pem
        privkey.pem
certs_flat/
    example.com.crt
    example.com.key
    example.com.chain.pem
    sub.example.nl.crt
    sub.example.nl.key
    sub.example.nl.chain.pem
```
