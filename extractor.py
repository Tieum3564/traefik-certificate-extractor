import sys
import os
import errno
import time
import json
import logging
import docker
import threading
import argparse
from argparse import ArgumentTypeError as err
from base64 import b64decode
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path


logger = logging.getLogger(__name__)


def configureLogging(stream=None):
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S%z'))
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False


class PathType(object):
    def __init__(self, exists=True, type='file', dash_ok=True):
        '''exists:
                True: a path that does exist
                False: a path that does not exist, in a valid parent directory
                None: don't care
           type: file, dir, symlink, None, or a function returning True for valid paths
                None: don't care
           dash_ok: whether to allow "-" as stdin/stdout'''

        assert exists in (True, False, None)
        assert type in ('file', 'dir', 'symlink',
                        None) or hasattr(type, '__call__')

        self._exists = exists
        self._type = type
        self._dash_ok = dash_ok

    def __call__(self, string):
        if string == '-':
            # the special argument "-" means sys.std{in,out}
            if self._type == 'dir':
                raise err(
                    'standard input/output (-) not allowed as directory path')
            elif self._type == 'symlink':
                raise err(
                    'standard input/output (-) not allowed as symlink path')
            elif not self._dash_ok:
                raise err('standard input/output (-) not allowed')
        else:
            e = os.path.exists(string)
            if self._exists == True:
                if not e:
                    raise err("path does not exist: '%s'" % string)

                if self._type is None:
                    pass
                elif self._type == 'file':
                    if not os.path.isfile(string):
                        raise err("path is not a file: '%s'" % string)
                elif self._type == 'symlink':
                    if not os.path.symlink(string):
                        raise err("path is not a symlink: '%s'" % string)
                elif self._type == 'dir':
                    if not os.path.isdir(string):
                        raise err("path is not a directory: '%s'" % string)
                elif not self._type(string):
                    raise err("path not valid: '%s'" % string)
            else:
                if self._exists == False and e:
                    raise err("path exists: '%s'" % string)

                p = os.path.dirname(os.path.normpath(string)) or '.'
                if not os.path.isdir(p):
                    raise err("parent path is not a directory: '%s'" % p)
                elif not os.path.exists(p):
                    raise err("parent directory does not exist: '%s'" % p)

        return string


def restartContainerWithDomains(domains):
    client = docker.from_env()
    container = client.containers.list(filters = {"label" : "com.github.SnowMB.traefik-certificate-extractor.restart_domain"})
    for c in container:
        restartDomains = str.split(c.labels["com.github.SnowMB.traefik-certificate-extractor.restart_domain"], ',')
        if not set(domains).isdisjoint(restartDomains):
            logger.info('Restarting container %s for domains: %s',
                        c.id, ', '.join(sorted(set(domains).intersection(restartDomains))))
            c.restart()
            logger.info('Container %s restarted', c.id)


def certificatePaths(certificate):
    paths = [certificate] if isinstance(certificate, (str, Path)) else certificate
    return list(dict.fromkeys(os.path.abspath(path) for path in paths))


def readCerts(source, args):
    try:
        with open(source) as source_file:
            data = json.load(source_file)
    except (OSError, ValueError) as error:
        raise ValueError('Unable to read ' + source + ': ' + str(error)) from error

    # Determine ACME version
    acme_version = 2 if 'acme-v02' in data['Account']['Registration']['uri'] else 1

    # Find certificates
    if acme_version == 1:
        certs = data['DomainsCertificate']['Certs']
    elif acme_version == 2:
        certs = data['Certificates']

    records = []

    for c in certs:
        if acme_version == 1:
            name = c['Certificate']['Domain']
            privatekey = c['Certificate']['PrivateKey']
            fullchain = c['Certificate']['Certificate']
            sans = c['Domains']['SANs']
        elif acme_version == 2:
            name = c['Domain']['Main']
            privatekey = c['Key']
            fullchain = c['Certificate']
            sans = c['Domain']['SANs']

        certificate_domains = [name] + (sans or [])
        if args.include and not any(domain in args.include for domain in certificate_domains):
            continue
        if args.exclude and any(domain in args.exclude for domain in certificate_domains):
            continue

        # Decode private key, certificate and chain
        privatekey = b64decode(privatekey).decode('utf-8')
        fullchain = b64decode(fullchain).decode('utf-8')
        start = fullchain.find('-----BEGIN CERTIFICATE-----', 1)
        cert = fullchain[0:start]
        chain = fullchain[start:]

        targets = list(dict.fromkeys(certificate_domains if args.flat else [name]))
        records.append((targets, privatekey, cert, chain, fullchain))
    return records


def createCerts(args):
    records = []
    owners = {}
    for source in certificatePaths(args.certificate):
        logger.info('Reading ACME file: %s', source)
        try:
            source_records = readCerts(source, args)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError('Unable to extract from ' + source + ': ' + str(error)) from error
        logger.info('Selected %d certificate(s) from %s', len(source_records), source)
        for record in source_records:
            for name in record[0]:
                owners.setdefault(name, set()).add(source)
            records.append(record)

    conflicts = {name for name, sources in owners.items() if len(sources) > 1}
    for name in sorted(conflicts):
        logger.error('Conflicting certificates for %s in %s; skipping this domain. '
                     'Existing output is unchanged and may be stale.',
                     name, ', '.join(sorted(owners[name])))

    names = []
    for targets, privatekey, cert, chain, fullchain in records:
        for name in targets:
            if name in conflicts:
                continue
            if not args.dry:
                directory = Path(args.directory)
                if args.flat:
                    files = {name + '.key': privatekey, name + '.crt': fullchain,
                             name + '.chain.pem': chain}
                else:
                    directory = directory / name
                    files = {'privkey.pem': privatekey, 'cert.pem': cert,
                             'chain.pem': chain, 'fullchain.pem': fullchain}
                directory.mkdir(parents=True, exist_ok=True)
                for filename, content in files.items():
                    (directory / filename).write_text(content)
            logger.info('%s certificate for: %s (output: %s)',
                        'Would extract' if args.dry else 'Extracted',
                        name, args.directory if args.flat else str(Path(args.directory) / name))
            names.append(name)
    return list(dict.fromkeys(names))


class Handler(FileSystemEventHandler):

    def __init__(self, args):
        self.args = args
        self.paths = set(certificatePaths(args.certificate))
        self.timer = None
        self.generation = 0
        self.lock = threading.Lock()
        self.work_lock = threading.Lock()

    def watch(self, observer):
        for directory in sorted({str(Path(path).parent) for path in self.paths}):
            observer.schedule(self, directory)

    def close(self):
        with self.lock:
            self.generation += 1
            if self.timer is not None:
                self.timer.cancel()
                self.timer = None
        with self.work_lock:
            pass

    def on_created(self, event):
        self.handle(event)

    def on_modified(self, event):
        self.handle(event)

    def on_moved(self, event):
        self.handle(event)

    def handle(self, event):
        event_paths = [event.src_path, getattr(event, 'dest_path', '')]
        if not event.is_directory and any(
                path and os.path.abspath(os.fsdecode(path)) in self.paths
                for path in event_paths):
            logger.info('Certificate file changed (%s): %s', event.event_type,
                        ' -> '.join(path for path in event_paths if path))

            with self.lock:
                self.generation += 1
                generation = self.generation
                if self.timer is not None:
                    self.timer.cancel()
                self.timer = threading.Timer(2, self.doTheWork, args=(generation,))
                self.timer.start()

    def doTheWork(self, generation):
        with self.work_lock:
            with self.lock:
                if generation != self.generation:
                    return
                self.timer = None

            started = time.monotonic()
            logger.info('Starting certificate extraction%s',
                        ' (dry run)' if self.args.dry else '')
            try:
                domains = createCerts(self.args)
                if domains and self.args.restart_container and not self.args.dry:
                    restartContainerWithDomains(domains)
            except (OSError, ValueError) as error:
                logger.error('Unable to extract certificates: %s (elapsed: %.3fs)',
                             error, time.monotonic() - started)
                return
            logger.info('Certificate extraction finished: %d domain(s) %s in %.3fs',
                        len(domains), 'selected (dry run)' if self.args.dry else 'extracted',
                        time.monotonic() - started)


def parseArgs(argv=None):
    parser = argparse.ArgumentParser(
        description='Extract traefik letsencrypt certificates.')
    parser.add_argument('-c', '--certificate', nargs='+', type=PathType(
        exists=True, dash_ok=False), help='ACME files to watch (default ACME_FILE or acme.json)')
    parser.add_argument('-d', '--directory', default='.',
                        type=PathType(type='dir'), help='output folder')
    parser.add_argument('-f', '--flat', action='store_true',
                        help='outputs all certificates into one folder')
    parser.add_argument('-r', '--restart_container', action='store_true',
                        help="uses the docker API to restart containers that are labeled with 'com.github.SnowMB.traefik-certificate-extractor.restart_domain=<DOMAIN>' if the domain name of a generated certificates matches. Multiple domains can be seperated by ','")
    parser.add_argument('--dry-run', action='store_true', dest='dry',
                        help="Don't write files and do not start docker containers.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--include', nargs='*')
    group.add_argument('--exclude', nargs='*')

    args = parser.parse_args(argv)
    if args.certificate is None:
        try:
            args.certificate = [PathType(dash_ok=False)(os.environ.get('ACME_FILE', 'acme.json'))]
        except err as error:
            parser.error(str(error))
    args.certificate = certificatePaths(args.certificate)
    return args


if __name__ == "__main__":
    configureLogging()
    args = parseArgs()

    logger.info('Watching ACME files: %s', ', '.join(args.certificate))
    logger.info('Output directory: %s (flat: %s, dry run: %s, container restart: %s)',
                args.directory, args.flat, args.dry, args.restart_container)

    # Create event handler and observer
    event_handler = Handler(args)
    observer = Observer()

    # Register the directory to watch
    event_handler.watch(observer)

    # Main loop to watch the directory
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    event_handler.close()
    logger.info('Certificate monitoring stopped')
