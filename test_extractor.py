import argparse
from base64 import b64encode
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from watchdog.events import FileCreatedEvent, FileModifiedEvent, FileMovedEvent

import extractor


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'output'
        self.args = argparse.Namespace(certificate=[], directory=str(self.output),
                                       flat=False, dry=False, include=None,
                                       exclude=None, restart_container=False)
        self.log = io.StringIO()
        self.errors = io.StringIO()
        logging_handlers = patch.object(extractor.logger, 'handlers', [])
        logging_handlers.start()
        self.addCleanup(logging_handlers.stop)
        extractor.configureLogging(self.log)
        self.stdout = redirect_stdout(self.log)
        self.stderr = redirect_stderr(self.errors)
        self.stdout.__enter__()
        self.stderr.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)
        self.addCleanup(self.stderr.__exit__, None, None, None)

    def source(self, filename, domains, version=2):
        fullchain = ('-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n'
                     '-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n')
        encoded = b64encode(fullchain.encode()).decode()
        key = b64encode(b'private key').decode()
        certificates = []
        for name, sans in domains:
            if version == 2:
                certificates.append({'Domain': {'Main': name, 'SANs': sans},
                                     'Key': key, 'Certificate': encoded})
            else:
                certificates.append({'Certificate': {'Domain': name, 'PrivateKey': key,
                                                     'Certificate': encoded},
                                     'Domains': {'SANs': sans}})
        data = {'Account': {'Registration': {'uri': 'acme-v02' if version == 2 else 'acme-v01'}}}
        if version == 2:
            data['Certificates'] = certificates
        else:
            data['DomainsCertificate'] = {'Certs': certificates}
        path = self.root / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))
        self.args.certificate.append(str(path))
        return path

    def test_mixed_versions_and_duplicate_input(self):
        first = self.source('first/acme.json', [('first.test', None)], version=1)
        self.source('second/acme.json', [('second.test', [])])
        self.args.certificate.append(str(first.parent / '.' / first.name))
        self.assertEqual(extractor.createCerts(self.args), ['first.test', 'second.test'])
        for name in ['first.test', 'second.test']:
            self.assertEqual((self.output / name / 'privkey.pem').read_text(), 'private key')
            self.assertIn('leaf', (self.output / name / 'cert.pem').read_text())
            self.assertNotIn('leaf', (self.output / name / 'chain.pem').read_text())

    def test_hierarchical_conflict_keeps_unrelated_output(self):
        self.source('first.json', [('shared.test', []), ('first.test', [])])
        self.source('second.json', [('shared.test', []), ('second.test', [])])
        self.assertEqual(extractor.createCerts(self.args), ['first.test', 'second.test'])
        self.assertFalse((self.output / 'shared.test').exists())
        self.assertIn('[ERROR] Conflicting certificates for shared.test', self.log.getvalue())
        self.assertIn('first.json', self.log.getvalue())
        self.assertIn('second.json', self.log.getvalue())

    def test_flat_conflict_skips_only_shared_san(self):
        self.source('first.json', [('first.test', ['shared.test', 'first.test'])])
        self.source('second.json', [('second.test', ['shared.test'])])
        self.args.flat = True
        self.assertEqual(extractor.createCerts(self.args), ['first.test', 'second.test'])
        self.assertFalse((self.output / 'shared.test.key').exists())
        self.assertEqual((self.output / 'first.test.key').read_text(), 'private key')
        self.assertIn('chain', (self.output / 'second.test.chain.pem').read_text())

    def test_hierarchical_sans_are_not_output_conflicts(self):
        self.source('first.json', [('first.test', ['shared.test'])])
        self.source('second.json', [('second.test', ['shared.test'])])
        self.assertEqual(extractor.createCerts(self.args), ['first.test', 'second.test'])
        self.assertNotIn('[ERROR]', self.log.getvalue())

    def test_extraction_logs_are_timestamped_and_line_separated(self):
        source = self.source('first.json', [('first.test', []), ('second.test', [])])
        handler = extractor.Handler(self.args)
        self.addCleanup(handler.close)
        handler.doTheWork(0)
        lines = self.log.getvalue().splitlines()
        self.assertEqual(len(lines), 6)
        for line in lines:
            with self.subTest(line=line):
                datetime.strptime(line[:24], '%Y-%m-%d %H:%M:%S%z')
                self.assertEqual(line[24:32], ' [INFO] ')
        self.assertIn('Starting certificate extraction', lines[0])
        self.assertIn(str(source), lines[1])
        self.assertIn('Selected 2 certificate(s)', lines[2])
        self.assertIn('Extracted certificate for: first.test', lines[3])
        self.assertIn(str(self.output / 'first.test'), lines[3])
        self.assertIn('Extracted certificate for: second.test', lines[4])
        self.assertRegex(lines[5], r'finished: 2 domain\(s\) extracted in \d+\.\d{3}s$')
        self.assertNotIn('private key', self.log.getvalue())

    def test_failed_extraction_logs_error_without_success_summary(self):
        source = self.source('broken.json', [])
        source.write_text('{')
        handler = extractor.Handler(self.args)
        self.addCleanup(handler.close)
        handler.doTheWork(0)
        lines = self.log.getvalue().splitlines()
        datetime.strptime(lines[-1][:24], '%Y-%m-%d %H:%M:%S%z')
        self.assertIn('[ERROR] Unable to extract certificates:', lines[-1])
        self.assertIn(str(source), lines[-1])
        self.assertNotIn('extraction finished', self.log.getvalue())

    def test_conflict_preserves_existing_output(self):
        self.source('first.json', [('shared.test', [])])
        extractor.createCerts(self.args)
        certificate = self.output / 'shared.test' / 'cert.pem'
        certificate.write_text('existing certificate')
        self.source('second.json', [('shared.test', [])])
        self.assertEqual(extractor.createCerts(self.args), [])
        self.assertEqual(certificate.read_text(), 'existing certificate')
        self.assertIn('stale', self.log.getvalue())

    def test_filters_remain_certificate_scoped(self):
        self.source('first.json', [('first.test', ['included.test'])])
        self.source('second.json', [('second.test', [])])
        self.args.include = ['included.test']
        self.assertEqual(extractor.createCerts(self.args), ['first.test'])
        self.args.include = None
        self.args.exclude = ['included.test']
        self.assertEqual(extractor.createCerts(self.args), ['second.test'])

    def test_dry_run_has_no_output(self):
        self.source('first.json', [('first.test', [])])
        self.args.dry = True
        self.assertEqual(extractor.createCerts(self.args), ['first.test'])
        self.assertFalse(self.output.exists())
        self.assertIn('Would extract certificate for: first.test', self.log.getvalue())

    def test_invalid_input_aborts_before_writes(self):
        self.source('first.json', [('first.test', [])])
        broken = self.source('broken.json', [])
        broken.write_text('{')
        with self.assertRaisesRegex(ValueError, 'broken.json'):
            extractor.createCerts(self.args)
        self.assertFalse(self.output.exists())
        broken.unlink()
        with self.assertRaisesRegex(ValueError, 'broken.json'):
            extractor.createCerts(self.args)
        self.assertFalse(self.output.exists())

    def test_conflict_removal_allows_next_batch(self):
        self.source('first.json', [('shared.test', [])])
        second = self.source('second.json', [('shared.test', [])])
        self.assertEqual(extractor.createCerts(self.args), [])
        data = json.loads(second.read_text())
        data['Certificates'] = []
        second.write_text(json.dumps(data))
        self.assertEqual(extractor.createCerts(self.args), ['shared.test'])
        self.assertTrue((self.output / 'shared.test' / 'cert.pem').exists())

    def test_live_watcher_across_directories_and_atomic_replacement(self):
        first = self.source('first/acme.json', [('first.test', [])]).resolve()
        second = self.source('second/acme.json', [('second.test', [])]).resolve()
        self.args.certificate = [str(first), str(second)]
        self.args.restart_container = True
        handler = extractor.Handler(self.args)
        observer = extractor.Observer()
        handler.watch(observer)
        completed = threading.Event()
        with patch('extractor.restartContainerWithDomains', side_effect=lambda domains: completed.set()) as restart:
            observer.start()
            try:
                first.write_text(first.read_text())
                self.assertTrue(completed.wait(10), 'First source change was not processed')
                self.assertTrue((self.output / 'first.test' / 'cert.pem').exists())
                self.assertTrue((self.output / 'second.test' / 'cert.pem').exists())
                completed.clear()
                second.write_text(second.read_text())
                self.assertTrue(completed.wait(10), 'Second source change was not processed')
                completed.clear()
                replacement = first.with_suffix('.temporary')
                replacement.write_text(first.read_text())
                replacement.replace(first)
                self.assertTrue(completed.wait(10), 'Atomic replacement was not processed')
                completed.clear()
                previous_calls = restart.call_count
                first.write_text(first.read_text())
                second.write_text(second.read_text())
                self.assertTrue(completed.wait(10), 'Combined source changes were not processed')
                self.assertEqual(restart.call_count, previous_calls + 1)
                restart.assert_called_with(['first.test', 'second.test'])
            finally:
                observer.stop()
                observer.join()
                handler.close()


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.first = self.root / 'first.json'
        self.second = self.root / 'second.json'
        self.first.touch()
        self.second.touch()

    def test_single_multiple_and_duplicate_paths(self):
        self.assertEqual(extractor.parseArgs(['-c', str(self.first)]).certificate,
                         [str(self.first)])
        parsed = extractor.parseArgs(['-c', str(self.first), str(self.second), str(self.first)])
        self.assertEqual(parsed.certificate, [str(self.first), str(self.second)])

    def test_environment_default_and_explicit_override(self):
        with patch.dict('os.environ', {'ACME_FILE': str(self.first)}):
            self.assertEqual(extractor.parseArgs([]).certificate, [str(self.first)])
        with patch.dict('os.environ', {'ACME_FILE': str(self.root / 'missing')}):
            self.assertEqual(extractor.parseArgs(['-c', str(self.second)]).certificate,
                             [str(self.second)])

    def test_local_default(self):
        with patch.dict('os.environ', {}, clear=True), patch.object(
                extractor.os.path, 'exists', return_value=True), patch.object(
                extractor.os.path, 'isfile', return_value=True):
            self.assertEqual(extractor.parseArgs([]).certificate,
                             [str(Path.cwd() / 'acme.json')])

    def test_invalid_paths_and_empty_option(self):
        with redirect_stderr(io.StringIO()):
            for arguments in [['-c'], ['-c', '-'], ['-c', str(self.root)],
                              ['-c', str(self.root / 'missing')]]:
                with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                    extractor.parseArgs(arguments)
            with patch.dict('os.environ', {'ACME_FILE': str(self.root / 'missing')}):
                with self.assertRaises(SystemExit):
                    extractor.parseArgs([])


class WatcherTests(unittest.TestCase):
    def setUp(self):
        self.args = argparse.Namespace(certificate=['/first/acme.json', '/first/other.json',
                                                    '/second/acme.json'],
                                       restart_container=True, dry=False)
        self.handler = extractor.Handler(self.args)
        self.addCleanup(self.handler.close)

    def test_unique_parent_watches(self):
        observer = Mock()
        self.handler.watch(observer)
        self.assertEqual(observer.schedule.call_count, 2)
        observer.schedule.assert_any_call(self.handler, '/first')
        observer.schedule.assert_any_call(self.handler, '/second')

    @patch('extractor.threading.Timer')
    def test_created_modified_moved_and_debounce(self, timer):
        self.handler.on_created(FileCreatedEvent('/first/acme.json'))
        self.handler.on_modified(FileModifiedEvent('/second/acme.json'))
        self.handler.on_moved(FileMovedEvent('/first/temporary', '/first/other.json'))
        self.assertEqual(timer.call_count, 3)
        self.assertEqual(timer.return_value.cancel.call_count, 2)
        timer.assert_called_with(2, self.handler.doTheWork, args=(3,))
        self.assertEqual(timer.return_value.start.call_count, 3)
        self.handler.handle(FileModifiedEvent('/unrelated/first/acme.json'))
        self.handler.handle(FileModifiedEvent('/first/acme.json.backup'))
        directory = Mock(is_directory=True, src_path='/first/acme.json', dest_path='')
        self.handler.handle(directory)
        self.assertEqual(timer.call_count, 3)

    @patch('extractor.restartContainerWithDomains')
    @patch('extractor.createCerts', return_value=['first.test', 'second.test'])
    def test_stale_generation_skipped_and_restart_once(self, create, restart):
        self.handler.generation = 2
        self.handler.doTheWork(1)
        create.assert_not_called()
        self.handler.doTheWork(2)
        create.assert_called_once_with(self.args)
        restart.assert_called_once_with(['first.test', 'second.test'])

    @patch('extractor.restartContainerWithDomains')
    @patch('extractor.createCerts', return_value=[])
    def test_empty_and_dry_batches_do_not_restart(self, create, restart):
        self.handler.doTheWork(0)
        create.return_value = ['first.test']
        self.args.dry = True
        self.handler.doTheWork(0)
        restart.assert_not_called()

    @patch('extractor.restartContainerWithDomains')
    @patch('extractor.createCerts')
    def test_failed_batch_can_recover(self, create, restart):
        create.side_effect = [ValueError('broken input'), ['first.test']]
        with redirect_stderr(io.StringIO()):
            self.handler.doTheWork(0)
        restart.assert_not_called()
        self.handler.doTheWork(0)
        restart.assert_called_once_with(['first.test'])

    @patch('extractor.createCerts', return_value=[])
    def test_batches_wait_for_work_lock(self, create):
        started = threading.Event()

        def run_batch():
            started.set()
            self.handler.doTheWork(0)

        with self.handler.work_lock:
            worker = threading.Thread(target=run_batch)
            worker.start()
            self.assertTrue(started.wait(2))
            create.assert_not_called()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        create.assert_called_once_with(self.args)


if __name__ == '__main__':
    unittest.main()