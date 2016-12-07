from __future__ import print_function
from unittest import TestCase
import os
import sys
import time
import hover
import codecs
import tempfile
import shutil

# test commit

class TestHover(TestCase):
    @classmethod
    def setUpClass(cls):

        cls.ts = time.strftime("%Y%m%dT%H%M%S")
        detail_config_file, cls.test_config_name = tempfile.mkstemp(suffix='.cfg')
        os.write(detail_config_file, "[hover]\n")
        os.close(detail_config_file)

        cls.test_storage_dir = tempfile.mkdtemp()

        sys.stderr.write("Test Config File: %s\n" % cls.test_config_name)
        sys.stderr.write("Test Storage Dir: %s\n" % cls.test_storage_dir)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.test_config_name)
        shutil.rmtree(cls.test_storage_dir)

    def setConfig(self, content):
        with codecs.open(TestHover.test_config_name, 'w') as cf:
            cf.write(content)

    def test_config_file(self):
        self.setConfig("detail=true\npurge-cached-data=default\nrefresh=FALSE\nlogout=-")
        h = hover.Hover()
        out_dns = h.command(['--dns', '--config', TestHover.test_config_name])
        self.assertTrue(u'domains' in out_dns)
        self.assertGreater(len(out_dns[u'domains']), 0)
        self.assertGreater(len(out_dns[u'domains'][0]), 4)

        self.setConfig("does-not-exist=FALSE")
        out_dns = h.command(['--profile', '--config', TestHover.test_config_name])
        self.assertTrue(u'domains' in out_dns)

    def DISABLED_dbg(self):
        h = hover.Hover()
        out_dns = h.command(['--dns', '--dbg-raw'])
        std_output = sys.stdout.getvalue()
        print(std_output[:50])

        out_dns = h.command(['--dns', '--dbg-dump'])
        std_output = sys.stdout.getvalue()
        print(std_output[:50])

    def test_storage(self):
        h = hover.Hover()
        out_dns = h.command(['--dns', '--storage-path', TestHover.test_storage_dir])
        self.assertGreater(len([name for name in os.listdir(TestHover.test_storage_dir) if os.path.isfile(os.path.join(TestHover.test_storage_dir,name))]), 0)

    def test_command_errors(self):
        h = hover.Hover()
        out_domains = h.command(['--domain-list', '--output=native'])
        assert len(out_domains.keys()) > 0
        domain = out_domains.keys()[0]
        test_fqdn = u"{ts}.test.{domain}".format(ts=TestHover.ts, domain=domain)

        out_set = None
        try:
            out_set = h.command(['--offline', '--set', test_fqdn, 'TXT', 'TEST', '--output=native'])
        except hover.HoverError as err:
            self.assertIsNotNone(err)
            self.assertIsNone(out_set)

        try:
            out_set = h.command(['--offline', '--set', test_fqdn, 'TXT', 'TEST', '--output=native'], throw_errors=False)
        except hover.HoverError as err:
            self.fail("No exception should have ben thrown")
        self.assertEqual(len(out_set), 2)
        self.assertNotEqual(out_set[0], 0)


    def test_command_dns(self):
        h = hover.Hover()
        out_domains = h.command(['--domain-list', '--output=native'])
        assert len(out_domains.keys()) > 0
        domain = out_domains.keys()[0]

        test_fqdn = u"{ts}.test.{domain}".format(ts=TestHover.ts, domain=domain)
        out_add = h.command(['--add', test_fqdn, 'TXT', TestHover.ts, '--output=native'])

        self.assertEqual(len(out_add.keys()), 1)
        new_id = out_add.keys()[0]

        self.assertEqual(new_id[:3], 'dns')
        domain_record = out_add[new_id]
        print(domain_record['fqdn'], file=sys.stdout)

        self.assertEqual(domain_record["content"], TestHover.ts)

        new_content = TestHover.ts[::-1]
        out_update = h.command(['--update', new_id, new_content, '--output=native'])
        updated_content = out_update[new_id]['content']

        self.assertEqual(updated_content, new_content)

        new_content = TestHover.ts
        out_set = h.command(['--set', test_fqdn, 'TXT', new_content, '--output=native'])

        self.assertEqual(new_id, out_set.keys()[0])

        updated_content = out_set[new_id]['content']

        self.assertEqual(updated_content, new_content)


        out_delete = h.command(['--delete', new_id, '--output=native'])

        print(out_delete, file=sys.stdout)
        self.assertEqual(len(out_delete.keys()), 1)
        delete_id = out_delete.keys()[0]
        self.assertEqual(delete_id, new_id)

        out_dns = h.command(['--dns-list', '--output=native'])
        assert new_id not in out_dns.keys()

    def test_command_cache(self):
        h = hover.Hover()
        out = h.command(['--purge'])
        self.assertIsNotNone(out)

        out = h.command(['--cache-all-data'])
        self.assertIsNotNone(out)

        out = h.command(['--offline', '--dns-list'])
        self.assertIsNotNone(out)
        assert 'domains' in out
        assert 'headers' in out

        out = h.command(['--purge'])
        self.assertIsNotNone(out)

    def test_main(self):
        h = hover.Hover()
        h.main([])
        std_output = sys.stdout.getvalue()
        self.assertIsNotNone(std_output)
        assert "Domain Name" in std_output
