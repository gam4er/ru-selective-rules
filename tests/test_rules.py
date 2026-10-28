import json
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
import rules


class RulesTests(unittest.TestCase):
    def files(self,p):
        for name in rules.ASSETS:(p/name).write_bytes(b'hello')
        (p/'manifest.json').write_text(json.dumps({'semantic_hash':'hash'}))
        (p/'SHA256SUMS').write_text(''.join(rules.sha((p/name).read_bytes())+'  '+name+'\n' for name in rules.ASSETS))

    def test_preserve_semantics_and_reject_networks(self):
        parsed, bad = rules.parse(b'full:API.Example.com\ndomain:example.org\nregexp:^foo[0-9]+\\.net$\n1.2.3.0/24\n1.2.3.4\n*.example.net\n')
        self.assertEqual(parsed, [('domain', 'api.example.com'), ('domain_regex', '^foo[0-9]+\\.net$'), ('domain_suffix', 'example.net'), ('domain_suffix', 'example.org')])
        self.assertEqual(bad, 2)

    def test_hash_ignores_order_and_duplicates(self):
        self.assertEqual(rules.semantic_hash([('domain', 'a.com')]*2), rules.semantic_hash([('domain', 'a.com')]))

    def test_snapshot_failure_expiry_and_quarantine(self):
        with tempfile.TemporaryDirectory() as d:
            store = rules.Snapshots(Path(d))
            source = {'id': 'test', 'url': 'https://example.com', 'minimum': 1}
            def good(_): return b'a.com\nb.com\nc.com\nd.com', {}
            first = store.obtain(source, 1000, good)
            def fail(_): raise OSError('offline')
            self.assertTrue(store.obtain(source, 1001, fail)['stale'])
            def small(_): return b'a.com', {}
            fallback = store.obtain(source, 1002, small)
            self.assertEqual(fallback['rules'], first['rules'])
            self.assertTrue(list((Path(d)/'quarantine').iterdir()))
            with self.assertRaises(rules.RuleError): store.obtain(source, 1000 + 72*3600+1, fail)
            with self.assertRaises(rules.RuleError): store.obtain(dict(source, id='new'), 1001, fail)

    def test_dat_has_expected_wire_types(self):
        blob = rules.encode_dat([('domain','a.com'),('domain_suffix','b.com'),('domain_regex','^c$')])
        self.assertIn(b'RU-SELECTIVE',blob)  # Xray uppercases requested geosite codes.
        self.assertEqual(rules.decode_dat(blob), [('domain','a.com'),('domain_regex','^c$'),('domain_suffix','b.com')])

    def test_resume_ambiguous_create_and_upload(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.files(p)
            api=FakeGitHub()
            with self.assertRaises(OSError): rules.release(api,p,Path(d)/'state.json','test-tag','hash')
            rules.release(api,p,Path(d)/'state.json','test-tag','hash')
            self.assertEqual(api.created,1)
            self.assertFalse(api.draft)
            self.assertEqual(api.published,1)

    def test_corrupt_remote_asset_never_published(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.files(p)
            api=FakeGitHub();api.ambiguous=False;api.corrupt=True
            with self.assertRaises(rules.RuleError): rules.release(api,p,p/'state.json','tag','hash')
            self.assertEqual(api.published,0)

    def test_resume_lost_upload_response(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.files(p)
            api=FakeGitHub();api.ambiguous=False;api.lose_upload=True
            with self.assertRaises(OSError):rules.release(api,p,p/'state.json','test-tag','hash')
            rules.release(api,p,p/'state.json','test-tag','hash')
            self.assertEqual(api.created,1);self.assertEqual(len(api.assets),len(rules.ASSETS)+1);self.assertEqual(api.published,1)

    def test_resume_lost_publish_response(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.files(p)
            api=FakeGitHub();api.ambiguous=False;api.lose_publish=True
            with self.assertRaises(OSError):rules.release(api,p,p/'state.json','test-tag','hash')
            rules.release(api,p,p/'state.json','test-tag','hash')
            self.assertEqual(api.published,1);self.assertTrue(rules.read_json(p/'state.json')['published'])

    def test_incomplete_bundle_never_creates_release(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'SHA256SUMS').write_text('')
            api=FakeGitHub();api.ambiguous=False
            with self.assertRaises(rules.RuleError):rules.release(api,p,p/'state.json','test-tag','hash')
            self.assertEqual(api.created,0)

    def test_builder_mutation_after_validation_never_uploaded(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.files(p)
            api=FakeGitHub();api.ambiguous=False
            original=api.create_release
            def mutate(tag):
                (p/'ru-selective.srs').write_bytes(b'PRIVATE CREDENTIAL')
                return original(tag)
            api.create_release=mutate
            rules.release(api,p,p/'state.json','test-tag','hash')
            self.assertEqual(api.assets['ru-selective.srs'],b'hello')

    def test_invalid_consumer_rules_preserve_good_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            store=rules.Snapshots(Path(d));source={'id':'test','url':'https://example.com'}
            first=store.obtain(source,1000,lambda _: (b'a.com',{}))
            def reject(_):raise rules.RuleError('consumer rejects regex')
            fallback=store.obtain(source,1001,lambda _: (b'regexp:[',{}),validate=reject)
            self.assertTrue(fallback['stale'])
            self.assertEqual(rules.read_json(Path(d)/'test.json'),first)

    def test_manifest_digest_mismatch_before_api(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.files(p);api=FakeGitHub()
            with self.assertRaises(rules.RuleError):rules.release(api,p,p/'state.json','test-tag','wrong-hash')
            self.assertEqual(api.created,0)

    def test_health_expiry_during_upload_prevents_promotion(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.files(p);api=FakeGitHub();api.ambiguous=False
            def expired():raise rules.RuleError('source expired during upload')
            with self.assertRaises(rules.RuleError):rules.release(api,p,p/'state.json','test-tag','hash',before_publish=expired)
            self.assertEqual(api.published,0)

    def test_asset_size_bound_before_api(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.files(p);api=FakeGitHub()
            with patch.object(rules,'MAX_ASSET_BYTES',4):
                with self.assertRaises(rules.RuleError):rules.release(api,p,p/'state.json','test-tag','hash')
            self.assertEqual(api.created,0)

    @unittest.skipUnless(os.name=='posix','production Linux no-follow descriptor test')
    def test_symlink_asset_and_directory_rejected_before_api(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);bundle=p/'bundle';bundle.mkdir();self.files(bundle)
            private=p/'private';private.write_bytes(b'hello')
            (bundle/'ru-selective.srs').unlink()
            (bundle/'ru-selective.srs').symlink_to(private)
            api=FakeGitHub()
            with self.assertRaises(OSError):rules.release(api,bundle,p/'state.json','test-tag','hash')
            self.assertEqual(api.created,0)
            alias=p/'alias';alias.symlink_to(bundle,target_is_directory=True)
            with self.assertRaises(OSError):rules.release(api,alias,p/'state.json','test-tag','hash')

    @unittest.skipUnless(os.name=='posix','production Linux FIFO test')
    def test_fifo_asset_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.files(p)
            (p/'ru-selective.srs').unlink();os.mkfifo(p/'ru-selective.srs')
            with self.assertRaises(rules.RuleError):rules.load_bundle(p)

    @unittest.skipUnless(os.environ.get('RU_RULES_TEST_SING_BOX') and os.environ.get('RU_RULES_TEST_XRAY'),'set consumer executable paths for integration verification')
    def test_real_engines_reject_invalid_regex_without_losing_lkg(self):
        config={'sing_box':os.environ['RU_RULES_TEST_SING_BOX'],'xray':os.environ['RU_RULES_TEST_XRAY']}
        with tempfile.TemporaryDirectory() as d:
            store=rules.Snapshots(Path(d));source={'id':'test','url':'https://example.com'}
            validate=lambda rows:rules.validate_rules(rows,config)
            first=store.obtain(source,1000,lambda _: (b'full:a.com\ndomain:b.com\nregexp:^c[0-9]+[.]com$',{}),validate=validate)
            fallback=store.obtain(source,1001,lambda _: (b'full:a.com\ndomain:b.com\nregexp:[',{}),validate=validate)
            self.assertTrue(fallback['stale'])
            self.assertEqual(rules.read_json(Path(d)/'test.json'),first)


class FakeGitHub:
    def __init__(self):
        self.created=0;self.published=0;self.draft=True;self.assets={};self.ambiguous=True;self.corrupt=False
    def get_release(self, tag=None, release_id=None):
        if not self.created:return None
        return {'id':1,'draft':self.draft,'tag_name':tag or 'test-tag','assets':[{'id':k,'name':k} for k in self.assets]}
    def create_release(self,tag):
        self.created+=1
        if self.ambiguous:self.ambiguous=False;raise OSError('lost create response')
        return self.get_release(tag)
    def upload(self,release,name,data):
        self.assets[name]=data
        if getattr(self,'lose_upload',False):self.lose_upload=False;raise OSError('lost upload response')
        return {'id':name,'name':name}
    def download(self,asset):return b'corrupt' if self.corrupt else self.assets[asset['id']]
    def publish(self,release_id):
        self.draft=False;self.published+=1
        if getattr(self,'lose_publish',False):self.lose_publish=False;raise OSError('lost publish response')
        return self.get_release()


if __name__=='__main__':unittest.main()
