import copy
import tempfile
import unittest
from pathlib import Path

import rules


class SelectionAPI(rules.GitHub):
    def __init__(self):
        super().__init__({'repository': 'owner/rules'})
        rows = [('domain', 'a.example'), ('domain_suffix', 'example.org')]
        digest = rules.semantic_hash(rows)
        self.tag = '20261028T041853Z-' + digest[:16]
        self.data = {name: b'fixture' for name in rules.ASSETS}
        self.data['ru-selective.dat'] = rules.encode_dat(rows)
        self.data['manifest.json'] = rules.canonical({'schema': 1, 'semantic_hash': digest, 'count': len(rows)})
        self.data['SHA256SUMS'] = ''.join(rules.sha(self.data[n]) + '  ' + n + '\n' for n in rules.ASSETS).encode()
        self.remote = {'id': 41, 'tag_name': self.tag, 'draft': False, 'prerelease': False,
                       'immutable': True, 'url': 'https://api.github.com/repos/owner/rules/releases/41',
                       'assets': [{'id': i, 'name': name, 'state': 'uploaded', 'size': len(data),
                                   'digest': 'sha256:' + rules.sha(data)}
                                  for i, (name, data) in enumerate(self.data.items(), 1)]}
        self.latest_remote = {'id': 42, 'tag_name': 'newer'}
        self.calls = []
        self.lose_patch = False

    def request(self, method, url, data=None, **kwargs):
        self.calls.append((method, url, data))
        if method == 'GET' and url.endswith('/releases/latest'):
            return copy.deepcopy(self.latest_remote)
        if method == 'GET' and '/releases?per_page=' in url:
            return [copy.deepcopy(self.remote)]
        if method == 'PATCH' and url.endswith('/releases/41'):
            self.latest_remote = copy.deepcopy(self.remote)
            if self.lose_patch:
                self.lose_patch = False
                raise OSError('lost PATCH response')
            return copy.deepcopy(self.remote)
        raise AssertionError('Unexpected API call: ' + method + ' ' + url)

    def download(self, asset):
        return self.data[asset['name']]


class SelectReleaseTests(unittest.TestCase):
    def test_select_existing_immutable_changes_only_latest(self):
        api = SelectionAPI()
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory) / 'selected-release.json'
            self.assertTrue(hasattr(rules, 'select_release'), 'safe release selection is missing')
            rules.select_release(api, api.tag, audit)
            self.assertEqual(api.latest_remote['id'], 41)
            writes = [call for call in api.calls if call[0] != 'GET']
            self.assertEqual(writes, [('PATCH', '/repos/owner/rules/releases/41', {'make_latest': 'true'})])
            self.assertEqual(rules.read_json(audit)['release_id'], 41)
            self.assertEqual(rules.read_json(audit)['previous_release_id'], 42)

    def test_noop_and_lost_patch_response_resume_without_duplicate_write(self):
        api = SelectionAPI()
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory) / 'selected-release.json'
            api.lose_patch = True
            with self.assertRaises(OSError):
                rules.select_release(api, api.tag, audit)
            rules.select_release(api, api.tag, audit)
            self.assertEqual(len([call for call in api.calls if call[0] == 'PATCH']), 1)
            self.assertEqual(rules.read_json(audit)['release_id'], 41)

    def test_unpublished_mutable_foreign_or_missing_assets_refused(self):
        for mutate in [lambda r: r.update(draft=True), lambda r: r.update(prerelease=True),
                       lambda r: r.update(immutable=False),
                       lambda r: r.update(url='https://api.github.com/repos/foreign/rules/releases/41'),
                       lambda r: r['assets'].pop(),
                       lambda r: r['assets'].append(dict(r['assets'][0])),
                       lambda r: r['assets'][0].update(state='starter'),
                       lambda r: r['assets'][0].update(size=rules.MAX_ASSET_BYTES + 1)]:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as directory:
                api = SelectionAPI()
                mutate(api.remote)
                with self.assertRaises(rules.RuleError):
                    rules.select_release(api, api.tag, Path(directory) / 'audit.json')
                self.assertFalse(any(call[0] != 'GET' for call in api.calls))

    def test_corrupt_bytes_manifest_or_dat_category_never_selected(self):
        for corrupt in ['bytes', 'manifest', 'dat-category', 'dat-no-category']:
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory() as directory:
                api = SelectionAPI()
                if corrupt == 'bytes':
                    api.data['ru-selective.srs'] = b'altered'
                else:
                    name = 'manifest.json' if corrupt == 'manifest' else 'ru-selective.dat'
                    api.data[name] = (rules.canonical({'schema': 1, 'semantic_hash': 'f' * 64, 'count': 2})
                                      if corrupt == 'manifest' else api.data[name].replace(b'RU-SELECTIVE', b'BAD-COUNTRY')
                                      if corrupt == 'dat-category' else api.data[name].replace(rules.field(1, b'RU-SELECTIVE'), rules.field(3, b'RU-SELECTIVE')))
                    api.data['SHA256SUMS'] = ''.join(rules.sha(api.data[n]) + '  ' + n + '\n' for n in rules.ASSETS).encode()
                    for asset in api.remote['assets']:
                        asset.update(size=len(api.data[asset['name']]), digest='sha256:' + rules.sha(api.data[asset['name']]))
                with self.assertRaises(rules.RuleError):
                    rules.select_release(api, api.tag, Path(directory) / 'audit.json')
                self.assertFalse(any(call[0] != 'GET' for call in api.calls))

    def test_api_must_confirm_selected_latest(self):
        api = SelectionAPI()
        original = api.request
        def request(method, url, data=None, **kwargs):
            answer = original(method, url, data, **kwargs)
            if method == 'PATCH':
                api.latest_remote = {'id': 99, 'tag_name': 'concurrent-change'}
            return answer
        api.request = request
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory) / 'audit.json'
            with self.assertRaisesRegex(rules.RuleError, 'latest'):
                rules.select_release(api, api.tag, audit)
            self.assertFalse(audit.exists())


if __name__ == '__main__':
    unittest.main()
