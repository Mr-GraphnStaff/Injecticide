"""Archive trust boundary and reproducibility tests."""
import hashlib
import io
import stat
import unittest
from unittest.mock import patch
import zipfile
from skill_sandbox.package_editor import PackageEditError, build_package, inspect_package, MAX_TEXT
SKILL = b'---\nname: example\ndescription: An example skill\n---\n# Example\n'
def archive(files=None, **kwargs):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', **kwargs) as package:
        for path, data in (files or {'example/SKILL.md': SKILL}).items():
            package.writestr(path, data)
    return output.getvalue()
def change(path, old, content=None, action='replace'):
    result = {'path': path, 'original_sha256': hashlib.sha256(old).hexdigest(), 'action': action}
    if content is not None:
        result['content'] = content
    return result
class PackageEditorTests(unittest.TestCase):
    def test_deterministic_output_preserves_source_and_unchanged_bytes(self):
        original = archive({'example/script.py': b"print('hello')\n", 'example/SKILL.md': SKILL})
        digest = hashlib.sha256(original).hexdigest()
        a = build_package(original, 'example.skill', [], 'generic-agent-skills', 'zip')
        b = build_package(original, 'example.skill', [], 'generic-agent-skills', 'zip')
        self.assertEqual(a['bytes'], b['bytes'])
        self.assertEqual(digest, hashlib.sha256(original).hexdigest())
        self.assertEqual(a['filename'], 'example.zip')
        with zipfile.ZipFile(io.BytesIO(a['bytes'])) as result:
            self.assertEqual(result.read('example/script.py'), b"print('hello')\n")
            self.assertEqual(result.namelist(), sorted(result.namelist()))
            self.assertEqual(result.getinfo('example/SKILL.md').date_time, (1980, 1, 1, 0, 0, 0))
        self.assertEqual(a['validation']['status'], 'pass')
    def test_explicit_text_replacement_and_deletion(self):
        original = archive({'example/SKILL.md': SKILL, 'example/notes.txt': b'old'})
        result = build_package(original, 'x.zip', [change('example/SKILL.md', SKILL, SKILL.decode() + 'Updated\n'), change('example/notes.txt', b'old', action='remove')], 'generic-agent-skills', 'skill')
        with zipfile.ZipFile(io.BytesIO(result['bytes'])) as package:
            self.assertNotIn('example/notes.txt', package.namelist())
            self.assertIn(b'Updated', package.read('example/SKILL.md'))
    def test_inspection_bounded_and_binary_readonly(self):
        data = archive({'example/SKILL.md': SKILL, 'example/data.bin': b'\0hi', 'example/long.txt': b'x' * (MAX_TEXT + 1)})
        info = inspect_package(data, 'x.zip')
        self.assertEqual(info['skill_root'], 'example')
        entries = {x['path']: x for x in info['entries']}
        self.assertFalse(entries['example/data.bin']['editable'])
        self.assertFalse(entries['example/long.txt']['editable'])
        self.assertTrue(entries['example/SKILL.md']['editable'])
        with self.assertRaises(PackageEditError):
            build_package(data, 'x.zip', [change('example/data.bin', b'\0hi', 'rewrite')], 'generic-agent-skills', 'zip')
    def test_stale_duplicate_unknown_and_invalid_changes(self):
        original = archive()
        for changes in ([{'path': 'example/SKILL.md', 'original_sha256': 'stale', 'action': 'remove'}], [change('example/SKILL.md', SKILL, SKILL.decode())] * 2, [change('example/missing.txt', b'', 'new')], [change('../SKILL.md', SKILL, 'new')], [change('example/SKILL.md', SKILL, 'new', action='add')]):
            with self.subTest(changes=changes), self.assertRaises(PackageEditError):
                build_package(original, 'x.zip', changes, 'generic-agent-skills', 'zip')
    def test_unsafe_paths_and_unicode_case_collisions(self):
        for path in ('../escape', '/absolute', 'C:/drive', '\\\\server\\file', 'example/../escape', 'example//file', 'example/con.txt', 'example/trailing.'):
            with self.subTest(path=path), self.assertRaises(PackageEditError):
                inspect_package(archive({'example/SKILL.md': SKILL, path: b'x'}), 'x.zip')
        for paths in (('example/A.txt', 'example/a.txt'), ('example/\u00e9.txt', 'example/e\u0301.txt'), ('example/dir', 'example/dir/child'), ('example/A/one', 'example/a/two')):
            with self.subTest(paths=paths), self.assertRaises(PackageEditError):
                inspect_package(archive({'example/SKILL.md': SKILL, paths[0]: b'x', paths[1]: b'y'}), 'x.zip')
    def test_duplicate_symlink_encryption_and_compression_bomb(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as package:
            package.writestr('example/SKILL.md', SKILL)
            entry = zipfile.ZipInfo('example/link')
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            package.writestr(entry, b'/etc/passwd')
        with self.assertRaises(PackageEditError):
            inspect_package(output.getvalue(), 'x.zip')
        with self.assertRaises(PackageEditError):
            inspect_package(archive({'example/SKILL.md': SKILL, 'example/bomb.txt': b'x' * 1000000}, compression=zipfile.ZIP_DEFLATED), 'x.zip')
        original = bytearray(archive())
        original[6] |= 1
        central = original.index(b'PK\x01\x02')
        original[central + 8] |= 1
        with self.assertRaises(PackageEditError):
            inspect_package(bytes(original), 'x.zip')
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as package:
            package.writestr('example/SKILL.md', SKILL)
            with self.assertWarns(UserWarning):
                package.writestr('example/SKILL.md', SKILL)
        with self.assertRaises(PackageEditError):
            inspect_package(output.getvalue(), 'x.zip')
    def test_nested_archives_and_masquerading_names(self):
        for path, content in (('example/nested.zip', b'data'), ('example/data.bin', archive())):
            with self.subTest(path=path), self.assertRaises(PackageEditError):
                inspect_package(archive({'example/SKILL.md': SKILL, path: content}), 'x.zip')
        for data, name in ((b'not a zip', 'x.skill'), (archive(), 'x.tar.gz')):
            with self.assertRaises(PackageEditError):
                inspect_package(data, name)
    def test_missing_multiroot_and_multiple_skill_files(self):
        for files in ({'SKILL.md': SKILL}, {'example/readme.md': b'x'}, {'example/SKILL.md': SKILL, 'other/file': b'x'}, {'example/SKILL.md': SKILL, 'example/sub/SKILL.md': SKILL}, {'example/skill.md': SKILL}):
            with self.subTest(files=list(files)), self.assertRaises(PackageEditError):
                inspect_package(archive(files), 'x.zip')
    def test_frontmatter_validation_profiles_and_no_silent_rewriting(self):
        cases = [(b'---\nname: different\ndescription: Example\n---\n', 'root_name'), (b'---\nname: example\ndescription: x\nname: example\n---\n', 'frontmatter'), (b'---\nname: example\ndescription: &a hello\nmetadata: {x: *a}\n---\n', 'frontmatter'), (b'---\nname: example\ndescription: x\nmetadata: {version: 1}\n---\n', 'metadata'), (b'---\nname: example\ndescription: x\ncompatibility: 23\n---\n', 'compatibility')]
        for content, code in cases:
            with self.subTest(code=code), self.assertRaises(PackageEditError) as raised:
                build_package(archive({'example/SKILL.md': content}), 'x.zip', [], 'generic-agent-skills', 'zip')
            self.assertIn(code, [x['code'] for x in raised.exception.validation['errors']])
        content = b'---\nname: example\ndescription: ' + b'x' * 201 + b'\ncontext: fork\n---\n'
        original = archive({'example/SKILL.md': content})
        code = build_package(original, 'x.zip', [], 'claude-code', 'zip')
        self.assertNotIn('extra_frontmatter', [w['code'] for w in code['validation']['warnings']])
        with zipfile.ZipFile(io.BytesIO(code['bytes'])) as package:
            self.assertEqual(content, package.read('example/SKILL.md'))
        description_only = content.replace(b'context: fork\n', b'')
        ai = build_package(archive({'example/SKILL.md': description_only}), 'x.zip', [], 'claude-ai', 'zip')
        self.assertIn('claude_ai_description', [w['code'] for w in ai['validation']['warnings']])
        for profile in ('claude-ai', 'claude-api', 'generic-agent-skills'):
            with self.assertRaises(PackageEditError):
                build_package(original, 'x.zip', [], profile, 'zip')
    def test_removed_markdown_reference_blocks_build_but_examples_do_not(self):
        for body, blocked in (('[notes](notes.txt)\n', True), ('[notes](notes%2Etxt)\n', True), ('See notes.txt in the documentation\n', False), ('\x60[notes](notes.txt)\x60\n', False), ('\x60\x60[notes](notes.txt)\x60\x60\n', False), ('\x60\x60\x60md\n[notes](notes.txt)\n\x60\x60\x60\n', False), ('[remote](https://example.com/notes.txt)\n', False)):
            content = SKILL + body.encode()
            data = archive({'example/SKILL.md': content, 'example/notes.txt': b'notes'})
            edits = [change('example/notes.txt', b'notes', action='remove')]
            if blocked:
                with self.assertRaises(PackageEditError) as raised:
                    build_package(data, 'x.zip', edits, 'generic-agent-skills', 'zip')
                self.assertEqual(raised.exception.validation['errors'][0]['code'], 'removed_reference')
            else:
                build_package(data, 'x.zip', edits, 'generic-agent-skills', 'zip')
    def test_removing_skill_or_invalid_profile_is_rejected(self):
        with self.assertRaises(PackageEditError):
            build_package(archive(), 'x.zip', [change('example/SKILL.md', SKILL, action='remove')], 'generic-agent-skills', 'zip')
        for profile, output in (('consumer-gemini', 'zip'), ('openai-api', 'tar')):
            with self.assertRaises(PackageEditError):
                build_package(archive(), 'x.zip', [], profile, output)
    def test_office_asset_preserved_and_nested_archive_rejected(self):
        workbook = archive({'[Content_Types].xml': b'<Types/>', 'xl/workbook.xml': b'<workbook/>'})
        presentation = archive({'[Content_Types].xml': b'<Types/>', 'ppt/presentation.xml': b'<presentation/>', 'ppt/embeddings/sheet.xlsx': workbook})
        data = archive({'example/SKILL.md': SKILL, 'example/assets/template.pptx': presentation})
        inspection = inspect_package(data, 'x.zip')
        entry = next(x for x in inspection['entries'] if x['path'].endswith('.pptx'))
        self.assertFalse(entry['editable'])
        result = build_package(data, 'x.zip', [], 'generic-agent-skills', 'zip')
        with zipfile.ZipFile(io.BytesIO(result['bytes'])) as package:
            self.assertEqual(package.read('example/assets/template.pptx'), presentation)
        unsafe = archive({'[Content_Types].xml': b'<Types/>', 'ppt/presentation.xml': b'<presentation/>', 'ppt/embeddings/payload.zip': archive()})
        with self.assertRaises(PackageEditError):
            inspect_package(archive({'example/SKILL.md': SKILL, 'example/a.pptx': unsafe}), 'x.zip')

    def test_unicode_name_is_preserved(self):
        content = '---\nname: café\ndescription: Example\n---\n'.encode()
        result = build_package(archive({'café/SKILL.md': content}), 'x.zip', [], 'generic-agent-skills', 'zip')
        with zipfile.ZipFile(io.BytesIO(result['bytes'])) as package:
            self.assertEqual(package.read('café/SKILL.md'), content)
    def test_claude_api_reserved_xml_and_cli_warning(self):
        for name, description in (('claude-example', 'Example'), ('example', '<tag>Example</tag>')):
            body = ('---\nname: ' + name + '\ndescription: ' + description + '\n---\n').encode()
            with self.assertRaises(PackageEditError) as raised:
                build_package(archive({name + '/SKILL.md': body}), 'x.zip', [], 'claude-api', 'zip')
            self.assertTrue(raised.exception.validation['errors'])
        for profile in ('openai-codex', 'gemini-cli', 'claude-code'):
            result = build_package(archive(), 'x.zip', [], profile, 'zip')
            self.assertIn('install_unverified', [w['code'] for w in result['validation']['warnings']])
    def test_preview_budget_and_forged_expanded_size(self):
        files = {'example/SKILL.md': SKILL}
        files.update({'example/n' + str(i) + '.txt': b'a' * MAX_TEXT for i in range(5)})
        info = inspect_package(archive(files), 'x.zip')
        self.assertTrue(all(x['editable'] == ('text' in x) for x in info['entries']))
        self.assertLessEqual(sum(len(x.get('text', '').encode()) for x in info['entries']), 512 * 1024)
        data = bytearray(archive())
        central = data.index(b'PK\x01\x02')
        data[central + 24:central + 28] = (26 * 1024 * 1024).to_bytes(4, 'little')
        with self.assertRaises(PackageEditError):
            inspect_package(bytes(data), 'x.zip')


    def test_central_directory_preflight_before_zipfile_allocation(self):
        original = archive()
        footer = original.rfind(b'PK\x05\x06')
        cases = []
        too_many = bytearray(original)
        too_many[footer + 8:footer + 12] = (501).to_bytes(2, 'little') * 2
        cases.append(bytes(too_many))
        huge_directory = bytearray(original)
        huge_directory[footer + 12:footer + 16] = (2 * 1024 * 1024 + 1).to_bytes(4, 'little')
        cases.append(bytes(huge_directory))
        false_count = bytearray(original)
        false_count[footer + 8:footer + 12] = (2).to_bytes(2, 'little') * 2
        cases.append(bytes(false_count))
        zip64 = bytearray(original)
        zip64[footer + 8:footer + 12] = b'\xff\xff' * 2
        cases.append(bytes(zip64))
        for data in cases:
            with self.subTest(data=data[-22:]), patch('skill_sandbox.package_editor.zipfile.ZipFile') as constructor:
                with self.assertRaises(PackageEditError):
                    inspect_package(data, 'x.zip')
                constructor.assert_not_called()

    def test_zip64_locator_is_rejected_before_archive_allocation(self):
        from unittest.mock import patch
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as package:
            entry = zipfile.ZipInfo('example/SKILL.md')
            entry.comment = bytes((80, 75, 6, 7)) + bytes(16)
            package.writestr(entry, SKILL)
        with patch('skill_sandbox.package_editor.zipfile.ZipFile') as constructor:
            with self.assertRaises(PackageEditError):
                inspect_package(output.getvalue(), 'example.skill')
            constructor.assert_not_called()

    def test_existing_executable_scripts_keep_nonprivileged_execute_permissions(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as package:
            package.writestr('example/SKILL.md', SKILL)
            script = zipfile.ZipInfo('example/scripts/run.sh')
            script.create_system = 3
            script.external_attr = (stat.S_IFREG | 0o4755) << 16
            package.writestr(script, b'#!/bin/sh\nexit 0\n')
        result = build_package(output.getvalue(), 'example.skill', [], 'generic-agent-skills', 'skill')
        with zipfile.ZipFile(io.BytesIO(result['bytes'])) as package:
            self.assertEqual((package.getinfo('example/scripts/run.sh').external_attr >> 16) & 0o7777, 0o755)
            self.assertEqual((package.getinfo('example/SKILL.md').external_attr >> 16) & 0o7777, 0o644)

    def test_signature_like_assets_are_preserved_with_explicit_warning(self):
        data = archive({'example/SKILL.md': SKILL, 'example/skill.oms.sig': b'source-owned signature fixture'})
        result = build_package(data, 'example.skill', [], 'generic-agent-skills', 'zip')
        self.assertIn('signature_revalidation_required', [item['code'] for item in result['validation']['warnings']])
        with zipfile.ZipFile(io.BytesIO(result['bytes'])) as package:
            self.assertEqual(package.read('example/skill.oms.sig'), b'source-owned signature fixture')

    def test_destination_documented_byte_limits_are_enforced(self):
        from unittest.mock import patch
        data = archive({'example/SKILL.md': SKILL, 'example/notes.txt': b'x' * 101})
        with patch('skill_sandbox.package_editor.OPENAI_MAX_FILE_BYTES', 100):
            with self.assertRaises(PackageEditError) as raised:
                build_package(data, 'example.zip', [], 'openai-api', 'zip')
            self.assertIn('openai_file_size', [item['code'] for item in raised.exception.validation['errors']])
        with patch('skill_sandbox.package_editor.CLAUDE_MAX_TOTAL_BYTES', 128):
            with self.assertRaises(PackageEditError) as raised:
                build_package(data, 'example.zip', [], 'claude-api', 'zip')
            self.assertIn('claude_size', [item['code'] for item in raised.exception.validation['errors']])

    def test_non_documented_extension_is_warned_not_silently_certified(self):
        result = build_package(archive(), 'example.zip', [], 'openai-api', 'skill')
        self.assertIn('documented_zip_upload', [item['code'] for item in result['validation']['warnings']])

if __name__ == '__main__':
    unittest.main()
