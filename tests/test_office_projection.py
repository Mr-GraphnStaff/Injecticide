"""Office projection regression fixtures contain only synthetic public test data."""
import hashlib
import io
import zipfile
from unittest.mock import patch
import pytest
from skill_sandbox import artifact_text as office
from skill_sandbox import app


def package(extra=None, kind='pptx', locator=False):
    core = {'pptx': 'ppt/presentation.xml', 'docx': 'word/document.xml', 'xlsx': 'xl/workbook.xml'}[kind]
    files = {'[Content_Types].xml': b'<Types/>', core: b'<document/>'}
    files.update(extra or {})
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for index, (name, data) in enumerate(files.items()):
            info = zipfile.ZipInfo(name)
            if locator and index == len(files) - 1:
                info.comment = b'PK\x06\x07' + b'\x00' * 16
            archive.writestr(info, data)
    return output.getvalue()


def rejected(data, code=None, budget=None):
    with pytest.raises(office.OfficeProjectionError) as caught:
        office.extract_office_projection(data, 'fixture.pptx', budget)
    if code:
        assert caught.value.code == code
    assert caught.value.profile.get('coverage', {}).get('status') != 'complete'


def test_54_parts_complete_with_hash_and_explicit_scope():
    data = package({'ppt/slides/s%d.xml' % i: b'<slide>Reference</slide>' for i in range(52)})
    text, profile = office.extract_office_projection(data, 'fixture.pptx')
    assert profile['coverage'] == {'status': 'complete', 'xml_parts_total': 54, 'xml_parts_read': 54, 'omitted': []}
    assert profile['sha256'] == hashlib.sha256(data).hexdigest()
    assert profile['container_inspection']['sha256'] == profile['sha256']
    assert profile['excluded_member_count'] == 0
    assert 'no binary runtime' in profile['scope']
    assert 'Reference' in text


def test_late_text_attributes_relationships_and_masters_reach_detectors():
    data = package({'ppt/slides/s.xml': ('<slide descr="attribute-marker">' + 'x' * 600 + ' late-text-marker</slide>').encode(),
                    'ppt/slideMasters/master.xml': b'<master>master-marker</master>',
                    'ppt/slides/_rels/s.xml.rels': b'<Relationships><Relationship Target="https://example.invalid/relationship-marker"/></Relationships>'})
    with patch.object(app, '_scan_text', return_value=[]) as detector:
        entry, text = app._scan_file_bytes('fixture.pptx', data)
    for marker in ('late-text-marker', 'attribute-marker', 'master-marker', 'relationship-marker'):
        assert marker in detector.call_args.args[1]
    assert entry['assessment_state'] == 'structured_content_analyzed'
    assert entry['analysis_coverage']['extraction']['status'] == 'complete'
    assert entry['analysis_coverage']['extraction']['original_binary_security_analysis'] == 'not_performed'


def test_part_cap_and_shared_sibling_budget():
    rejected(package({'ppt/slides/s%d.xml' % i: b'<r/>' for i in range(1023)}), 'office_xml_parts_limit')
    sibling = package({'ppt/slides/s%d.xml' % i: b'<r/>' for i in range(513)})
    budget = office.OfficeBudget()
    office.extract_office_projection(sibling, 'first.pptx', budget)
    rejected(sibling, 'office_xml_parts_limit', budget)


@pytest.mark.parametrize('raw,code', [(b'<broken>', 'office_xml_malformed'),
    (b'<!DOCTYPE r [<!ENTITY x "unsafe">]><r>&x;</r>', 'office_xml_dtd'),
    ('<r>text</r>'.encode('utf-16'), 'office_xml_encoding'),
    (b'<?xml version="1.0" encoding="no-such-encoding"?><r/>', 'office_xml_malformed')])
def test_bad_xml_never_becomes_complete(raw, code):
    rejected(package({'ppt/slides/s.xml': raw}), code)


def test_xml_bytes_and_text_have_explicit_limits():
    rejected(package({'ppt/slides/large.xml': b'<r>' + b'x' * office.MAX_OFFICE_PART_BYTES + b'</r>'}), 'office_xml_bytes_limit')
    comments = b'<r><!--' + b'x' * (900 * 1024) + b'--></r>'
    rejected(package({'ppt/slides/s%d.xml' % i: comments for i in range(6)}), 'office_xml_bytes_limit')
    text = b'<r>' + b'x' * 600000 + b'</r>'
    rejected(package({'ppt/slides/a.xml': text, 'ppt/slides/b.xml': text}), 'office_text_limit')


def test_crc_failure_and_missing_core_are_not_complete():
    data = bytearray(package({'ppt/slides/s.xml': b'<r>crc-unique-value</r>'}))
    data[data.index(b'crc-unique-value')] ^= 1
    rejected(bytes(data), 'office_container_incomplete')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('[Content_Types].xml', b'<Types/>')
    rejected(output.getvalue(), 'office_required_parts')


def test_embedded_workbook_and_unsupported_containers():
    workbook = package({'xl/worksheets/s.xml': b'<sheet>embedded-marker</sheet>'}, kind='xlsx')
    text, profile = office.extract_office_projection(package({'ppt/embeddings/s.xlsx': workbook}), 'fixture.pptx')
    assert 'embedded-marker' in text
    assert profile['embedded_office_documents'] == 1
    assert profile['coverage']['xml_parts_total'] == profile['coverage']['xml_parts_read'] == 5
    rejected(package({'ppt/embeddings/other.zip': workbook}), 'office_embedded_container')
    rejected(package({'ppt/embeddings/ole.bin': b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1payload'}), 'office_embedded_container')
    for _ in range(3):
        workbook = package({'xl/embeddings/child.xlsx': workbook}, kind='xlsx')
    rejected(workbook, 'office_container_incomplete')


def test_shared_time_budget_stops_before_work():
    budget = office.OfficeBudget()
    budget.seconds_used = budget.max_seconds + 1
    rejected(package(), 'office_time_limit', budget)


def test_zip64_locator_is_rejected_before_constructor():
    data = package(locator=True)
    with patch('skill_sandbox.nested_archives.zipfile.ZipFile') as constructor:
        rejected(data, 'office_container_incomplete')
        constructor.assert_not_called()


def test_app_does_not_promote_failed_projection():
    with patch.object(app, '_scan_text') as detector:
        entry, text = app._scan_file_bytes('fixture.pptx', package({'ppt/slides/s.xml': b'<broken>'}))
    assert text is None and entry['skipped']
    assert entry['analysis_coverage']['extraction']['status'] == 'partial'
    assert entry['office_error_code'] == 'office_xml_malformed'
    detector.assert_not_called()
