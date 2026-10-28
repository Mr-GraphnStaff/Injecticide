import json

from skill_sandbox.token_footprint import build_token_footprint


def skill(body='Summarize input.'):
    return '---\nname: demo\ndescription: Summarize text\n---\n' + body


def test_loading_stages_are_distinct_and_not_runtime_or_tokenizer_claims():
    sources = [{'path':'demo/SKILL.md','text':skill('[Notes](references/notes.md)')},
               {'path':'demo/references/notes.md','text':'Supporting notes.'},
               {'path':'demo/scripts/work.py','text':'print("not run")'}]
    graph = {'edges':[{'source':'demo/SKILL.md','target':'demo/references/notes.md','status':'resolved','kind':'document_reference'}]}
    result = build_token_footprint(sources, sources, graph)
    row = result['skills'][0]
    assert result['runtime_usage'] == 'not_assessed' and result['tokenizer'] is None
    assert row['main_instructions']['characters'] == len(sources[0]['text'])
    assert row['metadata_discovery']['characters'] < row['main_instructions']['characters']
    assert row['directly_referenced_text']['file_count'] == 1
    assert row['packaged_supporting_text']['file_count'] == 2
    assert result['extracted_text_total']['exact_tokens'] is None
    assert result['extracted_text_total']['estimated_tokens'] > 0


def test_unicode_and_encoded_text_do_not_get_a_misleading_english_proxy():
    result = build_token_footprint([{'path':'demo/SKILL.md','text':skill('汉字' * 100)}, {'path':'encoded.txt','text':'A' * 600}])
    assert all(row['estimated_tokens'] is None for row in result['largest_text_files'])
    assert result['extracted_text_total']['estimated_tokens'] is None
    assert result['extracted_text_total']['utf8_bytes'] > result['extracted_text_total']['characters']


def test_shared_reference_is_counted_once_and_cross_skill_support_is_separate():
    first, second = 'root/SKILL.md', 'root/other/SKILL.md'
    sources = [{'path':first,'text':skill()}, {'path':second,'text':skill()}, {'path':'root/other/notes.md','text':'notes'}]
    graph = {'edges':[{'source':first,'target':'root/other/notes.md','status':'resolved','kind':'document_reference'}] * 2}
    result = build_token_footprint(sources, sources, graph)
    row = next(row for row in result['skills'] if row['path'] == first)
    assert row['directly_referenced_text']['file_count'] == 1
    assert row['packaged_supporting_text']['file_count'] == 0


def test_omitted_assets_and_character_limits_are_explicit(monkeypatch):
    monkeypatch.setattr('skill_sandbox.token_footprint.MAX_CHARACTERS', 5)
    result = build_token_footprint([{'path':'notes.md','text':'Long source text'}], [{'path':'notes.md'}, {'path':'picture.png'}])
    assert result['status'] == 'partial'
    assert result['extracted_text_total']['characters'] == 5
    assert {row['kind'] for row in result['limits']} == {'footprint_character_budget','inventory_without_extracted_text'}


def test_measurement_never_returns_source_text_or_contacts_providers(monkeypatch):
    monkeypatch.setattr('socket.create_connection', lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('No network')))
    secret = 'SYNTHETIC_PRIVATE_VALUE_12345678'
    result = build_token_footprint([{'path':'demo/SKILL.md','text':skill('password="' + secret + '"')}])
    assert secret not in json.dumps(result)


def test_malformed_frontmatter_and_empty_input_remain_unassessed():
    assert build_token_footprint([])['status'] == 'not_assessed'
    result = build_token_footprint([{'path':'SKILL.md','text':'No frontmatter'}])
    assert result['skills'][0]['metadata_discovery'] is None


def test_unsupported_file_and_skill_budgets_are_disclosed(monkeypatch):
    monkeypatch.setattr('skill_sandbox.token_footprint.MAX_SKILLS', 1)
    result = build_token_footprint([{'path':f'{i}/SKILL.md','text':skill()} for i in range(2)])
    assert result['status'] == 'partial'
    assert any(row.get('omitted_skills') == 1 for row in result['limits'])


def test_nested_archive_contents_are_not_summed_as_ordinary_supporting_text():
    sources = [{'path':'demo/SKILL.md','text':skill()}, {'path':'demo/inner.zip!/SKILL.md','text':skill()},
               {'path':'demo/inner.zip!/notes.md','text':'nested notes'}]
    result = build_token_footprint(sources)
    assert next(row for row in result['skills'] if row['path'] == 'demo/SKILL.md')['packaged_supporting_text']['file_count'] == 0
