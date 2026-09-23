"""Validate the four curated chat tracks and pinned ATT&CK lookup index."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TRACKS = ('methodology', 'scans', 'footholds', 'tools')
EXPECTED = {
    'methodology': (30, 10),
    'scans': (33, 9),
    'footholds': (34, 10),
    'tools': (30, 20),
}


def rows(path):
    with path.open() as stream:
        for number, line in enumerate(stream, 1):
            assert line.strip(), (path, number)
            yield json.loads(line)


def validate():
    prompts = set()
    total = 0
    for track in TRACKS:
        groups = {}
        names = {}
        for split, expected in zip(('train', 'eval'), EXPECTED[track]):
            path = ROOT / track / f'{split}.jsonl'
            examples = list(rows(path))
            assert len(examples) == expected, (path, len(examples))
            groups[split] = set()
            names[split] = set()
            for row in examples:
                messages = row['messages']
                metadata = row['metadata']
                assert messages and isinstance(metadata, dict)
                assert metadata.get('review_status')
                assert metadata.get('fixture_id')
                assert metadata.get('split_group')
                groups[split].add(metadata['split_group'])
                user_messages = [m for m in messages if m['role'] == 'user']
                assert len(user_messages) == 1
                prompt = user_messages[0]['content'].strip().casefold()
                assert prompt not in prompts, (path, prompt)
                prompts.add(prompt)
                assert all('<think>' not in m.get('content', '').lower() for m in messages)
                if track != 'tools':
                    assert [m['role'] for m in messages] == ['user', 'assistant']
                    assert all(m['content'].strip() for m in messages)
                    assert 'tools' not in row
                else:
                    schemas = {t['function']['name']: t['function']['parameters'] for t in row['tools']}
                    assert schemas
                    calls = []
                    responses = []
                    for msg in messages:
                        if msg['role'] == 'assistant':
                            for call in msg.get('tool_calls', []):
                                assert call['type'] == 'function'
                                function = call['function']
                                name = function['name']
                                names[split].add(name)
                                assert name in schemas
                                args = function['arguments']
                                assert isinstance(args, dict)
                                schema = schemas[name]
                                assert set(schema['required']) <= set(args)
                                assert not (set(args) - set(schema['properties']))
                                for key, value in args.items():
                                    prop = schema['properties'][key]
                                    assert isinstance(value, str)
                                    assert value and (not prop.get('enum') or value in prop['enum'])
                                calls.append(name)
                        elif msg['role'] == 'tool':
                            assert msg['name'] in schemas
                            assert isinstance(json.loads(msg['content']), dict)
                            responses.append(msg['name'])
                    assert calls == responses
                    assert messages[-1]['role'] == 'assistant' and messages[-1]['content'].strip()
                total += 1
            print(f'{track}/{split}: {len(examples)} rows; sha256 {hashlib.sha256(path.read_bytes()).hexdigest()}')
        assert not groups['train'] & groups['eval'], (track, 'split group leakage')
        if track == 'tools':
            assert not names['train'] & names['eval'], 'tool alias leakage'
    index = list(rows(ROOT / 'reference' / 'attack_technique_index.jsonl'))
    assert len(index) == 697
    assert len({r['technique_id'] for r in index}) == len(index)
    assert all(r['reference_url'].startswith('https://attack.mitre.org/') for r in index)
    print(f'PASS: {total} chat rows and {len(index)} ATT&CK lookup rows')


if __name__ == '__main__':
    validate()
