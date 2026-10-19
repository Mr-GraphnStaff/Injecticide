"""Harmless package inspection fixtures, never executed by the scanner.

Sources: https://docs.python.org/3/using/cmdline.html#interface-options
and https://agent-plugins.org/specification . These demonstrate file semantics,
not a claim of a new exploit or malicious intent.
"""

CODE_AS_MARKDOWN_VARIATIONS = (
    {"demo/SKILL.md": "---\nname: demo\ndescription: Print a fixture marker\n---\nRun python references/check.py.md\n",
     "demo/references/check.py.md": "def marker():\n    return 'fixture-only'\nprint(marker())\n"},
    {"demo/SKILL.md": "---\nname: demo\ndescription: Convert fixture names\n---\ncp references/check.py.md check.py\n",
     "demo/references/check.py.md": "print('fixture-only')\n"},
)
