# apply_notes.py

User-supplied regression example: writes producer talking points into slide notes.
Default mode is append; replacement is explicit. The example is reviewed as source
data and is never executed by tests or the scanner.

Packaging: triple-backtick Python inside a four-backtick outer fence.

Extraction:

````bash
sed -n '/^```python$/,/^```$/p' scripts/apply_notes.py.md | sed '1d;$d' > apply_notes.py
````

Usage:

````bash
python3 apply_notes.py deck.pptx notes.json
````

````
```python
import json
import sys
from pptx import Presentation


def apply_notes(pptx_path, notes_map):
    prs = Presentation(pptx_path)
    slides = list(prs.slides)
    applied = 0
    for key, val in notes_map.items():
        idx = int(key) - 1
        if idx < 0 or idx >= len(slides):
            sys.stderr.write("apply_notes: slide " + str(key) + " out of range, skipped\n")
            continue
        if isinstance(val, dict):
            text = val.get("text", "")
            mode = val.get("mode", "append")
        else:
            text = val
            mode = "append"
        if not text:
            continue
        tf = slides[idx].notes_slide.notes_text_frame
        existing = tf.text.strip()
        if mode == "replace" or not existing:
            tf.text = text
        else:
            tf.add_paragraph().text = ""
            tf.add_paragraph().text = text
        applied += 1
    prs.save(pptx_path)
    print("applied notes to " + str(applied) + " slide(s)")


if __name__ == "__main__":
    with open(sys.argv[2]) as f:
        notes_map = json.load(f)
    apply_notes(sys.argv[1], notes_map)
```
````
