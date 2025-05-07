import re
from markdown_pdf import MarkdownPdf, Section

def slugify(text: str) -> str:
    slug = text.lower()
    slug = re.sub(r'[^\w\s-]', '', slug)
    slug = re.sub(r'\s+', '-', slug.strip())
    return slug

def add_anchors(md: str, max_depth: int = 2) -> str:
    out = []
    for line in md.splitlines():
        m = re.match(r'^(#{1,' + str(max_depth) + r'})\s+(.*)', line)
        if m:
            title = m.group(2).strip()
            slug = slugify(title)
            out.append(f'<a name="{slug}"></a>')
        out.append(line)
    return "\n".join(out)

def generate_toc(md: str, max_depth: int = 2) -> str:
    toc = []
    for line in md.splitlines():
        m = re.match(r'^(#{1,' + str(max_depth) + r'})\s+(.*)', line)
        if not m:
            continue
        level = len(m.group(1))
        title = m.group(2).strip()
        link = slugify(title)
        indent = '  ' * (level - 1)
        display = title.replace(' ', '\u00A0')
        toc.append(f"{indent}- [{display}](#{link})")
    return "\n".join(toc)

def render_toc_table(toc_md: str) -> str:
    rows = []
    for idx, line in enumerate(toc_md.splitlines(), start=1):
        label, href = re.match(r'\s*-\s+\[([^\]]+)\]\((#[^\)]+)\)', line).groups()
        rows.append(f'  <tr><td align="right">{idx}.</td><td><a href="{href}">{label}</a></td></tr>')
    return "\n".join([
        '<div align="center">',
        '<table>',
        *rows,
        '</table>',
        '</div>',
    ])

def write_to_PDF(md_path, output_pdf_path):
    with open(md_path, 'r', encoding='utf-8') as f:
        raw_md = f.read()
    toc_md = generate_toc(raw_md, max_depth=2)
    anchored_md = add_anchors(raw_md, max_depth=2)
    toc_block = render_toc_table(toc_md)
    full_md = "\n\n".join(["<!-- toc -->", toc_block, "<!-- tocstop -->", anchored_md])
    pdf = MarkdownPdf(toc_level=2)
    first = raw_md.splitlines()[0]
    if first.startswith('#'):
        pdf.meta["title"] = first.lstrip('# ').strip()
    pdf.add_section(Section(full_md))
    pdf.save(output_pdf_path)
