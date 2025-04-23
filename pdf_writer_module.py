from markdown_pdf import MarkdownPdf, Section

def writeToPDF(md_path, output_pdf_path):
    with open(md_path, 'r') as f:
        raw_title = f.readline().lstrip('# ').strip()
        md_content = f.read()
    pdf = MarkdownPdf(toc_level=2)
    pdf.meta["title"] = raw_title
    pdf.add_section(Section(md_content, toc=False))
    pdf.save(output_pdf_path)
