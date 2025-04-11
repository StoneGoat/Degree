from markdown_pdf import MarkdownPdf, Section

def writeToPDF(MDfilename):
    with open(MDfilename) as f:
        title = f.readline()
    with open(MDfilename, "r") as file:
        md_content = file.read()
    pdf = MarkdownPdf(toc_level=2)
    pdf.meta["title"] = title
    pdf.add_section(Section(md_content, toc=False))
    pdf.save(f'{title}.pdf')

writeToPDF("scan_results/7aab0d7d-40a5-4c6a-add4-b07130bd96dd/vulnerability.md")
