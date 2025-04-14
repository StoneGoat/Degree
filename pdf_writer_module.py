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

writeToPDF("scan_results/guru/vulnerability.md")
