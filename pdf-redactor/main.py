## Warning filter
import warnings

warnings.filterwarnings(
    "ignore",
    message="The `fitz` API is deprecated.*",
    category=FutureWarning
)

##re for regex, and spacy for NER models
import argparse
from pathlib import Path
from pdf2docx import Converter
import re
import spacy
from docx import Document
import tempfile
import pymupdf

parser = argparse.ArgumentParser(description="Convert a PDF to DOCX and mask sensitive information")

##load spacCy's small English model
nlp = spacy.load("en_core_web_sm")

##Masking function
def mask_sensitive_info(text):
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    phone_pattern = r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b";
    ssn_pattern = r"\b\d{3}-\d{2}-\d{4}\b";
    patterns = {
        "EMAIL": email_pattern,
        "PHONE": phone_pattern,
        "SSN": ssn_pattern
    }
    for category, pattern in patterns.items():
        matches = re.findall(pattern, text)
        for match in matches:
            placeholder = f"[{category}]"
            text = text.replace(match, placeholder)

    ##analyze text after regex masking
    doc = nlp(text)

    for entity in reversed(doc.ents):
        if entity.label_ == "PERSON":
            text = (
                text[:entity.start_char]
                + "[PERSON]"
                + text[entity.end_char:]
            )
    return text


def mask_paragraph(paragraph):
    runs = paragraph.runs

    if not runs:
        return

    original_texts = [run.text for run in runs]
    full_text = "".join(original_texts)

    spans = find_sensitive_spans(full_text)

    if not spans:
        return

    # Determine each run's position in original paragraph
    boundaries = []
    position = 0

    for text in original_texts:
        start = position
        end = start + len(text)
        boundaries.append((start, end))
        position = end

    # Construct each run's new text without shifting positions
    for i, run in enumerate(runs):
        run_start, run_end = boundaries[i]
        pieces = []
        cursor = run_start

        for start, end, placeholder in spans:
            if end <= run_start or start >= run_end:
                continue
            if start > cursor:
                pieces.append(full_text[cursor:min(start, run_end)])

            if run_start <= start < run_end:
                pieces.append(placeholder)

            cursor = max(cursor, min(end, run_end))

        if cursor < run_end:
            pieces.append(full_text[cursor:run_end])

        run.text = "".join(pieces)

    
def find_sensitive_spans(text):
    spans = []
    patterns = {
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "PHONE": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b"
    }

    for category, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            spans.append((
                match.start(),
                match.end(),
                f"[{category}]"
            ))
    doc = nlp(text)

    for entity in doc.ents:
        if entity.label_ == "PERSON":
            spans.append((
                entity.start_char,
                entity.end_char,
                "[PERSON]"
            ))

    spans.sort(key=lambda span: (span[0], -(span[1] - span[0])))

    filtered = []

    for span in spans:
        if not filtered or span[0] >= filtered[-1][1]:
            filtered.append(span)

    return filtered

parser.add_argument(
    "-p",
    "--pdf",
    required=True,
    help="Path to the PDF file"
)

def remove_pdf_links(pdf_path, temp_path):
    with pymupdf.open(str(pdf_path)) as pdf:
        for page in pdf:
            for link in page.get_links():
                page.delete_link(link)

        pdf.save(str(temp_path))

args = parser.parse_args();
print(args.pdf)

pdf_path = Path(args.pdf).expanduser().resolve()
if not pdf_path.is_file():
    parser.error("The specified file does not exist.")

if pdf_path.suffix.lower() != ".pdf":
    parser.error("The specified file must be a PDF.")

print("Valid PDF file:", pdf_path)

file_name = pdf_path.stem
output_name = file_name + "_redacted.docx"
output_path = pdf_path.with_name(output_name)

print("Input:", pdf_path)
print("Output:", output_path)

##temporary directory to remove links
with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = Path(temp_dir) / "no_links.pdf"
    remove_pdf_links(pdf_path, temp_path)
    converter = Converter(str(temp_path))

    try:
        converter.convert(str(output_path))
    finally:
        converter.close()

document = Document(output_path)
for paragraph in document.paragraphs:
    mask_paragraph(paragraph)

document.save(output_path)
print("Conversion successful!")
print(f"open {output_path}")


