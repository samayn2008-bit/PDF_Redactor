# PDF_Redactor

A Python command-line tool that converts PDF files into Word documents and automatically masks sensitive information.

It is designed to make document redaction simple and accessible. It runs locally on your computer, so you don't have to upload documents to an external service.

## What It Does
Original text:
```text
Contact John at john@example.com.
Phone: 777-555-4444
SSN: 123-45-6789
```

Redacted document:
```text
Contact [PERSON_1] at [EMAIL_1].
Phone: [PHONE_1]
SSN: [SSN_1]
```

Redaction key:
| Placeholder | Original Value |
| --- | --- | 
| [PERSON_1] | John | 
| [EMAIL_1] | john@example.com | 
| [PHONE_1] | 777-555-4444 | 
| [SSN_1] | 123-45-6789 | 

## Setup

You need Python 3.12, Poetry, and Microsoft Word.

1. Clone the repository
```bash
git clone https://github.com/samayn2008-bit PDF_Redactor.git
cd PDF_Redactor/pdf-redactor
```

2. Install dependencies
```bash
poetry install
```

3. Install the spaCy English language model
```bash
poetry run python -m spacy download en_core_web_sm
```

## Usage
Run the script with the path to the PDF you want to redact:
```bash
poetry run python main.py -p /path/to/document.pdf
```

For example, on macOS:
```bash
poetry run python main.py -p ~/Downloads/document.pdf
```
