"""odin-pdf-tables <pdf>: the tables pdfplumber finds, as Markdown under the page each is on,
within a time budget; prints nothing for a document without tables. web.read appends this to
the document's text, whose plain extraction flattens a table into loose words."""
import sys
import time

import pdfplumber

BUDGET = 15
MAX_PAGES = 80


def cell(value):
    return " ".join((value or "").split()).replace("|", "\\|")


def main():
    started = time.monotonic()
    out = []
    with pdfplumber.open(sys.argv[1]) as pdf:
        for number, page in enumerate(pdf.pages[:MAX_PAGES], 1):
            if time.monotonic() - started > BUDGET:
                out.append(f"(tables after page {number - 1} were not read in the time allowed)")
                break
            for table in page.extract_tables():
                rows = [[cell(c) for c in row] for row in table if any(row)]
                if len(rows) < 2 or max(len(row) for row in rows) < 2:
                    continue
                width = max(len(row) for row in rows)
                rows = [row + [""] * (width - len(row)) for row in rows]
                out += [f"Table on page {number}:", "| " + " | ".join(rows[0]) + " |", "|" + "---|" * width]
                out += ["| " + " | ".join(row) + " |" for row in rows[1:]] + [""]
    if out:
        print("\n## Tables\n\n" + "\n".join(out))


if __name__ == "__main__":
    main()
