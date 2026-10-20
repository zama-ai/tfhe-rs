#!/usr/bin/env python3
"""
Convert a workflow CSV (from stdin) to a formatted ODS spreadsheet.
Lines beginning with "WARNING: " are ignored.

Usage:
    python3 csv_to_ods.py [output.ods]   (default: workflows.ods)
    cat workflows.csv | python3 csv_to_ods.py workflows.ods
"""

import csv
import io
import sys
import zipfile

# ---------------------------------------------------------------------------
# Formatting constants (derived from workflows_example.ods)
# ---------------------------------------------------------------------------

# Number of leading metadata columns before the test-name columns
N_META = 6  # Workflow | PR | PR on approved | Manual only | Cron | Profile

# Column widths (inches) for the 6 metadata columns, in order
META_COL_WIDTHS = [
    "2.7874in",  # Workflow
    "0.4665in",  # PR
    "0.4035in",  # PR on approved
    "0.5043in",  # Manual only
    "1.1787in",  # Cron
    "1.678in",   # Profile (instance)
]

TEST_COL_WIDTH = "0.4290in"

# Row heights
HEADER_ROW_HEIGHT = "3.3898in"
DATA_ROW_HEIGHT   = "0.2311in"

# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def x(s: str) -> str:
    """Escape XML special characters."""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))


def make_cell(text: str, style: str = "ce_data") -> str:
    s = f' table:style-name="{style}"'
    if text:
        return (
            f'<table:table-cell{s} office:value-type="string">'
            f"<text:p>{x(text)}</text:p>"
            f"</table:table-cell>"
        )
    return f"<table:table-cell{s}/>"


# ---------------------------------------------------------------------------
# ODS builder
# ---------------------------------------------------------------------------

CONTENT_XML_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<office:document-content
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
  xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
  xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"
  xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
  office:version="1.3">
<office:automatic-styles>
  {col_styles}
  <style:style style:name="ro1" style:family="table-row">
    <style:table-row-properties style:row-height="{header_row_height}"
      fo:break-before="auto" style:use-optimal-row-height="true"/>
  </style:style>
  <style:style style:name="ro2" style:family="table-row">
    <style:table-row-properties style:row-height="{data_row_height}"
      fo:break-before="auto" style:use-optimal-row-height="true"/>
  </style:style>
  <style:style style:name="ta1" style:family="table" style:master-page-name="Default">
    <style:table-properties table:display="true" style:writing-mode="lr-tb"/>
  </style:style>
  <!-- ce_data: plain data cells with border + padding -->
  <style:style style:name="ce_data" style:family="table-cell" style:parent-style-name="Default">
    <style:table-cell-properties
      fo:border="0.74pt solid #aaaaaa"
      fo:padding="0.0417in"/>
  </style:style>
  <!-- ce1: bold - plain metadata header cells -->
  <style:style style:name="ce1" style:family="table-cell" style:parent-style-name="Default">
    <style:table-cell-properties
      fo:border="0.74pt solid #aaaaaa"
      fo:padding="0.0417in"/>
    <style:text-properties fo:font-weight="bold"
      style:font-weight-asian="bold" style:font-weight-complex="bold"/>
  </style:style>
  <!-- ce3: bold + wrap - "PR on approved" header cell -->
  <style:style style:name="ce3" style:family="table-cell" style:parent-style-name="Default">
    <style:table-cell-properties
      fo:wrap-option="wrap"
      fo:border="0.74pt solid #aaaaaa"
      fo:padding="0.0417in"/>
    <style:text-properties fo:font-weight="bold"
      style:font-weight-asian="bold" style:font-weight-complex="bold"/>
  </style:style>
  <!-- ce5: bold + 66 degree rotation - test-name header cells -->
  <style:style style:name="ce5" style:family="table-cell" style:parent-style-name="Default">
    <style:table-cell-properties
      style:rotation-angle="66"
      fo:border="0.74pt solid #aaaaaa"
      fo:padding="0.0417in"/>
    <style:text-properties fo:font-weight="bold"
      style:font-weight-asian="bold" style:font-weight-complex="bold"/>
  </style:style>
  <!-- ce_wrap: wrap - data cells that need word wrap (e.g. Cron) -->
  <style:style style:name="ce_wrap" style:family="table-cell" style:parent-style-name="Default">
    <style:table-cell-properties
      fo:wrap-option="wrap"
      fo:border="0.74pt solid #aaaaaa"
      fo:padding="0.0417in"/>
  </style:style>
</office:automatic-styles>
<office:body>
<office:spreadsheet>
<table:table table:name="Sheet1" table:style-name="ta1">
  {col_decls}
  {rows}
</table:table>
</office:spreadsheet>
</office:body>
</office:document-content>
"""

MANIFEST_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest
  xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
  manifest:version="1.3">
  <manifest:file-entry manifest:full-path="/"
    manifest:version="1.3"
    manifest:media-type="application/vnd.oasis.opendocument.spreadsheet"/>
  <manifest:file-entry manifest:full-path="content.xml"
    manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="styles.xml"
    manifest:media-type="text/xml"/>
</manifest:manifest>
"""

# Page layout: 28in x 12in, landscape (from workflows_example.ods)
STYLES_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
  xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
  xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
  office:version="1.3">
<office:automatic-styles>
  <style:page-layout style:name="Mpm1">
    <style:page-layout-properties
      fo:page-width="28in"
      fo:page-height="12in"
      style:print-orientation="landscape"
      style:writing-mode="lr-tb"/>
    <style:header-style>
      <style:header-footer-properties
        fo:min-height="0.2953in"
        fo:margin-left="0in"
        fo:margin-right="0in"
        fo:margin-bottom="0.0984in"/>
    </style:header-style>
    <style:footer-style>
      <style:header-footer-properties
        fo:min-height="0.2953in"
        fo:margin-left="0in"
        fo:margin-right="0in"
        fo:margin-top="0.0984in"/>
    </style:footer-style>
  </style:page-layout>
</office:automatic-styles>
<office:master-styles>
  <style:master-page style:name="Default" style:page-layout-name="Mpm1"/>
</office:master-styles>
</office:document-styles>
"""

MIMETYPE = "application/vnd.oasis.opendocument.spreadsheet"


def build_ods(rows: list[list[str]], output_path: str) -> None:
    if not rows:
        raise ValueError("No rows to write")

    n_cols = len(rows[0])
    n_test = n_cols - N_META

    # --- column style declarations -------------------------------------------
    col_styles = []
    for i, w in enumerate(META_COL_WIDTHS):
        col_styles.append(
            f'<style:style style:name="co{i+1}" style:family="table-column">'
            f'<style:table-column-properties fo:break-before="auto" style:column-width="{w}"/>'
            f"</style:style>"
        )
    col_styles.append(
        f'<style:style style:name="co{N_META+1}" style:family="table-column">'
        f'<style:table-column-properties fo:break-before="auto" style:column-width="{TEST_COL_WIDTH}"/>'
        f"</style:style>"
    )

    # --- column declarations inside the table --------------------------------
    col_decls = []
    for i in range(N_META):
        col_decls.append(f'<table:table-column table:style-name="co{i+1}"/>')
    if n_test > 0:
        col_decls.append(
            f'<table:table-column table:style-name="co{N_META+1}"'
            f' table:number-columns-repeated="{n_test}"/>'
        )

    # --- header row ----------------------------------------------------------
    header = rows[0]
    header_cells = []
    for i, h in enumerate(header):
        if i in (2, 4):
            style = "ce3"   # "PR on approved" / "Cron": bold + wrap
        elif i < N_META:
            style = "ce1"   # other metadata: bold
        else:
            style = "ce5"   # test names: bold + rotated
        header_cells.append(make_cell(h, style))

    header_row = (
        '<table:table-row table:style-name="ro1">'
        + "".join(header_cells)
        + "</table:table-row>"
    )

    # --- data rows -----------------------------------------------------------
    data_rows = []
    for row in rows[1:]:
        padded = row + [""] * (n_cols - len(row))
        cells = [make_cell(v, "ce_wrap" if i == 4 else "ce_data") for i, v in enumerate(padded)]
        data_rows.append(
            '<table:table-row table:style-name="ro2">'
            + "".join(cells)
            + "</table:table-row>"
        )

    # --- assemble content.xml ------------------------------------------------
    content = CONTENT_XML_TEMPLATE.format(
        col_styles="\n  ".join(col_styles),
        col_decls="\n  ".join(col_decls),
        rows="\n  ".join([header_row] + data_rows),
        header_row_height=HEADER_ROW_HEIGHT,
        data_row_height=DATA_ROW_HEIGHT,
    )

    # --- write ODS (ZIP) -----------------------------------------------------
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # mimetype must be first entry and stored uncompressed
        mi = zipfile.ZipInfo("mimetype")
        zf.writestr(mi, MIMETYPE, compress_type=zipfile.ZIP_STORED)
        zf.writestr("META-INF/manifest.xml", MANIFEST_XML)
        zf.writestr("styles.xml", STYLES_XML)
        zf.writestr("content.xml", content)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    output_path = sys.argv[1] if len(sys.argv) > 1 else "workflows.ods"

    raw_lines = [
        line for line in sys.stdin
        if not line.startswith("WARNING: ")
    ]

    reader = csv.reader(io.StringIO("".join(raw_lines)))
    rows = list(reader)

    if not rows:
        print("error: empty input", file=sys.stderr)
        sys.exit(1)

    # Normalise: ensure every row has the same number of columns
    n_cols = max(len(r) for r in rows)
    rows = [r + [""] * (n_cols - len(r)) for r in rows]

    build_ods(rows, output_path)
    print(f"Written {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
