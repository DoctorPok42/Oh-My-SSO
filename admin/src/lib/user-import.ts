// What the import of users needs without React: reading the file, and the CSV
// files the console gives back. The Admin API checks the file again.

/** service.MaxUserImportBytes: a larger file is refused before it is sent. */
export const MAX_IMPORT_BYTES = 1 << 20;

export const IMPORT_TEMPLATE =
  "email,username,name,department,groups,roles\r\n" +
  "alice@example.com,alice,Alice Moreau,Sales,staff|sales,support\r\n" +
  "bob@example.com,,Bob Martin,,staff,\r\n";

/**
 * The text of a file, or null when it is not UTF-8. file.text() would turn
 * the accents of a Latin-1 export into "�", and the server would never know.
 */
export function decodeCsvFile(bytes: ArrayBuffer): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/**
 * One cell. A spreadsheet runs what starts like a formula, and the cells of a
 * report come from an uploaded file: "=HYPERLINK(...)" is written as text.
 * https://owasp.org/www-community/attacks/CSV_Injection
 */
export function csvCell(value: string | number): string {
  let s = String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

/** A CSV file; the BOM makes Excel read it as UTF-8. */
export function toCsv(rows: (string | number)[][]): string {
  return "\uFEFF" + rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

/** How far an import is, 0 to 100. */
export function importPercent(job: { processed: number; total: number }): number {
  return job.total > 0 ? Math.min(100, Math.floor((job.processed / job.total) * 100)) : 0;
}

/** Saves a text as a file, from the browser. */
export function downloadText(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/csv;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
