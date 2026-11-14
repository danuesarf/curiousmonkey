// CSV for spreadsheets. Cells that start with = + - @ (or a tab or CR) are prefixed with ' so a spreadsheet does not
// run them as formulas: role names, ARNs and notes come from AWS or from people and are not trusted.
const cell = (v) => {
  let s = v == null ? '' : Array.isArray(v) ? v.join('; ') : v instanceof Date ? v.toISOString() : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
/** cols: [header, (row) => value]. Returns the whole file, with a header line. */
export const toCsv = (cols, rows) => `${[cols.map(([h]) => cell(h)).join(','), ...rows.map((r) => cols.map(([, f]) => cell(f(r))).join(','))].join('\n')}\n`;
/** Sends a CSV download. The name gets today's date. */
export function sendCsv(res, name, text) {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${name}-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(text);
}
