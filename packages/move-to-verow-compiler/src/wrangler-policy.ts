import ts from 'typescript';

const allowedWranglerKeys = new Set([
  '$schema',
  'compatibility_date',
  'compatibility_flags',
  'name',
  'pages_build_output_dir',
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isAllowedValue(key: string, value: unknown): boolean {
  if (key === 'compatibility_flags') {
    return Array.isArray(value) && value.every((item) => typeof item === 'string');
  }
  return typeof value === 'string';
}

function isMinimalJsonConfig(text: string, path: string): boolean {
  const parsed = ts.parseConfigFileTextToJson(path, text);
  if (parsed.error || !isPlainObject(parsed.config)) return false;
  const entries = Object.entries(parsed.config);
  return entries.every(([key, value]) => allowedWranglerKeys.has(key) && isAllowedValue(key, value));
}

function stripTomlComment(line: string): string {
  let quote: '"' | "'" | null = null;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if ((character === '"' || character === "'") && line[index - 1] !== '\\') {
      quote = quote === character ? null : quote === null ? character : quote;
    } else if (character === '#' && quote === null) {
      return line.slice(0, index);
    }
  }
  return line;
}

function isMinimalTomlConfig(text: string): boolean {
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = stripTomlComment(rawLine).trim();
    if (line === '') continue;
    if (line.startsWith('[')) return false;
    const match = /^([A-Za-z0-9_$-]+)\s*=\s*(.+)$/u.exec(line);
    if (!match || !allowedWranglerKeys.has(match[1] ?? '')) return false;
    const key = match[1] ?? '';
    const value = match[2]?.trim() ?? '';
    if (key === 'compatibility_flags') {
      if (!/^\[(?:\s*["'][^"']*["']\s*,?)*\]$/u.test(value)) return false;
    } else if (!/^["'][^"']*["']$/u.test(value)) {
      return false;
    }
  }
  return true;
}

export function isMinimalHostingOnlyWranglerConfig(path: string, text: string): boolean {
  if (path.endsWith('.toml')) return isMinimalTomlConfig(text);
  return isMinimalJsonConfig(text, path);
}
