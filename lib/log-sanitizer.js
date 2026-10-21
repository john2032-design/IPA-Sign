const ANSI_ESCAPE_PATTERN = /\x1B\[[0-?]*[ -/]*[@-~]/g;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Remove actual secret values without inserting a placeholder or deleting ordinary
 * substrings. Longer secrets are removed as whole tokens. For secrets shorter than
 * four characters, only recognizable password assignments are scrubbed because a
 * one-character password can otherwise match progress counters such as "2 / 2".
 */
export function removeSecretValue(value, secretValue = '') {
  const text = String(value ?? '');
  const secret = String(secretValue || '');
  if (!secret) return text;
  const escaped = escapeRegExp(secret);

  if (secret.length < 4) {
    const shortSecretAssignment = new RegExp(
      `((?:p12\\s+)?password\\s*[:=]\\s*["']?|passphrase\\s*[:=]\\s*["']?|(?:^|\\s)-p\\s+["']?)${escaped}(?=$|[\\s"';&,])`,
      'gi'
    );
    return text.replace(shortSecretAssignment, (match, prefix) => prefix);
  }

  const wholeSecretToken = new RegExp(`(?<![A-Za-z0-9])${escaped}(?![A-Za-z0-9])`, 'g');
  return text.replace(wholeSecretToken, '');
}

export function safeTerminalLine(value, secretValue = '') {
  let line = String(value || '').replace(ANSI_ESCAPE_PATTERN, '');
  line = removeSecretValue(line, secretValue);
  return line.replace(CONTROL_CHARACTER_PATTERN, '').trim().slice(0, 900);
}
