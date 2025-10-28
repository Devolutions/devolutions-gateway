export function ensureNoSameTimeCues(content: string) {
  const lines = content.split('\n');
  let prevLine = null; // Correctly using let to track previous line
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    try {
      const parsed = JSON.parse(line);
      if (Array.isArray(parsed)) {
        if (prevLine && prevLine[0] === parsed[0]) {
          parsed[0] += 0.001; // Adjust timestamp if same as previous
        }
        // Update the current line in the array after modification
        lines[i] = JSON.stringify(parsed);
        prevLine = parsed; // Update prevLine to the current parsed line
      }
    } catch (_e) {
      // If parsing fails (e.g., it's a non-JSON line), skip
    }
  }
  return lines.join('\n');
}
