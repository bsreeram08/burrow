/// Fuzzy matching for the command palette: every query character must appear in order. Matches at the
/// start, at word starts and in runs score higher; null means no match. Case-insensitive.
int? fuzzyScore(String query, String candidate) {
  final q = query.trim().toLowerCase(), c = candidate.toLowerCase();
  if (q.isEmpty) return 0;
  var score = 0, from = 0, run = 0, previous = -2;
  for (final ch in q.split('')) {
    if (ch == ' ') continue;
    final at = c.indexOf(ch, from);
    if (at == -1) return null;
    final wordStart = at == 0 || ' -_./@'.contains(c[at - 1]);
    run = at == previous + 1 ? run + 1 : 0;
    score += 1 + (wordStart ? 8 : 0) + run * 4 - ((at - from).clamp(0, 10));
    if (at == 0) score += 10;
    previous = at;
    from = at + 1;
  }
  if (c.startsWith(q)) score += 25;
  if (c == q) score += 50;
  return score;
}

/// [items] that match [query], best first; ties keep their order (recent items are passed first).
List<T> fuzzyFilter<T>(String query, List<T> items, String Function(T) text) {
  final scored = <(T, int, int)>[];
  for (var i = 0; i < items.length; i++) {
    final s = fuzzyScore(query, text(items[i]));
    if (s != null) scored.add((items[i], s, i));
  }
  scored.sort((a, b) => b.$2 != a.$2 ? b.$2.compareTo(a.$2) : a.$3.compareTo(b.$3));
  return [for (final s in scored) s.$1];
}
