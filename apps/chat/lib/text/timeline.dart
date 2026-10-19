import '../store/message.dart';

/// The conversation as rows: date separators, and messages grouped by sender (docs/phase1-protocol.md
/// §5). Consecutive messages from the same side within 5 minutes on the same day form one group: only
/// the first shows a header, only the last has the tail.
sealed class TimelineEntry {
  const TimelineEntry();
  String get key;
}

class DayDivider extends TimelineEntry {
  const DayDivider(this.day, this.label);
  final DateTime day;
  final String label;
  @override
  String get key => 'day-${day.year}-${day.month}-${day.day}';
}

class MessageEntry extends TimelineEntry {
  const MessageEntry(this.message, {required this.first, required this.last});
  final ChatMessage message;

  /// Starts a group (shows the sender header) / ends it (draws the tail).
  final bool first, last;
  @override
  String get key => message.id;
}

const groupGapMs = 5 * 60 * 1000;

DateTime _day(int ms) {
  final t = DateTime.fromMillisecondsSinceEpoch(ms);
  return DateTime(t.year, t.month, t.day);
}

const _weekdays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const _months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

/// "Today", "Yesterday", a weekday within the last week, else "3 March" (with the year when not this year).
String dayLabel(DateTime day, DateTime now) {
  final today = DateTime(now.year, now.month, now.day);
  final days = DateTime(today.year, today.month, today.day).difference(DateTime(day.year, day.month, day.day)).inHours / 24;
  if (days.round() == 0) return 'Today';
  if (days.round() == 1) return 'Yesterday';
  if (days > 1 && days < 7) return _weekdays[day.weekday - 1];
  final base = '${day.day} ${_months[day.month - 1]}';
  return day.year == now.year ? base : '$base ${day.year}';
}

/// Oldest first, like [messages].
List<TimelineEntry> buildTimeline(List<ChatMessage> messages, {DateTime? now}) {
  final at = now ?? DateTime.now();
  final out = <TimelineEntry>[];
  for (var i = 0; i < messages.length; i++) {
    final m = messages[i];
    final previous = i > 0 ? messages[i - 1] : null, next = i + 1 < messages.length ? messages[i + 1] : null;
    final day = _day(m.createdAt);
    final newDay = previous == null || _day(previous.createdAt) != day;
    if (newDay) out.add(DayDivider(day, dayLabel(day, at)));
    bool joins(ChatMessage? a, ChatMessage? b) =>
        a != null && b != null && a.direction == b.direction && _day(a.createdAt) == _day(b.createdAt) && (b.createdAt - a.createdAt).abs() <= groupGapMs;
    out.add(MessageEntry(m, first: !joins(previous, m), last: !joins(m, next)));
  }
  return out;
}
