import { useEffect, useMemo, useRef, useState } from 'react';
import * as api from '../api-client';
import { useRecordingPlayerContext } from '../context/RecordingPlayerContext';

// The gateway can hold hundreds of recordings; cap the rendered rows and let the user filter by id.
const MAX_VISIBLE = 100;
const FETCH_CONCURRENCY = 8;

// A recording's start time never changes, so the fetched id->startTime index is persisted to
// localStorage. It survives page refreshes — the times are loaded once and only missing ids fetched.
const STORAGE_KEY = 'recording-player-tester:start-times';

// /jet/jrec/list returns only ids. Id sorts are instant; the recency sorts lazily fetch each matched
// recording's start time from its manifest (then cached), so filter first to keep that cheap.
type SortMode = 'newest' | 'oldest' | 'id-asc' | 'id-desc';

const isTimeSort = (mode: SortMode) => mode === 'newest' || mode === 'oldest';

function loadCachedTimes(): Record<string, number> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : null;
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, number>) : {};
  } catch {
    return {};
  }
}

function saveCachedTimes(times: Record<string, number>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(times));
  } catch {
    // storage unavailable or full — caching is best-effort, so ignore.
  }
}

export function RecordingList() {
  const { recordings, setSelectedRecording } = useRecordingPlayerContext();
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<SortMode>('id-asc');
  const [times, setTimes] = useState<Record<string, number>>(loadCachedTimes);
  const [loading, setLoading] = useState(false);
  const timesRef = useRef<Record<string, number>>({ ...times });

  const matched = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? recordings.filter((recording) => recording.toLowerCase().includes(q)) : recordings;
  }, [recordings, query]);

  // For time sorts, fetch (and persistently cache) each matched recording's start time, bounded concurrency.
  useEffect(() => {
    if (!isTimeSort(sort)) {
      return;
    }
    const missing = matched.filter((id) => timesRef.current[id] === undefined);
    if (missing.length === 0) {
      return;
    }
    let cancelled = false;
    setLoading(true);
    (async () => {
      for (let i = 0; i < missing.length && !cancelled; i += FETCH_CONCURRENCY) {
        const batch = missing.slice(i, i + FETCH_CONCURRENCY);
        const results = await Promise.all(
          batch.map(async (id) => {
            try {
              return [id, await api.getRecordingStartTime(id)] as const;
            } catch {
              return [id, 0] as const;
            }
          }),
        );
        for (const [id, startTime] of results) {
          timesRef.current[id] = startTime;
        }
        if (!cancelled) {
          setTimes({ ...timesRef.current });
          saveCachedTimes(timesRef.current);
        }
      }
      if (!cancelled) {
        setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [sort, matched]);

  const sorted = useMemo(() => {
    const arr = matched.slice();
    if (sort === 'id-asc') {
      arr.sort((a, b) => a.localeCompare(b));
    } else if (sort === 'id-desc') {
      arr.sort((a, b) => b.localeCompare(a));
    } else {
      const dir = sort === 'newest' ? -1 : 1;
      arr.sort((a, b) => dir * ((times[a] ?? 0) - (times[b] ?? 0)));
    }
    return arr;
  }, [matched, sort, times]);

  const loadedCount = matched.filter((id) => times[id] !== undefined).length;
  const visible = sorted.slice(0, MAX_VISIBLE);

  return (
    <div>
      <div className="flex gap-2 mb-2">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter by recording id…"
          className="flex-grow px-2 py-1 border border-gray-300 rounded text-sm"
        />
        <select
          value={sort}
          onChange={(e) => setSort(e.target.value as SortMode)}
          className="px-2 py-1 border border-gray-300 rounded text-sm bg-white"
        >
          <option value="id-asc">Id ↑</option>
          <option value="id-desc">Id ↓</option>
          <option value="newest">Newest</option>
          <option value="oldest">Oldest</option>
        </select>
      </div>
      <div className="text-xs text-gray-500 mb-2">
        {matched.length} / {recordings.length} recordings
        {matched.length > MAX_VISIBLE && ` (showing first ${MAX_VISIBLE})`}
        {isTimeSort(sort) && loading && ` · loading times ${loadedCount}/${matched.length}…`}
      </div>
      <ul className="space-y-2 list-none pl-0">
        {matched.length === 0 && <li className="text-gray-500 italic">No matching recordings</li>}
        {visible.map((recording) => (
          <li key={recording} className="flex items-center justify-between p-2 border-b border-gray-200">
            <span className="truncate">{recording}</span>
            <button
              onClick={() =>
                setSelectedRecording({
                  id: recording,
                  isActive: false,
                })
              }
              className="ml-2 px-3 py-1 bg-blue-500 text-white rounded text-sm hover:bg-blue-600"
              type="button"
            >
              Play
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
