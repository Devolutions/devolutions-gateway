import { useRecordingPlayerContext } from '../context/RecordingPlayerContext';

export function RecordingList() {
  const { recordings, setSelectedRecording } = useRecordingPlayerContext();
  return (
    <ul className="space-y-2 list-none pl-0">
      {recordings.length === 0 && <li className="text-gray-500 italic">No active recordings available</li>}
      {recordings.map((recording) => (
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
  );
}
