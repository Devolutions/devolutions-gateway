import { useEffect } from 'react';
import { listRecordings } from '../api-client';
import { useRecordingPlayerContext } from '../context/RecordingPlayerContext';

export function StreamingList() {
  const { setSelectedRecording, setStreamingRecordings, currentLanguage, setCurrentLanguage, streamingRecordings } =
    useRecordingPlayerContext();

  useEffect(() => {
    const refreshRecordings = async () => {
      try {
        const list = await listRecordings({
          active: true,
        });
        setStreamingRecordings(list);
      } catch (error) {
        console.error('Error fetching recordings:', error);
      }
    };
    // Initial load
    refreshRecordings();
  }, [setStreamingRecordings]);

  const handlePlay = (recordingId: string) => {
    setSelectedRecording({ id: recordingId, isActive: true });
  };

  return (
    <div>
      <div className="language-selector mb-4">
        <label htmlFor="language" className="mr-2 text-gray-700">
          Language:
        </label>
        <select
          id="language"
          value={currentLanguage}
          onChange={(e) => setCurrentLanguage(e.target.value)}
          className="p-2 border border-gray-300 rounded bg-white"
        >
          <option value="en">English</option>
          <option value="fr">French</option>
          <option value="es">Spanish</option>
          <option value="de">German</option>
        </select>
      </div>

      <ul className="space-y-2 list-none pl-0">
        {streamingRecordings.length === 0 && <li className="text-gray-500 italic">No active recordings available</li>}
        {streamingRecordings.map((recording) => (
          <li key={recording} className="flex items-center justify-between p-2 border-b border-gray-200">
            <span className="truncate">{recording}</span>
            <button
              onClick={() => handlePlay(recording)}
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
