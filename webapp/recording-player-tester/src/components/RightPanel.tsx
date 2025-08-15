import React, { useEffect } from 'react';
import { useRecordingPlayerContext } from '../context/RecordingPlayerContext';
import { RecordingPlayer } from './RecordingPlayer';

export const RightPanel: React.FC = () => {
  const { showPlayer, setShowPlayer, selectedRecording } = useRecordingPlayerContext();
  useEffect(() => {
    setShowPlayer(!!selectedRecording);
  }, [selectedRecording, setShowPlayer]);

  return (
    <div className="flex flex-col flex-grow bg-gray-100 justify-center items-center">
      <h1 className="text-2xl font-bold text-gray-800 mb-6">Recording Player Tester</h1>
      {!showPlayer && <div className="text-gray-500 italic">No recording selected</div>}
      {showPlayer && <RecordingPlayer />}
    </div>
  );
};
