import React, { useEffect } from 'react';
import { RecordingPlayer } from './RecordingPlayer';
import { useRecordingPlayerContext } from '../context/RecordingPlayerContext';

export const RightPanel: React.FC = () => {
  const { showPlayer, setShowPlayer, selectedRecording: slectedRecording } = useRecordingPlayerContext();
  useEffect(() => {
    setShowPlayer(!!slectedRecording);
  }, [slectedRecording, setShowPlayer]);

  return (
    <div className="flex flex-col flex-grow bg-gray-100 justify-center items-center">
      <h1 className="text-2xl font-bold text-gray-800 mb-6">Recording Player Tester</h1>
      {!showPlayer && <div className="text-gray-500 italic">No recording selected</div>}
      {showPlayer && <RecordingPlayer />}
    </div>
  );
};
