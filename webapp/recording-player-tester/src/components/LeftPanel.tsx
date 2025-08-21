import React from 'react';
import { StreamingList } from './StreamingList';
import { RecordingList } from './RecordingList';

export const LeftPanel: React.FC = () => {
  return (
    <div className="flex flex-col bg-amber-100 p-4 w-1/3 overflow-y-auto">
      <div>
        <h2 className="text-lg font-bold text-gray-700 mb-2">Active Recordings</h2>
        <div className="flex items-center gap-2 mb-4">
          <button
            className="px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600"
            id="refreshButton"
            type="button"
          >
            refresh
          </button>
        </div>
        <StreamingList />
      </div>
      <div className="mt-6">
        <h2 className="text-lg font-bold text-gray-700 mb-2">Existing Recording</h2>
        <RecordingList />
      </div>
    </div>
  );
};
