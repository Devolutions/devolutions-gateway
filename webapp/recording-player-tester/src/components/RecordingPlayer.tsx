import { useEffect, useRef } from 'react';
import * as api from '../api-client';
import { useRecordingPlayerContext } from '../context/RecordingPlayerContext';

export function RecordingPlayer() {
  const { setShowPlayer, selectedRecording, currentLanguage } = useRecordingPlayerContext();
  const iframeRef = useRef<HTMLDivElement>(null);

  const handleClose = () => {
    setShowPlayer(false);
  };

  useEffect(() => {
    async function openPlayer() {
      if (!selectedRecording) {
        return;
      }
      const url = await api.getPlayerUrl({
        uid: selectedRecording.id,
        active: selectedRecording.isActive,
        lang: currentLanguage,
      });

      if (iframeRef.current) {
        iframeRef.current.innerHTML = `
        <iframe src="${url}" frameborder="0" class="h-[70vh] w-[70vw] border-none overflow-hidden"></iframe>
      `;
      }
    }

    openPlayer();
  }, [selectedRecording, currentLanguage]);

  return (
    <div className="fixed inset-0 flex justify-center items-center mt-8 overflow-hidden">
      <button
        onClick={handleClose}
        className="absolute top-24 right-[400px] px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600"
        type="button"
      >
        Close
      </button>
      <div ref={iframeRef} className="relative" />
    </div>
  );
}
