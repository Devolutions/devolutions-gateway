import React, { createContext, useState, useContext, ReactNode, useEffect } from 'react';
import { listRecordings } from '../api-client';

export interface Recording {
  id: string;
  duration: number;
}

const contextCreator = () => {
  const [file, setFile] = useState<File | null>(null);
  const [fileDetails, setFileDetails] = useState<{
    name: string;
    size: string;
    type: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showPlayer, setShowPlayer] = useState(false);
  const [recordings, setRecordings] = useState<string[]>([]);
  const [selectedRecording, setSelectedRecording] = useState<{
    id: string;
    isActive: boolean;
  } | null>(null);

  const [streamingRecordings, setStreamingRecordings] = useState<string[]>([]);
  const [currentLanguage, setCurrentLanguage] = useState<string>('en');

  useEffect(() => {
    const fetchFinishedRecordings = async () => {
      const response = await listRecordings({
        active: false,
      });
      setRecordings(response);
    };

    fetchFinishedRecordings();
  }, []);

  return {
    file,
    setFile,
    fileDetails,
    setFileDetails,
    error,
    setError,
    showPlayer,
    setShowPlayer,
    recordings,
    setRecordings,
    selectedRecording,
    setSelectedRecording,
    streamingRecordings,
    setStreamingRecordings,
    currentLanguage,
    setCurrentLanguage,
  };
};

const RecordingPlayerContext = createContext<ReturnType<typeof contextCreator> | undefined>(undefined);

export const useRecordingPlayerContext = () => {
  const context = useContext(RecordingPlayerContext);
  if (context === undefined) {
    throw new Error('useRecordingPlayerContext must be used within a RecordingPlayerProvider');
  }
  return context;
};

export const RecordingPlayerProvider = ({
  children,
}: {
  children: ReactNode;
}) => {
  const value = contextCreator();
  return <RecordingPlayerContext.Provider value={value}>{children}</RecordingPlayerContext.Provider>;
};
