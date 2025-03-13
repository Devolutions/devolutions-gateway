import { RecordingPlayerProvider } from './context/RecordingPlayerContext';
import { LeftPanel } from './components/LeftPanel';
import { RightPanel } from './components/RightPanel';

function App() {
  return (
    <RecordingPlayerProvider>
      <div className="flex h-screen w-full">
        <LeftPanel />
        <RightPanel />
      </div>
    </RecordingPlayerProvider>
  );
}

export default App;
