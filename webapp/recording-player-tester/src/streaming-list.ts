import { listRecordings } from './api-client';
import { openPlayer } from './player';

const recordingList = document.getElementById('recordingList');
// Track existing recordings in memory with their DOM elements
const recordingElements = new Map<string, HTMLLIElement>();

// Get language selector element
const languageSelect = document.getElementById('language') as HTMLSelectElement;
if (!languageSelect) {
  throw new Error('Language selector not found');
}

// Store current language
let currentLanguage = languageSelect.value;

// Add language change listener
languageSelect.addEventListener('change', (event) => {
  currentLanguage = (event.target as HTMLSelectElement).value;
});

if (!recordingList) {
  throw new Error('Recording list not found');
}

const refreshButton = document.getElementById('refreshButton');
if (!refreshButton) {
  throw new Error('Refresh button not found');
}

refreshButton.addEventListener('click', refresh);

function createRecordingElement(recording: string): HTMLLIElement {
  const listItem = document.createElement('li');
  listItem.style.marginBottom = '10px';

  const recordingText = document.createElement('span');
  recordingText.textContent = recording;

  const playButton = document.createElement('button');
  playButton.textContent = 'Play';
  playButton.style.marginLeft = '10px';
  playButton.classList.add('btn');

  playButton.addEventListener('click', () => {
    openPlayer({ recordingId: recording, active: true, language: currentLanguage });
  });

  listItem.appendChild(recordingText);
  listItem.appendChild(playButton);
  return listItem;
}

function updateList(currentRecordings: string[]) {
  const currentSet = new Set(currentRecordings);

  // Remove recordings that are no longer active
  for (const [id, element] of recordingElements) {
    if (!currentSet.has(id)) {
      element.remove();
      recordingElements.delete(id);
    }
  }

  // Add new recordings
  for (const recording of currentRecordings) {
    if (!recordingElements.has(recording)) {
      const element = createRecordingElement(recording);
      recordingList?.appendChild(element);
      recordingElements.set(recording, element);
    }
  }
}

async function refresh() {
  const list = await listRecordings({
    active: true,
  });
  updateList(list);
}

refresh();
