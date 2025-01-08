import { listRealtimeRecordings } from './api-client';
import { openPlayer } from './player';

const recordingList = document.getElementById('recordingList');

if (!recordingList) {
  throw new Error('Recording list not found');
}

const refreshButton = document.getElementById('refreshButton');
if (!refreshButton) {
  throw new Error('Refresh button not found');
}

refreshButton.addEventListener('click', refresh);

function populate_list(list: string[]) {
  for (const recording of list) {
    const listItem = document.createElement('li');
    listItem.style.marginBottom = '10px';

    const recordingText = document.createElement('span');
    recordingText.textContent = recording;

    const playButton = document.createElement('button');
    playButton.textContent = 'Play';
    playButton.style.marginLeft = '10px';
    playButton.classList.add('btn');

    // Add click event to play button
    playButton.addEventListener('click', () => {
      openPlayer({ recordingId: recording, active: true });
    });

    listItem.appendChild(recordingText);
    listItem.appendChild(playButton);
    recordingList?.appendChild(listItem);
  }
}

async function refresh() {
  const list = await listRealtimeRecordings();
  populate_list(list);
}

refresh();
