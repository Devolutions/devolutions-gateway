import { listRealtimeRecordings } from './apiClient';
import { download, playStream } from './play';

// Function to populate the file list
async function populateFileList() {
  const files = await listRealtimeRecordings();

  const fileList = document.getElementById('fileList');
  if (!fileList) {
    console.error('File list not found');
    return;
  }

  fileList.innerHTML = ''; // Clear existing items

  files.forEach((file, index) => {
    const fileItem = document.createElement('div');
    fileItem.className = 'file-item';

    const fileName = document.createElement('span');
    fileName.className = 'file-name';
    fileName.textContent = file;

    const playButton = document.createElement('button');
    playButton.className = 'play-button';
    playButton.textContent = 'Play';
    playButton.onclick = () => playStream(file);

    fileItem.appendChild(fileName);
    fileItem.appendChild(playButton);

    fileList.appendChild(fileItem);
  });
}

// Initialize the file list on page load
window.onload = populateFileList;

export function refreshList() {
  // Logic to refresh the list can be added here
  // For now, we'll just re-populate the list
  populateFileList();
}

export const getElementNotNull = (id: string) => {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Element with ID ${id} not found`);
  }
  return element;
};

getElementNotNull('refreshButton').onclick = refreshList;
getElementNotNull('downloadButton').onclick = download;
