const app = document.getElementById('app') as HTMLElement;
const fileInput = document.getElementById('fileInput') as HTMLInputElement;
const fileDetails = document.getElementById('fileDetails') as HTMLElement;
const playButton = document.getElementById('playButton') as HTMLButtonElement;

// Function to handle file selection
fileInput.addEventListener('change', (event: Event) => {
  const target = event.target as HTMLInputElement;
  if (target.files && target.files.length > 0) {
    const file = target.files[0];
    const fileName = file.name;
    const fileSize = (file.size / 1024 / 1024).toFixed(2); // File size in MB
    const fileExtension = fileName.split('.').pop()?.toLowerCase();

    // Validate the file extension
    if (['trp', 'webm', 'cast'].includes(fileExtension || '')) {
      fileDetails.innerHTML = `<p>File name: <strong>${fileName}</strong></p>
                               <p>File size: <strong>${fileSize} MB</strong></p>
                               <p>File type: <strong>${fileExtension}</strong></p>`;
      playButton.disabled = false; // Enable the play button when a valid file is uploaded
      fileDetails.classList.remove('error');
      // upload file to server
      const formData = new FormData();
      formData.append('file', file);
      fetch('upload', {
        method: 'POST',
        body: formData,
      })
    }
  } else {
    fileDetails.innerHTML = `<p class="error">Invalid file type. Only .trp, .webm, and .cast files are allowed.</p>`;
    fileInput.value = ''; // Clear the input if the file type is invalid
    playButton.disabled = true; // Disable the play button
  }
});

// Empty function for Play button (add functionality later)
playButton.addEventListener('click', () => {
  app.innerHTML = `
    <iframe src="player" width="100%" height="100%" frameborder="0">
    </iframe>
  `
});
