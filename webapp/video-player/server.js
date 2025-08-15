import { createReadStream, existsSync, statSync } from 'node:fs';
import path, { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 5678;

// Video streaming route
app.get('/video/*', (req, res) => {
  const videoFile = req.params[0]; // Extract the file path after /video/
  const videoPath = join(__dirname, 'example-videos', videoFile);

  if (!existsSync(videoPath)) {
    return res.status(404).send('Video not found');
  }

  const stat = statSync(videoPath);
  const fileSize = stat.size;
  const range = req.headers.range;

  if (range) {
    const parts = range.replace(/bytes=/, '').split('-');
    const start = Number.parseInt(parts[0], 10);
    const end = parts[1] ? Number.parseInt(parts[1], 10) : fileSize - 1;
    const chunksize = end - start + 1;
    const file = createReadStream(videoPath, { start, end });
    const head = {
      'Content-Range': `bytes ${start}-${end}/${fileSize}`,
      'Accept-Ranges': 'bytes',
      'Content-Length': chunksize,
      'Content-Type': 'video/mp4',
    };
    res.writeHead(206, head);
    file.pipe(res);
  } else {
    const head = {
      'Content-Length': fileSize,
      'Content-Type': 'video/mp4',
    };
    res.writeHead(200, head);
    createReadStream(videoPath).pipe(res);
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
