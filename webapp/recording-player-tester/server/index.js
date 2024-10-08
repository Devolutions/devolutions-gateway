import express from "express";
import multer from "multer";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);

// Get the OS's temp directory
const tempDir = os.tmpdir();

// Global variable to store file handle (file path and metadata)
let uploadedFileHandle = null;

// Setup Multer for file uploads, specifying destination folder as tempDir
const upload = multer({
  dest: tempDir, // Save files to the temporary directory
  limits: { fileSize: 10 * 1024 * 1024 }, // Max file size (10 MB)
  fileFilter: (req, file, cb) => {
    // Only accept .trp, .webm, and .cast files
    const fileTypes = /trp|webm|cast/;
    const extname = fileTypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    if (extname) {
      return cb(null, true);
    }
    cb(
      new Error(
        "Unsupported file type! Only .trp, .webm, and .cast files are allowed."
      )
    );
  },
});

// Initialize Express app
const app = express();

// Upload endpoint to handle file uploads
app.post("/upload", upload.single("file"), (req, res) => {
  console.log("File uploaded invoked");
  try {
    if (!req.file) {
      return res.status(400).send("No file uploaded.");
    }

    // Save the file handle globally
    uploadedFileHandle = {
      originalname: req.file.originalname,
      path: req.file.path,
      mimetype: req.file.mimetype,
      size: req.file.size,
    };

    res.send(
      `File uploaded successfully: ${req.file.originalname}, saved at ${req.file.path}`
    );
  } catch (err) {
    res.status(500).send("Error uploading file: " + err.message);
  }
});

const playerPath = path.join(fileURLToPath(import.meta.url), '../../../player');
app.use('/player', express.static(playerPath));

// Middleware to handle all other requests
app.use((req, res, next) => {
  if (req.path === "/upload" && req.method === "POST") {
    return next();
  }

  if (req.path === "/player"){
    return next();
  }

  if (uploadedFileHandle && fs.existsSync(uploadedFileHandle.path)) {
    // Send the file as a response if it exists
    res.sendFile(uploadedFileHandle.path, (err) => {
      if (err) {
        res.status(500).send("Error sending file: " + err.message);
      }
    });
  } else {
    // If no file has been uploaded yet, send a 404 response
    res.status(404).send("No file uploaded yet.");
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
