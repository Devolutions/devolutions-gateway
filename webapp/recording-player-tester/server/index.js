import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import multer from "multer";

// Get the OS's temp directory
const tempDir = os.tmpdir();

// Global variable to store file handle (file path and metadata)
const uploadedFileHandle = [];

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
    uploadedFileHandle.push({
      originalname: req.file.originalname,
      path: req.file.path,
      mimetype: req.file.mimetype,
      size: req.file.size,
    });

    res.send(
      `File uploaded successfully: ${req.file.originalname}, saved at ${req.file.path}`
    );
  } catch (err) {
    res.status(500).send("Error uploading file: " + err.message);
  }
});

const playerPath = path.join(fileURLToPath(import.meta.url), "../../../player");
app.use("/jet/jrec/play", express.static(playerPath));

app.get("/jet/jrec/pull/:sessionId/:fileName", (req, res) => {
  if (uploadedFileHandle?.length === 0) {
    return res.status(404).send("No file uploaded.");
  }

  console.log("File pulled invoked, fileName: ", req.params.fileName);

  if (req.params.fileName === "recording.json") {
    res.json({
      sessionId: req.params.sessionId,
      startTime: 1728335793,
      duration: 8,
      files: uploadedFileHandle.map((file) => ({
        fileName: file.originalname,
        startTime: 1728335793,
        duration: 8,
      })),
    });

  } else if (req.params.fileName === uploadedFileHandle.originalname) {
    const { path, originalname, mimetype, size } = uploadedFileHandle;
    const fileStream = fs.createReadStream(path);

    res.setHeader(
      "Content-Disposition",
      `attachment; filename=${originalname}`
    );
    res.setHeader("Content-Type", mimetype);
    res.setHeader("Content-Length", size);

    fileStream.pipe(res);
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
