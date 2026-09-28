# Background
Recording in Gateway has always been simple.
The source pushes a stream into Gateway, and Gateway persists it to disk.
Now we would like to add a new feature, AI and machine generated logs to improve searchability.


# Logs 
Recording manifest should now have a new field called `logs`. 
We define material as a file that is pushed to Gateway.
We will have two material types, `recording` and `log`.
To keep everything backward compatible, we will accept `materialType` as a query parameter, and when it is null, we will treat the stream as a recording.
If `materialType` is `recording`, the `fileType` param must be present, we currently have four file types, `webm`, `cast`, `trp` and `slog`. That is right, `slog` can be both a recording file type and the log itself. This is intentional to keep backward compatibility.
`fileType` is mandatory for `recording`, and rejected for `log`.
The content of the log and the recording is transparent to Gateway unless it is streamed, see the `streaming` crates.
The client doesn't own the naming of log and recording files, Gateway does with number-based naming.