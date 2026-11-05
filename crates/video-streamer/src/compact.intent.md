<a id="compaction"></a>
# Compaction
Compaction re-encodes a finished WebM recording, keeping only the frames whose picture changed.
*Avoid:* dedup, deduplication.

<a id="changed-frame"></a>
# Changed frame
A frame is kept when any 8×8 block of its luma differs from the last kept frame by a mean absolute difference of more than 12.
The first and the last frame are always kept, so the recording keeps its duration.

<a id="encoding"></a>
# Encoding
The kept frames are encoded as VP8 with a fixed quantizer of 30, whatever the codec of the recording, and the bitrate target is high enough that it never limits the encoder.
A bitrate target taken from the recording is rejected because it spends bytes above that quality wherever the picture moves: on 8 lab recordings it stored 84.8 MB where the fixed quantizer stored 68.0 MB, for about the same CPU time and with no visible change lost.
VP9 output is rejected because it saved another 6.6 MB at a fixed quantizer of 25 for about three times the CPU time, which a 2-vCPU Gateway cannot spare beside its live sessions.
