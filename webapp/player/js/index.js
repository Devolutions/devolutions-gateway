import { convertTRPtoCast } from "./trp-decoder.js";

const windowURL = new URL(window.location.href);
var sessionId = windowURL.searchParams.get("sessionId");
var token = windowURL.searchParams.get("token");
const gatewayAccessUrl = windowURL.toString().split("/jet/jrec")[0];
var videoSrcInfo = `${gatewayAccessUrl}/jet/jrec/pull/${sessionId}/recording.json?token=${token}`;
var request = new XMLHttpRequest();

request.onreadystatechange = function () {
  if (request.readyState !== XMLHttpRequest.DONE) {
    return false;
  }

  if (request.status !== 200) {
    console.error("Request failed. Returned status of " + request.status);
    return false;
  }

  var recordingInfo = JSON.parse(request.responseText);
  var fileType = recordingInfo.files[0].fileName.split(".")[1];

  var terminalDiv = document.createElement("div");
  terminalDiv.setAttribute("id", "terminal");

  switch (fileType) {
    case "webm":
      // create the video object
      var videoPlayer = document.createElement("video");
      videoPlayer.id = "videoPlayer";
      videoPlayer.controls = true;
      videoPlayer.autoplay = true;
      videoPlayer.name = "media";

      var videoSrcElement = document.createElement("source");
      videoSrcElement.id = "videoSrcElement";
      videoSrcElement.type = "video/webm";
      videoPlayer.muted = true;

      videoPlayer.appendChild(videoSrcElement);
      document.body.appendChild(videoPlayer);

      // initialize the video player
      let videoSrc = `${gatewayAccessUrl}/jet/jrec/pull/${sessionId}/${recordingInfo.files[0].fileName}?token=${token}`;
      videoSrcElement.setAttribute("src", videoSrc);

      // set up video cycling
      var currentIndex = 0;
      var maxIndex = recordingInfo.files.length - 1;

      videoPlayer.play();

      videoPlayer.onended = function () {
        currentIndex++;
        if (currentIndex > maxIndex) {
          currentIndex = 0;
        }
        videoSrc = `${gatewayAccessUrl}/jet/jrec/pull/${sessionId}/${recordingInfo.files[currentIndex].fileName}?token=${token}`;
        videoSrcElement.setAttribute("src", videoSrc);
        videoPlayer.load();
        videoPlayer.play();
      };

      break;

    case "trp":
      // create the Div
      document.body.appendChild(terminalDiv);

      let trpSrc = `${gatewayAccessUrl}/jet/jrec/pull/${sessionId}/${recordingInfo.files[0].fileName}?token=${token}`;

      loadFile(trpSrc, (trpFileContent) => {
        const castFileContent = convertTRPtoCast(trpFileContent);
        const objectUrl = URL.createObjectURL(
          new Blob([castFileContent], { type: "text/plain" })
        );
        const originalFetch = window.fetch;
        // HACK: override fetch to return the cast file content, we should definately update the XtermPlayer to avoid this
        window.fetch = (url, options) => {
          if (url === objectUrl) {
            return Promise.resolve({
              text: () => {
                return Promise.resolve(castFileContent);
              },
            });
          }
          return originalFetch(url, options);
        };
        const player = new XtermPlayer.XtermPlayer(objectUrl, terminalDiv);
        window.fetch = originalFetch;

        // need a slight delay to play waiting for it to load
        setTimeout(() => {
          player.play();
        }, 500);
      });

      break;
    case "cast":
      // create the Div
      document.body.appendChild(terminalDiv);
      let castSrc = `${gatewayAccessUrl}/jet/jrec/pull/${sessionId}/${recordingInfo.files[0].fileName}?token=${token}`;
      const player = new XtermPlayer.XtermPlayer(castSrc, terminalDiv, {
        fontSize: 12,
      });
      setTimeout(() => {
        player.play();
      }, 500);

      break;
  }
};

request.open("GET", videoSrcInfo, true);
request.send();

function loadFile(fileName, onLoad) {
  const req = new XMLHttpRequest();
  req.open("GET", fileName, true);
  req.responseType = "arraybuffer";
  req.onload = (event) => {
    const arrayBuffer = req.response;
    if (arrayBuffer) {
      const byteArray = new Uint8Array(arrayBuffer);
      onLoad(byteArray);
    }
  };
  req.send(null);
}
