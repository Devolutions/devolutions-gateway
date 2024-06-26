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

      videoPlayer.appendChild(videoSrcElement);
      document.body.appendChild(videoPlayer);

      // initialize the video player
      let videoSrc = `${gatewayAccessUrl}/jet/jrec/pull/${sessionId}/${recordingInfo.files[0].fileName}?token=${token}`;
      videoSrcElement.setAttribute("src", videoSrc);

      // set up video cycling
      var currentIndex = 0;
      var maxIndex = recordingInfo.files.length - 1;

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
      var terminalDiv = document.createElement("div");
      document.body.appendChild(terminalDiv);

      let trpSrc = `${gatewayAccessUrl}/jet/jrec/pull/${sessionId}/${recordingInfo.files[0].fileName}?token=${token}`;

      loadFile(trpSrc, function (trpFileContent) {
        var castFileContent = convertTRPtoCast(trpFileContent);

        // make the file a base64 embedded src url
        var url = "data:text/plain;base64," + btoa(castFileContent);
        var player = new XtermPlayer.XtermPlayer(url, terminalDiv);

        // need a slight delay to play waiting for it to load
        setTimeout(function () {
          player.play();
        }, 500);
      });

      break;
    case "cast":
      // create the Div
      var terminalDiv = document.createElement("div");
      document.body.appendChild(terminalDiv);
      let castSrc = `${gatewayAccessUrl}/jet/jrec/pull/${sessionId}/${recordingInfo.files[0].fileName}?token=${token}`;
      const player = new XtermPlayer.XtermPlayer(castSrc, terminalDiv , {
        fontSize: 12
      });
      player.play();

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
