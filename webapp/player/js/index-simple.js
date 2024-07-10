import { convertTRPtoCast } from "./trp-decoder.js";

document.addEventListener("DOMContentLoaded", async function () {
  const trpSrc = 'recording-simple.trp'
  const byteArray = await loadFile(trpSrc);
  const castFileContent = convertTRPtoCast(byteArray);
  const url = "data:text/plain;base64," + btoa(castFileContent);

  const terminalDiv = document.getElementById('terminal');

  const playerOptions = {
    'fontSize': 12
  }
  const player = new XtermPlayer.XtermPlayer(url, terminalDiv, playerOptions);

  setTimeout(function () {
    player.play();
  }, 500);
});


function loadFile(fileName) {
  return new Promise((resolve, reject) => {
    const req = new XMLHttpRequest();
    req.open("GET", fileName, true);
    req.responseType = "arraybuffer";
    req.onload = () => {
      const arrayBuffer = req.response;
      if (arrayBuffer) {
        const byteArray = new Uint8Array(arrayBuffer);
        resolve(byteArray);
      } else {
        reject('No data received');
      }
    };
    req.onerror = () => reject('Request failed');
    req.send(null);
  });
}
