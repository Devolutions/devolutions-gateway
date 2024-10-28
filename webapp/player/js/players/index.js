import { handleWebm } from "./webm.js";
import { handleTrp } from "./trp.js";
import { handleCast } from "./cast.js";

export const getPlayer = (fileType) => {
  const player = {
    play: () => {},
  };

  if (fileType === "webm") {
    player.play = handleWebm;
  }

  if (fileType === "trp") {
    player.play = handleTrp;
  }

  if (fileType === "cast") {
    player.play = handleCast;
  }

  return player;
};

export function overrideFetch(objectUrl, content) {
  const originalFetch = window.fetch;
  window.fetch = (url) => {
    if (url === objectUrl) {
      return Promise.resolve(new Response(content));
    }
    return originalFetch(url);
  };
  window.originalFetch = originalFetch; // Save for restoration
}

export function restoreFetch() {
  window.fetch = window.originalFetch;
}

export function createTerminalDiv() {
  const terminalDiv = document.createElement("div");
  terminalDiv.setAttribute("id", "terminal");
  document.body.appendChild(terminalDiv);
  return terminalDiv;
}

export function loadFile(fileName) {
  return fetch(fileName)
    .then((response) => {
      if (!response.ok) {
        throw new Error(`Failed to load file ${fileName}: ${response.statusText}`);
      }
      return response.arrayBuffer();
    })
    .then((arrayBuffer) => new Uint8Array(arrayBuffer));
}
