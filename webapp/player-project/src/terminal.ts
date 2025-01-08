// ascinema-player does not have typescript support, so we need to disable typescript checking for this file
// track issue: https://github.com/asciinema/asciinema-player/issues/187
// @ts-ignore
import * as AsciinemaPlayer from 'asciinema-player';

export function createTerminal(src) {
  const element = createTerminalDiv();
  return AsciinemaPlayer.create(src, element, {
    fit: false,
    fontSize: 'big',
    logger: console,
  });
}

export function createTerminalDiv() {
  const terminalDiv = document.createElement('div');
  terminalDiv.setAttribute('id', 'terminal');
  document.body.appendChild(terminalDiv);
  return terminalDiv;
}

export function removeTerminal() {
  const terminalDiv = document.getElementById('terminal');
  if (terminalDiv) {
    terminalDiv.remove();
  }
}
