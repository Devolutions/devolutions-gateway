import * as AsciinemaPlayer from 'asciinema-player';

export function createTerminal(src) {
  const element = createTerminalDiv();
  return AsciinemaPlayer.create(src, element, {
    fit: false,
    fontSize: 'big',
  });
}

export function createTerminalDiv() {
  const terminalDiv = document.createElement('div');
  terminalDiv.setAttribute('id', 'terminal');
  document.body.appendChild(terminalDiv);
  return terminalDiv;
}
