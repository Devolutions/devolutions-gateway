import { Dom } from '../util';
/**
 * @jest-environment jsdom
 */

describe('createElement function', () => {
  const { createEl: createElement } = Dom;
  test('should create an element with the given tag name', () => {
    const div = createElement('div');
    expect(div.tagName).toBe('DIV');
  });

  test('should apply properties correctly', () => {
    const button = createElement('button', {
      id: 'myButton',
      className: 'btn btn-primary',
      disabled: true,
      innerText: 'Click Me',
    });

    expect(button.id).toBe('myButton');
    expect(button.className).toBe('btn btn-primary');
    expect(button.disabled).toBe(true);
    expect(button.innerText).toBe('Click Me');
  });

  test('should apply attributes correctly', () => {
    const input = createElement(
      'input',
      {},
      {
        type: 'text',
        placeholder: 'Enter text',
        'data-test': 'input-field',
      },
    );

    expect(input.getAttribute('type')).toBe('text');
    expect(input.getAttribute('placeholder')).toBe('Enter text');
    expect(input.getAttribute('data-test')).toBe('input-field');
  });

  test('should set styles correctly', () => {
    const div = createElement('div', {
      style: {
        color: 'red',
        backgroundColor: 'blue',
        fontSize: '16px',
      },
    });

    expect(div.style.color).toBe('red');
    expect(div.style.backgroundColor).toBe('blue');
    expect(div.style.fontSize).toBe('16px');
  });

  test('should append text content correctly', () => {
    const p = createElement('p', {}, {}, 'Hello World');
    expect(p.textContent).toBe('Hello World');
  });

  test('should append an HTMLElement as content', () => {
    const span = createElement('span', {}, {}, 'Nested span');
    const div = createElement('div', {}, {}, span);

    expect(div.children.length).toBe(1);
    expect(div.children[0].tagName).toBe('SPAN');
    expect(div.children[0].textContent).toBe('Nested span');
  });

  test('should append an array of elements and text as content', () => {
    const span1 = createElement('span', {}, {}, 'Span 1');
    const span2 = createElement('span', {}, {}, 'Span 2');
    const div = createElement('div', {}, {}, ['Text before', span1, 'Middle text', span2, 'Text after']);

    expect(div.childNodes.length).toBe(5);
    expect(div.childNodes[0].textContent).toBe('Text before');
    expect(div.childNodes[1].nodeName).toBe('SPAN');
    expect(div.childNodes[1].textContent).toBe('Span 1');
    expect(div.childNodes[2].textContent).toBe('Middle text');
    expect(div.childNodes[3].nodeName).toBe('SPAN');
    expect(div.childNodes[3].textContent).toBe('Span 2');
    expect(div.childNodes[4].textContent).toBe('Text after');
  });
});
