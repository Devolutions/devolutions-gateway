import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { UAParser } from 'ua-parser-js';
import { AppModule } from './app/app.module';

// The minimum required browser versions were determined by manual testing.
const CHROME_MINIMUM_REQUIRED_VERSION = [102];
const FIREFOX_MINIMUM_REQUIRED_VERSION = [102];
const SAFARI_MINIMUM_REQUIRED_VERSION = [16, 4];

function isVersionsGreaterOrEqual(v1: number[], v2: number[]): boolean {
  const len = Math.max(v1.length, v2.length);

  for (let i = 0; i < len; i++) {
    const num1 = v1[i] || 0;
    const num2 = v2[i] || 0;

    if (num1 > num2) return true;
    if (num1 < num2) return false;
  }

  // Versions are equal.
  return true;
}

function isBrowserCompatible(): boolean {
  const browser = new UAParser().getBrowser();
  const browserName = browser.name.toLowerCase();
  const browserVersion = browser.version.split('.').map(Number);

  if (browserName === 'chrome') {
    return isVersionsGreaterOrEqual(browserVersion, CHROME_MINIMUM_REQUIRED_VERSION);
  }

  if (browserName === 'firefox') {
    return isVersionsGreaterOrEqual(browserVersion, FIREFOX_MINIMUM_REQUIRED_VERSION);
  }

  if (browserName === 'safari') {
    return isVersionsGreaterOrEqual(browserVersion, SAFARI_MINIMUM_REQUIRED_VERSION);
  }

  // We cannot say whether the untested browsers support our web application, so we will simply return true.
  return true;
}

if (isBrowserCompatible()) {
  platformBrowserDynamic()
    .bootstrapModule(AppModule)
    .catch((err) => console.error(err));
} else {
  document.body.innerHTML = `
    <div id="fallback">
        <h1>Unsupported browser!</h1>
        <p>Devolutions Gateway Standalone is not supported on this browser version. Please update it to the latest one.</p>
    </div>
`;
}
