import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { AppModule } from '@gateway/app.module';

// Check for essential modern browser features required by Angular 20
function isBrowserCompatible(): boolean {
  try {
    // Check for ES2022 features (required by Angular 20)
    return !!(globalThis && Promise.allSettled && String.prototype.replaceAll && Array.prototype.at && Object.hasOwn);
  } catch {
    return false;
  }
}

if (isBrowserCompatible()) {
  platformBrowserDynamic()
    .bootstrapModule(AppModule)
    .catch((err) => console.error(err));
} else {
  document.body.innerHTML = `
    <div style="
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100vh;
      font-family: system-ui, -apple-system, sans-serif;
      text-align: center;
      padding: 20px;
    ">
      <h1 style="color: #d32f2f; margin-bottom: 16px;">Unsupported Browser</h1>
      <p style="color: #666; max-width: 500px; line-height: 1.5;">
        Devolutions Gateway requires a modern browser to run properly.
        Please update your browser to the latest version or use Chrome, Firefox, Safari, or Edge.
      </p>
    </div>
  `;
}
