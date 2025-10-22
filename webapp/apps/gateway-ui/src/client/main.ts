import { platformBrowserDynamic } from '@angular/platform-browser-dynamic';
import { AppModule } from '@gateway/app.module';

platformBrowserDynamic()
  .bootstrapModule(AppModule)
  .catch((err) => console.error(err));
