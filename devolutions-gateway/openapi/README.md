# OpenAPI libraries

Clients to use the Devolutions Gateway REST API and C# interface to support Gateway subscription.

Code is generated using [OpenAPI Generator](https://openapi-generator.tech/) and OpenAPI documents.

## How-to

1. Make sure that OpenAPI documents are up-to-date by running `../../tools/generate-openapi/generate.ps1`

2. Install `openapi-generator-cli`.

  ```bash
  npm install @openapitools/openapi-generator-cli
  ```

3. Bump versions appropriately in `config.json` files

4. Run `./generate_clients.ps1` script.

Note: script `./generate_all.ps1` will do both 1 and 4 at once.
