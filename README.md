## RRC-ORG-INVITE

This is a simple slackbot built on Cloudflare Workers to invite users to the ramblinrocketclub Github organization.

When uploading it to Github, a personal access token needs to be generated by someone who is an owner of the organization. Additionally, there are three possible signing secrets that can be added, corresponding to each of the RRC's slack workspaces. All these should be set as environment variables as specified at the top of `index.ts`.

### Deploying

To build:
`npm run build`

To publish
`wrangler publish`

Theoretically, `wrangler build` should be able to transparently call `npm build`, but it doesn't seem to be working. Oh well.

### Typescript

The typescript support isn't actually completely functional. Trying to build with `tsc` results in errors. Building with esbuild works as esbuild simply strips out types instead of doing type checking.

However, due to `"@cloudflare/workers-types"` being defined in `tsconfig.json` and the `bindings.d.ts` file, vscode does actually correctly understand all the types. This means that during development, errors will be surfaced in the problems pain. Not perfect, but better than nothing.