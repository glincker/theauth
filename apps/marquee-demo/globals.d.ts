// Let TypeScript accept side-effect imports of plain CSS files. Next.js
// handles the bundling; tsc 6.0 needs this declaration to stop flagging
// `import "./globals.css"` with TS2882.
declare module "*.css";
