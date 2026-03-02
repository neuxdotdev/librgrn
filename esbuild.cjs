const esbuild = require('esbuild');

esbuild.build({
  entryPoints: ['./src/lib.ts'],  // entry point TS
  bundle: true,                     // gabung semua dependency
  platform: 'node',                 // buat Node.js
  outfile: './build/bundle.js',     // hasil di ./build
  minify: false,                    // bisa true kalau mau kecilin
}).catch(() => process.exit(1));