import { defineConfig } from 'vite';

export default defineConfig({
  root: 'web',
  server: {
    port: 5180,
    proxy: {
      '/api': 'http://localhost:3020',
    },
  },
  build: {
    outDir: '../web-dist',
    emptyOutDir: true,
  },
});
