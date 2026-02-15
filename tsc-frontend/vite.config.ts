import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    headers: {
      // Required for SharedArrayBuffer (used by some WebGPU paths)
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
  // Allow BigInt literals in built output
  build: {
    target: 'es2022',
  },
  optimizeDeps: {
    // webgpu-phase2 uses BigInt extensively; ensure esbuild handles it
    esbuildOptions: {
      target: 'es2022',
    },
  },
})
