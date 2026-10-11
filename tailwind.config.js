/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#080d1a',
          surface: '#0f172a',
          card: '#131e36',
          border: '#1e293b',
          borderHighlight: '#334155',
          accent: '#06b6d4', // cyan-500
          accentGlow: 'rgba(6, 182, 212, 0.15)',
          safe: '#10b981', // emerald-500
          warning: '#f59e0b', // amber-500
          danger: '#ef4444', // red-500
          textMuted: '#94a3b8',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Menlo', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
