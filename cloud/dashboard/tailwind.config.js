/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eef9ff',
          100: '#d8f1ff',
          200: '#b9e7ff',
          300: '#89d9ff',
          400: '#51c2ff',
          500: '#29a3ff',
          600: '#1183f5',
          700: '#0a6be1',
          800: '#0f56b6',
          900: '#134a8f',
          950: '#112d57',
        },
      },
    },
  },
  plugins: [],
};
