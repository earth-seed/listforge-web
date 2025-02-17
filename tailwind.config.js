module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx}',
    './components/**/*.{js,ts,jsx,tsx}',
    './*.html'
  ],
  darkMode: 'class', // or 'media'
  theme: {
    extend: {
      colors: {
        black: '#000000',
      },
    },
  },
  plugins: [],
} 