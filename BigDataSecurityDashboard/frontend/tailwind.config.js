/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        darkBg: "#05070C",
        cardBg: "#0C111D",
        cardBorder: "#1F2A37",
        cyberGreen: "#00FF66",
        cyberRed: "#FF3366",
        cyberBlue: "#33CCFF",
        cyberYellow: "#FFCC00",
      },
      boxShadow: {
        glowGreen: "0 0 15px rgba(0, 255, 102, 0.15)",
        glowRed: "0 0 15px rgba(255, 51, 102, 0.15)",
        glowBlue: "0 0 15px rgba(51, 204, 255, 0.15)",
        glowYellow: "0 0 15px rgba(255, 204, 0, 0.15)",
      }
    },
  },
  plugins: [],
}
