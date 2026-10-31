/** Dev-only. Rebuild web/assets/tailwind.css with: ./tailwindcss -c tailwind.config.js -i web/src/input.css -o web/assets/tailwind.css --minify */
module.exports = {
  content: ["./web/*.html", "./web/assets/app.js"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: ["ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
    },
  },
};
