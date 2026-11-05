(function () {
  var theme = null;
  try { theme = localStorage.getItem("fvault-theme"); } catch (e) {}
  if (theme !== "dark" && theme !== "light") {
    theme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", theme);
})();
