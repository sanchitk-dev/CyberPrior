document.addEventListener("DOMContentLoaded", () => {
  const themeButton = document.querySelector("#theme-toggle");
  if (themeButton) {
    const page = document.body;
    const applyTheme = (theme) => {
      const light = theme === "light";
      page.classList.add("theme-switching");
      page.dataset.theme = light ? "light" : "dark";
      if (page.classList.contains("dashboard-page")) page.dataset.dashboardTheme = page.dataset.theme;
      themeButton.querySelector("span:last-child").textContent = light ? "Use dark mode" : "Use light mode";
      themeButton.setAttribute("aria-label", light ? "Use dark mode" : "Use light mode");
      const themeColor = document.querySelector('meta[name="theme-color"]');
      if (themeColor) themeColor.content = light ? "#f1f5f9" : "#0a111d";
      try { localStorage.setItem("cyberprior-theme", page.dataset.theme); } catch (_) {}
      requestAnimationFrame(() => requestAnimationFrame(() => page.classList.remove("theme-switching")));
    };
    try { applyTheme(localStorage.getItem("cyberprior-theme") || "light"); } catch (_) { applyTheme("light"); }
    themeButton.addEventListener("click", () => applyTheme(page.dataset.theme === "light" ? "dark" : "light"));
  }

  const riskFilters = document.querySelectorAll("[data-risk-filter]");
  const exampleRows = document.querySelectorAll(".dashboard-priority-panel tbody tr[data-risk-level]");
  const filterStatus = document.querySelector("#example-filter-status");
  riskFilters.forEach((button) => button.addEventListener("click", () => {
    const filter = button.dataset.riskFilter;
    let visible = 0;
    exampleRows.forEach((row) => {
      const show = filter === "all" || row.dataset.riskLevel === filter;
      row.hidden = !show;
      if (show) visible += 1;
    });
    riskFilters.forEach((item) => {
      const selected = item === button;
      item.classList.toggle("active", selected);
      item.setAttribute("aria-pressed", String(selected));
    });
    if (filterStatus) filterStatus.textContent = filter === "all" ? "Showing all examples" : `Showing ${visible} ${filter} ${visible === 1 ? "example" : "examples"}`;
  }));

  document.querySelectorAll("tr.clickable-row[data-href]").forEach((row) => {
    row.addEventListener("click", (event) => {
      if (event.target.closest("a, button, input, select")) return;
      window.location.href = row.dataset.href;
    });
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && row.dataset.href) window.location.href = row.dataset.href;
    });
    row.setAttribute("tabindex", "0");
    row.setAttribute("role", "link");
    row.setAttribute("aria-label", `Open vulnerability details for ${row.dataset.label || "selected record"}`);
  });

});
