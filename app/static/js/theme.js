// Dark mode toggle — persisted in localStorage
(() => {
    const saved = localStorage.getItem("theme");
    if (saved) {
        document.documentElement.setAttribute("data-theme", saved);
    } else if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
        document.documentElement.setAttribute("data-theme", "dark");
    }

    document.addEventListener("DOMContentLoaded", () => {
        const btn = document.getElementById("theme-toggle");
        if (!btn) return;
        const update = () => {
            const isDark = document.documentElement.getAttribute("data-theme") === "dark";
            btn.textContent = isDark ? "\u2600\uFE0F Light" : "\uD83C\uDF19 Dark";
        };
        update();
        btn.addEventListener("click", () => {
            const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
            document.documentElement.setAttribute("data-theme", next);
            localStorage.setItem("theme", next);
            update();
        });
    });
})();
