(function () {
  "use strict";

  (function initTheme() {
    try {
      var saved = localStorage.getItem("fvault-theme");
      if (saved === "dark" || saved === "light") {
        document.documentElement.setAttribute("data-theme", saved);
      }
    } catch (err) {}
    var btn = document.getElementById("theme-toggle");
    if (btn) {
      var current = document.documentElement.getAttribute("data-theme");
      if (!current) current = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
      btn.textContent = current === "dark" ? "Light" : "Dark";
    }
  })();

  var toastTimer = null;

  function toast(message) {
    var el = document.getElementById("toast");
    if (!el) return;
    el.textContent = message;
    el.hidden = false;
    requestAnimationFrame(function () {
      el.classList.add("show");
    });
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      el.classList.remove("show");
      setTimeout(function () {
        el.hidden = true;
      }, 200);
    }, 2200);
  }

  function fetchValue(folder, name, field, csrf) {
    var body = new URLSearchParams();
    body.set("folder", folder);
    body.set("name", name);
    body.set("field", field);
    body.set("csrf", csrf);
    return fetch("/entry/value", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "X-CSRF-Token": csrf
      },
      body: body.toString()
    }).then(function (response) {
      if (response.status === 401) {
        window.location.href = "/login";
        throw new Error("Session expired");
      }
      if (!response.ok) throw new Error("Request failed");
      return response.json();
    });
  }

  function fallbackCopy(text) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (err) {
      ok = false;
    }
    document.body.removeChild(area);
    return ok;
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () {
        return true;
      }).catch(function () {
        return fallbackCopy(text);
      });
    }
    return Promise.resolve(fallbackCopy(text));
  }

  function scheduleClear() {
    setTimeout(function () {
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText("").catch(function () {});
      }
    }, 30000);
  }

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-copy]");
    if (!button) return;
    event.preventDefault();
    var field = button.getAttribute("data-copy") || "password";
    var folder = button.getAttribute("data-folder");
    var name = button.getAttribute("data-name");
    var csrf = button.getAttribute("data-csrf");
    button.disabled = true;
    fetchValue(folder, name, field, csrf)
      .then(function (data) {
        if (!data.value) {
          toast("Nothing to copy");
          return;
        }
        return copyText(data.value).then(function (ok) {
          if (ok) {
            toast("Copied " + field + " (clears in 30s)");
            scheduleClear();
          } else {
            toast("Could not access the clipboard");
          }
        });
      })
      .catch(function (err) {
        if (err && err.message !== "Session expired") {
          toast("Could not copy: " + err.message);
        }
      })
      .finally(function () {
        button.disabled = false;
      });
  });

  var revealButton = document.getElementById("reveal-button");
  var passwordValue = document.getElementById("password-value");
  if (revealButton && passwordValue) {
    revealButton.addEventListener("click", function () {
      var revealed = passwordValue.getAttribute("data-revealed") === "1";
      if (revealed) {
        passwordValue.textContent = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
        passwordValue.setAttribute("data-revealed", "0");
        revealButton.textContent = "Reveal";
        return;
      }
      revealButton.disabled = true;
      fetchValue(
        passwordValue.getAttribute("data-folder"),
        passwordValue.getAttribute("data-name"),
        "password",
        passwordValue.getAttribute("data-csrf")
      )
        .then(function (data) {
          passwordValue.textContent = data.value;
          passwordValue.setAttribute("data-revealed", "1");
          revealButton.textContent = "Hide";
        })
        .catch(function (err) {
          if (err && err.message !== "Session expired") {
            toast("Could not reveal: " + err.message);
          }
        })
        .finally(function () {
          revealButton.disabled = false;
        });
    });
  }

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form || !form.hasAttribute("data-confirm")) return;
    if (!window.confirm(form.getAttribute("data-confirm"))) {
      event.preventDefault();
    }
  });

  var themeButton = document.getElementById("theme-toggle");
  if (themeButton) {
    themeButton.addEventListener("click", function () {
      var current = document.documentElement.getAttribute("data-theme");
      if (!current) {
        current = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
      }
      var next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("fvault-theme", next); } catch (err) {}
      themeButton.textContent = next === "dark" ? "Light" : "Dark";
    });
  }

  document.addEventListener("keydown", function (event) {
    if (event.defaultPrevented) return;
    var target = event.target;
    if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)) return;
    if (event.key === "/") {
      var search = document.querySelector('input[type="search"]');
      if (search) { event.preventDefault(); search.focus(); }
    } else if (event.key === "n" || event.key === "N") {
      var link = document.querySelector('a[href^="/entry/new"]');
      if (link) { window.location.href = link.getAttribute("href"); }
    }
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/static/sw.js").catch(function () {});
  }

  var searchInput = document.querySelector('input[type="search"][name="q"]');
  if (searchInput && searchInput.form) {
    var searchForm = searchInput.form;
    var searchTimer = null;
    var searchSeq = 0;

    function runLiveSearch() {
      var seq = ++searchSeq;
      var params = new URLSearchParams(new FormData(searchForm));
      var url = searchForm.getAttribute("action") + "?" + params.toString();
      fetch(url, { credentials: "same-origin", headers: { "Accept": "text/html" } })
        .then(function (res) {
          if (!res.ok) throw new Error("status " + res.status);
          return res.text();
        })
        .then(function (html) {
          if (seq !== searchSeq) return;
          var doc = new DOMParser().parseFromString(html, "text/html");
          var newBody = doc.querySelector(".entries tbody");
          var oldBody = document.querySelector(".entries tbody");
          if (!newBody || !oldBody) {
            window.location.href = url;
            return;
          }
          oldBody.innerHTML = newBody.innerHTML;
          var newCount = doc.querySelector(".content-head p.muted");
          var oldCount = document.querySelector(".content-head p.muted");
          if (newCount && oldCount) oldCount.innerHTML = newCount.innerHTML;
          try { history.replaceState(null, "", url); } catch (e) {}
        })
        .catch(function () {});
    }

    searchInput.addEventListener("input", function () {
      if (searchTimer) clearTimeout(searchTimer);
      searchTimer = setTimeout(runLiveSearch, 300);
    });
    searchForm.addEventListener("submit", function (event) {
      event.preventDefault();
      runLiveSearch();
    });
  }


  document.querySelectorAll(".password-toggle").forEach(function (button) {
    var input = document.getElementById(button.getAttribute("data-target"));
    if (!input) return;
    var openIcon = button.querySelector(".eye-open");
    var closedIcon = button.querySelector(".eye-closed");
    function sync() {
      var visible = input.type === "text";
      if (openIcon) openIcon.hidden = visible;
      if (closedIcon) closedIcon.hidden = !visible;
      button.setAttribute("aria-pressed", visible ? "true" : "false");
      button.setAttribute("aria-label", visible ? "Hide password" : "Show password");
    }
    sync();
    button.addEventListener("click", function () {
      input.type = input.type === "text" ? "password" : "text";
      sync();
    });
    if (input.form) {
      input.form.addEventListener("submit", function () {
        input.type = "password";
        sync();
      });
    }
  });

  (function passwordGenerator() {
    var button = document.getElementById("generate-password");
    if (!button) return;
    var input = document.getElementById("entry-password");
    var symbolsBox = document.getElementById("gen-symbols");
    var lengthInput = document.getElementById("gen-length");
    var status = document.getElementById("gen-status");
    if (!input) return;

    var LOWER = "abcdefghijkmnopqrstuvwxyz"; // no l
    var UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I, O
    var DIGITS = "23456789";                 // no 0, 1
    var SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?";

    function randomBelow(n) {
      if (n <= 1) return 0;
      var limit = Math.floor(4294967296 / n) * n;
      var buf = new Uint32Array(1);
      for (;;) {
        crypto.getRandomValues(buf);
        if (buf[0] < limit) return buf[0] % n;
      }
    }

    function randomFrom(charset) {
      return charset.charAt(randomBelow(charset.length));
    }

    function generate() {
      var length = parseInt(lengthInput && lengthInput.value, 10);
      if (!length || isNaN(length)) length = 20;
      if (length < 6) length = 6;
      if (length > 128) length = 128;
      if (lengthInput && parseInt(lengthInput.value, 10) !== length) lengthInput.value = length;

      var groups = [LOWER, UPPER, DIGITS];
      if (symbolsBox && symbolsBox.checked) groups.push(SYMBOLS);
      var all = groups.join("");

      var chars = [];
      groups.forEach(function (group) { chars.push(randomFrom(group)); });
      while (chars.length < length) chars.push(randomFrom(all));
      // Fisher-Yates shuffle with the same crypto source.
      for (var i = chars.length - 1; i > 0; i--) {
        var j = randomBelow(i + 1);
        var tmp = chars[i]; chars[i] = chars[j]; chars[j] = tmp;
      }
      return chars.slice(0, length).join("");
    }

    button.addEventListener("click", function () {
      var pw = generate();
      input.value = pw;
      input.dispatchEvent(new Event("input", { bubbles: true }));
      if (status) status.textContent = "Generated " + pw.length + " characters.";
    });
  })();


  (function folderContextMenu() {
    var menu = document.getElementById("folder-menu");
    var sidebar = document.querySelector(".sidebar[data-csrf]");
    if (!menu || !sidebar) return;
    var csrf = sidebar.getAttribute("data-csrf") || "";
    var current = null;

    function hideMenu() {
      menu.hidden = true;
      current = null;
    }

    function showMenu(x, y, li) {
      current = li;
      var locked = li.getAttribute("data-locked") === "1";
      menu.querySelectorAll("button[data-action]").forEach(function (btn) {
        var action = btn.getAttribute("data-action");
        btn.hidden = locked && (action === "rename" || action === "delete");
      });
      menu.hidden = false;
      var maxX = window.innerWidth - menu.offsetWidth - 8;
      var maxY = window.innerHeight - menu.offsetHeight - 8;
      menu.style.left = Math.max(4, Math.min(x, maxX)) + "px";
      menu.style.top = Math.max(4, Math.min(y, maxY)) + "px";
    }

    function postForm(url, fields) {
      var body = new URLSearchParams();
      Object.keys(fields).forEach(function (k) { body.set(k, fields[k]); });
      body.set("csrf", csrf);
      fetch(url, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8", "X-CSRF-Token": csrf },
        body: body.toString()
      }).then(function (r) {
        if (r.status === 403) { toast("Invalid CSRF token - please refresh the page."); return; }
        if (r.status >= 400) { toast("Request failed (" + r.status + ")."); return; }
        if (r.url.indexOf(window.location.origin) === 0) { window.location.href = r.url; }
      }).catch(function () { toast("Network error."); });
    }

    document.addEventListener("contextmenu", function (event) {
      var li = event.target && event.target.closest ? event.target.closest("li.folder-item") : null;
      if (!li) return;
      event.preventDefault();
      showMenu(event.clientX, event.clientY, li);
    });

    function outsideMenu(event) {
      if (menu.hidden) return false;
      if (event.target && event.target.closest && event.target.closest("#folder-menu")) return false;
      hideMenu();
      return true;
    }

    document.addEventListener("click", outsideMenu);
    document.addEventListener("mousedown", outsideMenu);
    document.addEventListener("contextmenu", function (event) {
      var onFolder = event.target && event.target.closest && event.target.closest("li.folder-item");
      if (!onFolder && !menu.hidden) hideMenu();
    });
    window.addEventListener("scroll", hideMenu, true);
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") hideMenu();
    });
    window.addEventListener("blur", hideMenu);

    menu.addEventListener("click", function (event) {
      var btn = event.target && event.target.closest ? event.target.closest("button[data-action]") : null;
      if (!btn || !current) return;
      var folder = current.getAttribute("data-folder");
      var action = btn.getAttribute("data-action");
      hideMenu();
      if (action === "open") {
        window.location.href = "/vault?folder=" + encodeURIComponent(folder);
      } else if (action === "new-entry") {
        window.location.href = "/entry/new?folder=" + encodeURIComponent(folder);
      } else if (action === "rename") {
        var next = window.prompt("Rename folder '" + folder + "' to:", folder);
        if (next === null) return;
        next = next.trim();
        if (!next || next === folder) return;
        postForm("/folder/rename", { "old": folder, "name": next });
      } else if (action === "delete") {
        if (!window.confirm("Delete folder '" + folder + "' and ALL of its entries? This cannot be undone.")) return;
        postForm("/folder/delete", { "name": folder, "force": "1" });
      }
    });
  })();

})();
