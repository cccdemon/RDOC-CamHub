// camhub.js — UI-M0 client glue.
//
// Three jobs:
//   1. Login form submit (fetch to {api-base}/v1/auth/login, redirect on 200).
//   2. Silent refresh ticker (every 10 min while tab visible).
//   3. /v1/auth/me bootstrap + logout link wiring on the dashboard.
//
// htmx is NOT loaded in UI-M0; it arrives with UI-M1's polling partials.

(function () {
  "use strict";

  function meta(name) {
    var el = document.querySelector('meta[name="' + name + '"]');
    return el ? el.getAttribute("content") || "" : "";
  }

  // Same-origin when api-base is empty. Strip trailing slash so we can
  // concatenate paths cleanly.
  var API_BASE = (meta("api-base") || "").replace(/\/+$/, "");
  function apiURL(path) {
    return API_BASE + path;
  }

  // Read the non-HttpOnly camhub_csrf cookie. Empty when not signed in
  // or before the first login response.
  function csrfFromCookie() {
    var match = document.cookie.match(/(?:^|;\s*)camhub_csrf=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  // ---------- Login form ------------------------------------------------

  var form = document.getElementById("login-form");
  if (form) {
    var errBox = document.getElementById("login-err");
    var submit = document.getElementById("login-submit");

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      errBox.classList.remove("show");
      errBox.textContent = "";
      submit.disabled = true;

      var email = document.getElementById("email").value.trim();
      var password = document.getElementById("password").value;

      fetch(apiURL("/v1/auth/login"), {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email, password: password }),
      })
        .then(function (res) {
          if (res.ok) {
            window.location.replace("/");
            return null;
          }
          return res.json().catch(function () { return {}; }).then(function (body) {
            var msg = body && body.message
              ? body.message
              : (res.status === 401 ? "Invalid credentials" : "Sign-in failed");
            errBox.textContent = msg;
            errBox.classList.add("show");
            submit.disabled = false;
          });
        })
        .catch(function () {
          errBox.textContent = "Network error";
          errBox.classList.add("show");
          submit.disabled = false;
        });
    });
  }

  // ---------- Logout link -----------------------------------------------

  document.querySelectorAll('[data-action="logout"]').forEach(function (a) {
    a.addEventListener("click", function (ev) {
      ev.preventDefault();
      fetch(apiURL("/v1/auth/logout"), {
        method: "POST",
        credentials: "include",
      }).finally(function () {
        window.location.replace("/login");
      });
    });
  });

  // ---------- Silent refresh ticker ------------------------------------

  // Run every 10 min while the tab is visible. The cookie's lifetime is
  // SessionAccessTTL (15 min, PR-S5); 10 min gives us five minutes of
  // headroom before the access window closes.
  var REFRESH_EVERY_MS = 10 * 60 * 1000;
  var refreshTimer = null;
  var refreshState = document.getElementById("refresh-state");

  function setRefreshState(s) {
    if (refreshState) refreshState.textContent = s;
  }

  function doRefresh() {
    setRefreshState("refreshing…");
    return fetch(apiURL("/v1/auth/refresh"), {
      method: "POST",
      credentials: "include",
    })
      .then(function (res) {
        if (res.status === 204) {
          setRefreshState("ok · " + new Date().toLocaleTimeString());
          return;
        }
        if (res.status === 401) {
          // Cookie no longer valid (rotated, deleted, beyond refresh
          // window). Hard-redirect to /login.
          window.location.replace("/login");
          return;
        }
        setRefreshState("error · " + res.status);
      })
      .catch(function () {
        setRefreshState("network error");
      });
  }

  function startTicker() {
    if (refreshTimer) return;
    refreshTimer = setInterval(doRefresh, REFRESH_EVERY_MS);
  }
  function stopTicker() {
    if (!refreshTimer) return;
    clearInterval(refreshTimer);
    refreshTimer = null;
  }

  // Only run the ticker on pages with a session cookie. The login page
  // has no session, so there's nothing to refresh.
  if (csrfFromCookie() || document.getElementById("me-state")) {
    startTicker();
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        stopTicker();
      } else {
        startTicker();
      }
    });
  }

  // ---------- /me bootstrap (dashboard stub) ---------------------------

  var meEl = document.getElementById("me-state");
  if (meEl) {
    fetch(apiURL("/v1/auth/me"), {
      method: "GET",
      credentials: "include",
      headers: { "X-CSRF-Token": csrfFromCookie() },
    })
      .then(function (res) {
        if (res.status === 401) {
          window.location.replace("/login");
          return null;
        }
        return res.ok ? res.json() : null;
      })
      .then(function (body) {
        if (!body) return;
        meEl.textContent = body.email + " (" + body.role + ")";
      })
      .catch(function () {
        meEl.textContent = "network error";
      });
  }
})();
