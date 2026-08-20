// CodeScan UI — dependency-free. Server renders the pages; this adds the
// interactive bits: source tabs, async form submit, live polling, filters.
(function () {
  "use strict";

  // ---- humanize timestamps rendered as unix seconds ----
  document.querySelectorAll("[data-ts]").forEach(function (el) {
    var ts = parseInt(el.getAttribute("data-ts"), 10);
    if (ts > 0) el.textContent = new Date(ts * 1000).toLocaleString();
  });

  // ---- new-scan page: tabs ----
  var tabs = document.querySelectorAll(".tab");
  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      var which = tab.getAttribute("data-tab");
      tabs.forEach(function (t) { t.classList.toggle("active", t === tab); });
      document.querySelectorAll("[data-panel]").forEach(function (p) {
        p.classList.toggle("hidden", p.getAttribute("data-panel") !== which);
      });
    });
  });

  function showError(msg) {
    var box = document.getElementById("form-error");
    if (!box) return;
    box.textContent = msg;
    box.classList.remove("hidden");
  }

  // ---- recent-scans list: delete a scan ----
  document.querySelectorAll("button[data-del]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var id = btn.getAttribute("data-del");
      if (!window.confirm("Delete this scan and its findings? This cannot be undone.")) return;
      btn.disabled = true;
      fetch("/api/scans/" + id, { method: "DELETE" })
        .then(function (res) {
          if (res.ok) {
            var row = document.querySelector('tr[data-row="' + id + '"]');
            if (row) row.remove();
            return;
          }
          return res.json().catch(function () { return {}; }).then(function (data) {
            btn.disabled = false;
            window.alert(data.error || "Could not delete scan (HTTP " + res.status + ").");
          });
        })
        .catch(function () {
          btn.disabled = false;
          window.alert("Could not delete scan — network error.");
        });
    });
  });

  // ---- git form → JSON POST ----
  var gitForm = document.getElementById("git-form");
  if (gitForm) {
    gitForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var fd = new FormData(gitForm);
      var body = { source_type: "git", source_ref: fd.get("source_ref") };
      var token = fd.get("token");
      if (token) body.token = token;
      submitScan({ button: submitBtn(gitForm), body: JSON.stringify(body), contentType: "application/json" });
    });
  }

  // ---- zip form → multipart POST ----
  var zipForm = document.getElementById("zip-form");
  if (zipForm) {
    zipForm.addEventListener("submit", function (e) {
      e.preventDefault();
      submitScan({ button: submitBtn(zipForm), body: new FormData(zipForm), isUpload: true });
    });
  }

  function submitBtn(form) {
    return form.querySelector("button[type=submit]") || form.querySelector("button");
  }

  function hideError() {
    var box = document.getElementById("form-error");
    if (box) box.classList.add("hidden");
  }

  // submitScan POSTs the scan and gives the user feedback the whole time: it
  // disables the button, shows upload progress % for archives (via XHR, which —
  // unlike fetch — exposes upload progress), then redirects to the scan page on
  // success. Without this, a big upload looked like nothing was happening.
  function submitScan(opts) {
    var btn = opts.button;
    var original = btn ? btn.textContent : "";
    if (btn) { btn.disabled = true; btn.textContent = opts.isUpload ? "Uploading… 0%" : "Starting…"; }
    hideError();

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/scans");
    if (opts.contentType) xhr.setRequestHeader("Content-Type", opts.contentType);

    if (opts.isUpload && xhr.upload) {
      xhr.upload.onprogress = function (e) {
        if (!btn || !e.lengthComputable) return;
        var pct = Math.round((e.loaded / e.total) * 100);
        btn.textContent = pct < 100 ? "Uploading… " + pct + "%" : "Processing…";
      };
    }
    xhr.onload = function () {
      var data = {};
      try { data = JSON.parse(xhr.responseText); } catch (err) { /* non-JSON */ }
      if (xhr.status >= 200 && xhr.status < 300 && data.id) {
        window.location.href = "/scans/" + data.id;
        return;
      }
      if (btn) { btn.disabled = false; btn.textContent = original; }
      showError((data && data.error) || ("scan failed to start (HTTP " + xhr.status + ")"));
    };
    xhr.onerror = function () {
      if (btn) { btn.disabled = false; btn.textContent = original; }
      showError("network error — the upload was interrupted, please retry");
    };
    xhr.send(opts.body);
  }

  // ---- detail page: live polling ----
  var jobCard = document.getElementById("job-card");
  if (jobCard) {
    var id = jobCard.getAttribute("data-job-id");
    var status = jobCard.getAttribute("data-status");
    var running = status === "queued" || status === "fetching" || status === "scanning";

    var cancelBtn = document.getElementById("cancel-btn");
    if (cancelBtn) {
      cancelBtn.addEventListener("click", function () {
        cancelBtn.disabled = true;
        fetch("/api/scans/" + id + "/cancel", { method: "POST" });
      });
    }

    if (running) pollJob(id);
    wireFilters();
  }

  function pollJob(id) {
    var timer = setInterval(function () {
      fetch("/api/scans/" + id)
        .then(function (r) { return r.json(); })
        .then(function (job) {
          var badge = document.getElementById("job-status");
          if (badge) { badge.textContent = job.status; badge.className = "badge s-" + job.status; }
          var prog = document.getElementById("job-progress");
          if (prog) prog.textContent = job.progress || "";
          var terminal = job.status === "done" || job.status === "failed" || job.status === "canceled";
          if (terminal) {
            clearInterval(timer);
            // Reload once so findings + summary render server-side (simplest, correct).
            window.location.reload();
          }
        })
        .catch(function () { /* transient; keep polling */ });
    }, 1500);
  }

  function wireFilters() {
    var sevLinks = document.querySelectorAll("#filters a[data-filter]");
    var directBtn = document.getElementById("direct-only");
    var hideUnusedBtn = document.getElementById("hide-unused");
    var rows = document.querySelectorAll("#findings-card tr[data-sev]");
    var tiers = document.querySelectorAll("#findings-card .tier");
    var sev = "";          // "" = all severities
    var directOnly = false;
    var hideUnused = false;

    function apply() {
      rows.forEach(function (row) {
        var okSev = sev === "" || row.getAttribute("data-sev") === sev;
        var okDep = !directOnly || row.getAttribute("data-rel") === "direct";
        var okUse = !hideUnused || row.getAttribute("data-usage") !== "unused_suspected";
        row.classList.toggle("hidden", !(okSev && okDep && okUse));
      });
      // Collapse a whole tier when the active filter leaves it with no rows.
      tiers.forEach(function (t) {
        var visible = t.querySelectorAll("tr[data-sev]:not(.hidden)").length;
        t.classList.toggle("hidden", visible === 0);
      });
    }

    sevLinks.forEach(function (a) {
      a.addEventListener("click", function (e) {
        e.preventDefault();
        sev = a.getAttribute("data-filter");
        sevLinks.forEach(function (l) { l.classList.toggle("active", l === a); });
        apply();
      });
    });

    function toggle(btn, set) {
      if (!btn) return;
      btn.addEventListener("click", function (e) {
        e.preventDefault();
        btn.classList.toggle("active");
        set(btn.classList.contains("active"));
        apply();
      });
    }
    toggle(directBtn, function (v) { directOnly = v; });
    toggle(hideUnusedBtn, function (v) { hideUnused = v; });
  }
})();
