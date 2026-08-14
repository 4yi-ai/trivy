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

  // ---- git form → JSON POST ----
  var gitForm = document.getElementById("git-form");
  if (gitForm) {
    gitForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var fd = new FormData(gitForm);
      var body = { source_type: "git", source_ref: fd.get("source_ref") };
      var token = fd.get("token");
      if (token) body.token = token;
      submitScan(JSON.stringify(body), { "Content-Type": "application/json" });
    });
  }

  // ---- zip form → multipart POST ----
  var zipForm = document.getElementById("zip-form");
  if (zipForm) {
    zipForm.addEventListener("submit", function (e) {
      e.preventDefault();
      submitScan(new FormData(zipForm), null);
    });
  }

  function submitScan(body, headers) {
    var opts = { method: "POST", body: body };
    if (headers) opts.headers = headers;
    fetch("/api/scans", opts)
      .then(function (r) {
        return r.json().then(function (data) { return { ok: r.ok, data: data }; });
      })
      .then(function (res) {
        if (!res.ok) { showError(res.data.error || "scan failed to start"); return; }
        window.location.href = "/scans/" + res.data.id;
      })
      .catch(function () { showError("network error"); });
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
    var links = document.querySelectorAll("#filters a");
    var rows = document.querySelectorAll("#findings-table tbody tr[data-sev]");
    links.forEach(function (a) {
      a.addEventListener("click", function (e) {
        e.preventDefault();
        var f = a.getAttribute("data-filter");
        links.forEach(function (l) { l.classList.toggle("active", l === a); });
        rows.forEach(function (row) {
          row.classList.toggle("hidden", f !== "" && row.getAttribute("data-sev") !== f);
        });
      });
    });
  }
})();
