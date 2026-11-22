(function () {
  "use strict";

  var state = {
    coords: {
      latitude: -7.9021141,
      longitude: 110.065129,
      distance_m: 0.0
    },
    isSubmittedToday: false,
    isSubmitting: false
  };

  var els = {
    loginSection: document.getElementById("login-section"),
    loginForm: document.getElementById("login-form"),
    usernameInput: document.getElementById("username-input"),
    passwordInput: document.getElementById("password-input"),
    loginSubmitBtn: document.getElementById("login-submit-btn"),
    loginError: document.getElementById("login-error"),

    dashboard: document.getElementById("dashboard"),
    dashboardAlert: document.getElementById("dashboard-alert"),
    userName: document.getElementById("user-name"),
    userMentor: document.getElementById("user-mentor"),
    refreshBtn: document.getElementById("refresh-btn"),
    logoutBtn: document.getElementById("logout-btn"),

    todayDate: document.getElementById("today-date"),
    todayTime: document.getElementById("today-time"),
    todayBadge: document.getElementById("today-badge"),
    todayDetails: document.getElementById("today-details"),
    todaySubmittedAt: document.getElementById("today-submitted-at"),
    todayApproval: document.getElementById("today-approval"),
    todayLogBox: document.getElementById("today-log-box"),
    todayActivityLog: document.getElementById("today-activity-log"),

    coordsDisplay: document.getElementById("coords-display"),
    coordsDistance: document.getElementById("coords-distance"),
    rerollBtn: document.getElementById("reroll-btn"),

    templateCounter: document.getElementById("template-counter"),
    randomTemplateBtn: document.getElementById("random-template-btn"),
    attendanceForm: document.getElementById("attendance-form"),
    activityInput: document.getElementById("activity-input"),
    learningInput: document.getElementById("learning-input"),
    obstaclesInput: document.getElementById("obstacles-input"),
    activityCount: document.getElementById("activity-count"),
    learningCount: document.getElementById("learning-count"),
    obstaclesCount: document.getElementById("obstacles-count"),
    submitBtn: document.getElementById("submit-btn"),

    recentHistoryList: document.getElementById("recent-history-list")
  };

  function extractErrorMessage(data, fallback) {
    if (data && typeof data === "object") {
      if (typeof data.error === "string" && data.error.trim()) {
        return data.error.trim();
      }
      if (data.error && typeof data.error === "object") {
        if (typeof data.error.message === "string" && data.error.message.trim()) {
          return data.error.message.trim();
        }
        if (typeof data.error.code === "string" && data.error.code.trim()) {
          return data.error.code.trim();
        }
      }
      if (typeof data.message === "string" && data.message.trim()) {
        return data.message.trim();
      }
    }
    return fallback;
  }

  function showLoginError(msg) {
    if (!els.loginError) return;
    if (!msg) {
      els.loginError.textContent = "";
      els.loginError.classList.add("hidden");
      return;
    }
    els.loginError.textContent = String(msg);
    els.loginError.classList.remove("hidden");
  }

  function showDashboardAlert(msg, type) {
    if (!els.dashboardAlert) return;
    if (!msg) {
      els.dashboardAlert.textContent = "";
      els.dashboardAlert.className = "alert hidden";
      return;
    }
    els.dashboardAlert.textContent = String(msg);
    var alertClass = type === "success" ? "alert alert-success" : "alert alert-error";
    els.dashboardAlert.className = alertClass;
  }

  function updateCharCounts() {
    if (els.activityCount && els.activityInput) {
      els.activityCount.textContent = String(els.activityInput.value.length) + " karakter";
    }
    if (els.learningCount && els.learningInput) {
      els.learningCount.textContent = String(els.learningInput.value.length) + " karakter";
    }
    if (els.obstaclesCount && els.obstaclesInput) {
      els.obstaclesCount.textContent = String(els.obstaclesInput.value.length) + " karakter";
    }
  }

  function renderCoordinates(coords) {
    if (!coords || typeof coords !== "object") return;
    var lat = Number(coords.latitude);
    var lon = Number(coords.longitude);
    var dist = Number(coords.distance_m);

    if (Number.isFinite(lat) && Number.isFinite(lon)) {
      state.coords.latitude = lat;
      state.coords.longitude = lon;
      state.coords.distance_m = Number.isFinite(dist) ? dist : 0.0;

      if (els.coordsDisplay) {
        els.coordsDisplay.textContent = lat.toFixed(7) + ", " + lon.toFixed(7);
      }
      if (els.coordsDistance) {
        els.coordsDistance.textContent = state.coords.distance_m.toFixed(2) + " m";
      }
    }
  }

  function renderTemplatesCounter(templatesInfo) {
    if (!els.templateCounter) return;
    if (templatesInfo && typeof templatesInfo === "object") {
      var rem = templatesInfo.remaining !== undefined ? String(templatesInfo.remaining) : "-";
      var tot = templatesInfo.total !== undefined ? String(templatesInfo.total) : "-";
      els.templateCounter.textContent = "Template belum dipakai: " + rem + " / " + tot;
    } else {
      els.templateCounter.textContent = "Template belum dipakai: - / -";
    }
  }

  function setFormDisabledState(disabled, alreadySubmitted) {
    if (els.activityInput) els.activityInput.disabled = disabled;
    if (els.learningInput) els.learningInput.disabled = disabled;
    if (els.obstaclesInput) els.obstaclesInput.disabled = disabled;
    if (els.randomTemplateBtn) els.randomTemplateBtn.disabled = disabled;
    if (els.rerollBtn) els.rerollBtn.disabled = disabled;
    if (els.submitBtn) {
      els.submitBtn.disabled = disabled;
      if (alreadySubmitted) {
        els.submitBtn.textContent = "Presensi Hari Ini Sudah Terkirim";
      } else if (state.isSubmitting) {
        els.submitBtn.textContent = "Mengirim Presensi...";
      } else {
        els.submitBtn.textContent = "Kirim Presensi Hari Ini";
      }
    }
  }

  function renderRecentHistory(items) {
    if (!els.recentHistoryList) return;
    while (els.recentHistoryList.firstChild) {
      els.recentHistoryList.removeChild(els.recentHistoryList.firstChild);
    }

    if (!Array.isArray(items) || items.length === 0) {
      var emptyLi = document.createElement("li");
      emptyLi.className = "history-empty";
      emptyLi.textContent = "Belum ada riwayat presensi.";
      els.recentHistoryList.appendChild(emptyLi);
      return;
    }

    for (var i = 0; i < items.length; i++) {
      var item = items[i] || {};
      var li = document.createElement("li");
      li.className = "history-item";

      var dateSpan = document.createElement("span");
      dateSpan.className = "history-date";
      dateSpan.textContent = String(item.date || "-");

      var metaDiv = document.createElement("div");
      metaDiv.className = "history-meta";

      var statusSpan = document.createElement("span");
      statusSpan.className = "history-status";
      statusSpan.textContent = String(item.status || "PRESENT");

      var badgeSpan = document.createElement("span");
      var approval = String(item.approval_status || "SUBMITTED");
      badgeSpan.className = "badge badge-submitted";
      badgeSpan.textContent = approval;

      metaDiv.appendChild(statusSpan);
      metaDiv.appendChild(badgeSpan);

      li.appendChild(dateSpan);
      li.appendChild(metaDiv);
      els.recentHistoryList.appendChild(li);
    }
  }

  function renderDashboard(data) {
    if (els.loginSection) els.loginSection.classList.add("hidden");
    if (els.dashboard) els.dashboard.classList.remove("hidden");

    var user = (data && data.user) || {};
    if (els.userName) els.userName.textContent = String(user.name || "-");
    if (els.userMentor) els.userMentor.textContent = String(user.mentor || "-");

    if (els.todayDate) els.todayDate.textContent = String((data && data.date) || "-");
    if (els.todayTime) els.todayTime.textContent = String((data && data.time_wib) || "--:--:--");

    var today = (data && data.today) || {};
    var submitted = Boolean(today.submitted);
    state.isSubmittedToday = submitted;

    if (els.todayBadge) {
      if (submitted) {
        els.todayBadge.className = "badge badge-submitted";
        els.todayBadge.textContent = "Sudah Presensi";
      } else {
        els.todayBadge.className = "badge badge-pending";
        els.todayBadge.textContent = "Belum Presensi";
      }
    }

    if (els.todayDetails) {
      if (submitted) {
        els.todayDetails.classList.remove("hidden");
        if (els.todaySubmittedAt) {
          els.todaySubmittedAt.textContent = String(today.submitted_at || "-");
        }
        if (els.todayApproval) {
          els.todayApproval.textContent = String(today.approval_status || "SUBMITTED");
        }
        if (els.todayLogBox && els.todayActivityLog) {
          if (today.activity_log) {
            els.todayActivityLog.textContent = String(today.activity_log);
            els.todayLogBox.classList.remove("hidden");
          } else {
            els.todayActivityLog.textContent = "";
            els.todayLogBox.classList.add("hidden");
          }
        }
      } else {
        els.todayDetails.classList.add("hidden");
      }
    }

    renderCoordinates(data && data.coords);
    renderTemplatesCounter(data && data.templates);
    renderRecentHistory((data && data.recent) || []);
    setFormDisabledState(submitted, submitted);
  }

  function showLoginScreen(errorMsg) {
    state.isSubmittedToday = false;
    state.isSubmitting = false;

    if (els.dashboard) els.dashboard.classList.add("hidden");
    if (els.loginSection) els.loginSection.classList.remove("hidden");

    if (els.userName) els.userName.textContent = "-";
    if (els.userMentor) els.userMentor.textContent = "-";
    if (els.activityInput) els.activityInput.value = "";
    if (els.learningInput) els.learningInput.value = "";
    if (els.obstaclesInput) els.obstaclesInput.value = "";
    updateCharCounts();
    showDashboardAlert("");
    showLoginError(errorMsg || "");
  }

  async function loadStatus(preserveAlert) {
    if (!preserveAlert) {
      showDashboardAlert("");
    }
    try {
      var res = await fetch("/api/status", {
        method: "GET",
        credentials: "same-origin",
        headers: {
          "Accept": "application/json"
        }
      });

      var data = {};
      try {
        data = await res.json();
      } catch (_err) {
        data = {};
      }

      if (res.status === 200) {
        renderDashboard(data);
        return;
      }

      if (res.status === 401) {
        showLoginScreen("");
        return;
      }

      var errText = extractErrorMessage(data, "Gagal memuat status presensi.");
      if (els.dashboard && els.dashboard.classList.contains("hidden")) {
        showLoginScreen(errText);
      } else {
        showDashboardAlert(errText, "error");
      }
    } catch (_err) {
      if (els.dashboard && els.dashboard.classList.contains("hidden")) {
        showLoginScreen("Tidak dapat terhubung ke server.");
      } else {
        showDashboardAlert("Tidak dapat terhubung ke server.", "error");
      }
    }
  }

  async function handleLoginSubmit(event) {
    event.preventDefault();
    showLoginError("");

    var username = els.usernameInput ? els.usernameInput.value.trim() : "";
    var password = els.passwordInput ? els.passwordInput.value : "";

    if (els.passwordInput) {
      els.passwordInput.value = "";
    }

    if (!username || !password.trim()) {
      showLoginError("Username dan kata sandi wajib diisi.");
      return;
    }

    if (els.loginSubmitBtn) {
      els.loginSubmitBtn.disabled = true;
      els.loginSubmitBtn.textContent = "Memverifikasi...";
    }

    try {
      var res = await fetch("/api/auth", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({
          username: username,
          password: password
        })
      });

      var data = {};
      try {
        data = await res.json();
      } catch (_err) {
        data = {};
      }

      if (res.status === 200) {
        await loadStatus(false);
        return;
      }

      showLoginError(extractErrorMessage(data, "Gagal masuk. Periksa kembali akun Anda."));
    } catch (_err) {
      showLoginError("Gagal menghubungi server autentikasi.");
    } finally {
      if (els.loginSubmitBtn) {
        els.loginSubmitBtn.disabled = false;
        els.loginSubmitBtn.textContent = "Masuk";
      }
    }
  }

  async function handleLogout() {
    try {
      await fetch("/api/auth", {
        method: "DELETE",
        credentials: "same-origin",
        headers: {
          "Accept": "application/json"
        }
      });
    } catch (_err) {
      // Ignore network error on logout; always clear client UI
    }
    showLoginScreen("");
  }

  async function handleRerollCoords() {
    if (state.isSubmittedToday || state.isSubmitting) return;
    if (els.rerollBtn) els.rerollBtn.disabled = true;

    try {
      var res = await fetch("/api/template?coords_only=1", {
        method: "GET",
        credentials: "same-origin",
        headers: {
          "Accept": "application/json"
        }
      });

      var data = {};
      try {
        data = await res.json();
      } catch (_err) {
        data = {};
      }

      if (res.status === 401) {
        showLoginScreen("Sesi Anda telah berakhir. Silakan masuk kembali.");
        return;
      }

      if (res.status === 200 && data.coords) {
        renderCoordinates(data.coords);
      } else {
        showDashboardAlert(extractErrorMessage(data, "Gagal mengacak ulang koordinat."), "error");
      }
    } catch (_err) {
      showDashboardAlert("Gagal mengacak ulang koordinat.", "error");
    } finally {
      if (els.rerollBtn && !state.isSubmittedToday) {
        els.rerollBtn.disabled = false;
      }
    }
  }

  async function handleRandomTemplate() {
    if (state.isSubmittedToday || state.isSubmitting) return;
    if (els.randomTemplateBtn) els.randomTemplateBtn.disabled = true;

    try {
      var res = await fetch("/api/template", {
        method: "GET",
        credentials: "same-origin",
        headers: {
          "Accept": "application/json"
        }
      });

      var data = {};
      try {
        data = await res.json();
      } catch (_err) {
        data = {};
      }

      if (res.status === 401) {
        showLoginScreen("Sesi Anda telah berakhir. Silakan masuk kembali.");
        return;
      }

      if (res.status === 200) {
        if (data.coords) {
          renderCoordinates(data.coords);
        }
        if (data.templates) {
          renderTemplatesCounter(data.templates);
        }
        var tpl = data.template;
        if (tpl && typeof tpl === "object") {
          if (els.activityInput) els.activityInput.value = String(tpl.activity || "");
          if (els.learningInput) els.learningInput.value = String(tpl.learning || "");
          if (els.obstaclesInput) els.obstaclesInput.value = String(tpl.obstacles || "");
          updateCharCounts();
        }
      } else {
        showDashboardAlert(extractErrorMessage(data, "Gagal memuat template laporan."), "error");
      }
    } catch (_err) {
      showDashboardAlert("Gagal memuat template laporan.", "error");
    } finally {
      if (els.randomTemplateBtn && !state.isSubmittedToday) {
        els.randomTemplateBtn.disabled = false;
      }
    }
  }

  async function handleAttendanceSubmit(event) {
    event.preventDefault();
    if (state.isSubmittedToday || state.isSubmitting) return;

    var activity = els.activityInput ? els.activityInput.value.trim() : "";
    var learning = els.learningInput ? els.learningInput.value.trim() : "";
    var obstacles = els.obstaclesInput ? els.obstaclesInput.value.trim() : "";

    if (!activity || !learning || !obstacles) {
      showDashboardAlert("Uraian aktivitas, pembelajaran, dan kendala wajib diisi.", "error");
      return;
    }

    state.isSubmitting = true;
    showDashboardAlert("");
    setFormDisabledState(true, false);

    try {
      var res = await fetch("/api/submit", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({
          activity: activity,
          learning: learning,
          obstacles: obstacles,
          latitude: state.coords.latitude,
          longitude: state.coords.longitude
        })
      });

      var data = {};
      try {
        data = await res.json();
      } catch (_err) {
        data = {};
      }

      if (res.status === 401) {
        showLoginScreen("Sesi Anda telah berakhir. Silakan masuk kembali.");
        return;
      }

      if (res.status === 409) {
        showDashboardAlert(extractErrorMessage(data, "Presensi hari ini sudah tercatat."), "error");
        await loadStatus(true);
        return;
      }

      if (res.status === 200) {
        showDashboardAlert(data.message || "Presensi hari ini berhasil dikirim!", "success");
        await loadStatus(true);
        return;
      }

      showDashboardAlert(extractErrorMessage(data, "Gagal mengirim presensi."), "error");
    } catch (_err) {
      showDashboardAlert("Gagal menghubungi server saat mengirim presensi.", "error");
    } finally {
      state.isSubmitting = false;
      if (!state.isSubmittedToday) {
        setFormDisabledState(false, false);
      }
    }
  }

  function bindEvents() {
    if (els.loginForm) {
      els.loginForm.addEventListener("submit", handleLoginSubmit);
    }
    if (els.refreshBtn) {
      els.refreshBtn.addEventListener("click", function () {
        loadStatus(false);
      });
    }
    if (els.logoutBtn) {
      els.logoutBtn.addEventListener("click", handleLogout);
    }
    if (els.rerollBtn) {
      els.rerollBtn.addEventListener("click", handleRerollCoords);
    }
    if (els.randomTemplateBtn) {
      els.randomTemplateBtn.addEventListener("click", handleRandomTemplate);
    }
    if (els.attendanceForm) {
      els.attendanceForm.addEventListener("submit", handleAttendanceSubmit);
    }
    if (els.activityInput) {
      els.activityInput.addEventListener("input", updateCharCounts);
    }
    if (els.learningInput) {
      els.learningInput.addEventListener("input", updateCharCounts);
    }
    if (els.obstaclesInput) {
      els.obstaclesInput.addEventListener("input", updateCharCounts);
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    bindEvents();
    updateCharCounts();
    loadStatus(false);
  });
})();
