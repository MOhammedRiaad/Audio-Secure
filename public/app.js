// app.js - Updated Secure Audio Player for new backend (ID-based, sections, signed URLs)
class SecureAudioPlayer {
  constructor() {
    this.API_BASE = window.location.origin;
    this.authToken = null;
    this.currentAudio = null;
    this.sessionTimer = null;
    this.availableFiles = [];
    this.currentFileData = null;
    this.isSessionActive = false;
    this.elements = {};
    this.init();
  }

  init() {
    this.initSecurity();
    this.cacheElements();
    this.setupEventListeners();
    this.showToast("Application initialized", "info");
  }

  initSecurity() {
    document.addEventListener("contextmenu", (e) => e.preventDefault());
    document.addEventListener("keydown", (e) => {
      if (this.isSecurityKeyCombo(e)) {
        e.preventDefault();
        this.showToast("Keyboard shortcut disabled", "warning");
      }
    });
    ["dragstart", "drop", "dragover", "dragenter"].forEach((event) => {
      document.addEventListener(event, (e) => e.preventDefault());
    });
    document.addEventListener("visibilitychange", () => {
      if (document.hidden && this.currentAudio && !this.currentAudio.paused) {
        this.currentAudio.pause();
        this.showToast("Audio paused due to tab change", "warning");
      }
    });
    window.addEventListener("beforeunload", (e) => {
      if (this.isSessionActive) {
        e.preventDefault();
        e.returnValue = "Leaving will end your session.";
        return e.returnValue;
      }
    });
  }

  isSecurityKeyCombo(e) {
    return (
      e.keyCode === 123 || // F12
      (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) ||
      (e.ctrlKey && e.keyCode === 85) || // Ctrl+U
      (e.ctrlKey && e.keyCode === 83) || // Ctrl+S
      (e.ctrlKey && e.keyCode === 80) || // Ctrl+P
      (e.ctrlKey && e.keyCode === 65) || // Ctrl+A
      (e.ctrlKey && e.keyCode === 67) || // Ctrl+C
      e.keyCode === 44 // Print Screen
    );
  }

  cacheElements() {
    const ids = [
      "loginContainer",
      "audioContainer",
      "loginForm",
      "username",
      "password",
      "loginBtn",
      "logoutBtn",
      "refreshBtn",
      "errorMsg",
      "successMsg",
      "userName",
      "timeRemaining",
      "fileSelect",
      "audioPlayer",
      "audioPlayerContainer",
      "timeline",
      "progress",
      "currentTime",
      "totalTime",
      "currentFileName",
      "indexContainer",
      "indexList",
      "loadingOverlay",
      "loadingText",
      "confirmModal",
      "confirmTitle",
      "confirmMessage",
      "confirmCancel",
      "confirmOk",
      "toastContainer",
    ];
    ids.forEach((id) => {
      this.elements[id] = document.getElementById(id);
    });
  }

  setupEventListeners() {
    if (this.elements.loginForm)
      this.elements.loginForm.addEventListener("submit", (e) => {
        e.preventDefault();
        this.handleLogin();
      });
    if (this.elements.username && this.elements.password) {
      this.elements.username.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          this.elements.password.focus();
        }
      });
      this.elements.password.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          this.handleLogin();
        }
      });
    }
    if (this.elements.loginBtn)
      this.elements.loginBtn.addEventListener("click", (e) => {
        e.preventDefault();
        this.handleLogin();
      });
    if (this.elements.logoutBtn)
      this.elements.logoutBtn.addEventListener("click", (e) => {
        e.preventDefault();
        this.handleLogout();
      });
    if (this.elements.refreshBtn)
      this.elements.refreshBtn.addEventListener("click", (e) => {
        e.preventDefault();
        this.refreshFileList();
      });
    if (this.elements.fileSelect)
      this.elements.fileSelect.addEventListener("change", (e) => {
        this.handleFileSelection(e.target.value);
      });
    if (this.elements.timeline) {
      this.elements.timeline.addEventListener("click", (e) =>
        this.handleTimelineClick(e)
      );
      this.elements.timeline.addEventListener("mousemove", (e) =>
        this.handleTimelineHover(e)
      );
      this.elements.timeline.addEventListener("mouseleave", () =>
        this.hideTimelineHover()
      );
    }
    this.setupModalEvents();
  }

  setupModalEvents() {
    const modal = this.elements.confirmModal;
    if (!modal) return;
    [
      modal.querySelector(".modal-backdrop"),
      this.elements.confirmCancel,
    ].forEach((el) => {
      if (el) el.addEventListener("click", () => this.hideModal());
    });
    if (this.elements.confirmOk)
      this.elements.confirmOk.addEventListener("click", () =>
        this.handleModalConfirm()
      );
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && modal.style.display !== "none")
        this.hideModal();
    });
  }

  async handleLogin() {
    const username = this.elements.username?.value?.trim();
    const password = this.elements.password?.value;
    if (!username || !password)
      return this.showError("Enter username & password");
    this.setLoginLoading(true);
    try {
      const response = await fetch(`${this.API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      if (response.ok && data.success) {
        this.authToken = data.token;
        this.isSessionActive = true;
        this.showSuccess("Authentication successful");
        setTimeout(() => this.switchToAudioView(data.user.username), 1000);
      } else {
        this.showError(data.error || "Authentication failed");
        this.clearLoginForm();
      }
    } catch (err) {
      console.error("Login error", err);
      this.showError("Network error");
    } finally {
      this.setLoginLoading(false);
    }
  }

  async handleLogout() {
    this.showModal("Confirm Logout", "Logout will terminate session", () =>
      this.performLogout()
    );
  }
  async performLogout() {
    this.showLoading("Logging out...");
    try {
      if (this.authToken)
        await fetch(`${this.API_BASE}/api/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${this.authToken}` },
        });
    } catch {}
    this.clearSession();
    this.switchToLoginView();
    this.hideLoading();
    this.showToast("Logged out", "info");
  }
  clearSession() {
    this.authToken = null;
    this.isSessionActive = false;
    this.availableFiles = [];
    this.currentFileData = null;
    if (this.sessionTimer) clearInterval(this.sessionTimer);
    this.cleanupAudio();
  }
  cleanupAudio() {
    if (this.currentAudio) {
      if (this.currentAudio.src.startsWith("blob:"))
        URL.revokeObjectURL(this.currentAudio.src);
      this.currentAudio.src = "";
      this.currentAudio = null;
    }
    if (this.elements.audioPlayer) this.elements.audioPlayer.src = "";
  }

  switchToAudioView(username) {
    this.elements.loginContainer.style.display = "none";
    this.elements.audioContainer.style.display = "block";
    if (this.elements.userName) this.elements.userName.textContent = username;
    const badge = document.getElementById("userBadge");
    if (badge) badge.textContent = username === "admin" ? "Admin" : "User";
    this.loadAvailableFiles();
  }
  switchToLoginView() {
    this.elements.audioContainer.style.display = "none";
    this.elements.loginContainer.style.display = "block";
    this.clearLoginForm();
    this.resetAudioView();
    this.hideMessages();
  }
  resetAudioView() {
    this.elements.audioPlayerContainer.style.display = "none";
    this.elements.fileSelect.innerHTML =
      '<option value="">Select an audio file...</option>';
    this.elements.indexList.innerHTML = "<div>Select an audio file</div>";
    this.updatePlayerInfo("", "0:00", "0:00");
    this.updateProgress(0);
  }

  async loadAvailableFiles() {
    try {
      this.showLoading("Loading files...");
      const res = await fetch(`${this.API_BASE}/api/audio/list`, {
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
      if (!res.ok) throw new Error("fail");
      const data = await res.json();
      this.availableFiles = data.files;
      this.populateFileSelector();
    } catch {
      this.showError("Failed to load files");
    } finally {
      this.hideLoading();
    }
  }

  populateFileSelector() {
    this.elements.fileSelect.innerHTML =
      '<option value="">Select an audio file...</option>';
    this.availableFiles.forEach((f) => {
      const opt = document.createElement("option");
      opt.value = f._id;
      opt.textContent = f.filename;
      this.elements.fileSelect.appendChild(opt);
    });
  }

  async handleFileSelection(fileId) {
    if (!fileId) return this.hideAudioPlayer();
    this.showLoading("Loading audio...");
    try {
      await this.loadAudioFile(fileId);
      this.showAudioPlayer();
    } catch (err) {
      this.showError("Failed to load audio");
    } finally {
      this.hideLoading();
    }
  }

  async loadAudioFile(fileId) {
    const metaRes = await fetch(
      `${this.API_BASE}/api/audio/${fileId}/metadata`,
      { headers: { Authorization: `Bearer ${this.authToken}` } }
    );
    if (!metaRes.ok) throw new Error("metadata");
    const metadata = await metaRes.json();
    this.currentFileData = metadata;

    // request signed URL for playback
    const signedRes = await fetch(
      `${this.API_BASE}/api/audio/${fileId}/signed-url`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ttlSeconds: 600 }),
      }
    );
    const { url } = await signedRes.json();
    const fullUrl = `${this.API_BASE}${url}`;

    this.setupAudioElement(fullUrl, metadata.filename);
    this.createTimestampIndex(metadata.sections);
  }

  setupAudioElement(srcUrl, filename) {
    this.cleanupAudio();
    if (this.elements.audioPlayer) {
      this.elements.audioPlayer.src = srcUrl;
      this.elements.audioPlayer.preload = "metadata";
      this.currentAudio = this.elements.audioPlayer;
      this.setupAudioEvents();
      this.updatePlayerInfo(filename, "0:00", "0:00");
      this.elements.audioPlayer.controlsList = "nodownload";
    }
  }

  setupAudioEvents() {
    if (!this.currentAudio) return;
    this.currentAudio.addEventListener("timeupdate", () =>
      this.handleTimeUpdate()
    );
    this.currentAudio.addEventListener("loadedmetadata", () =>
      this.handleMetadataLoaded()
    );
    this.currentAudio.addEventListener("ended", () =>
      this.showToast("Audio finished", "info")
    );
    this.currentAudio.addEventListener("error", () =>
      this.showError("Audio error")
    );
  }

  handleTimeUpdate() {
    if (!this.currentAudio?.duration) return;
    const cur = this.currentAudio.currentTime,
      dur = this.currentAudio.duration,
      perc = (cur / dur) * 100;
    this.updateProgress(perc);
    this.updatePlayerInfo(null, this.formatTime(cur), this.formatTime(dur));
  }
  handleMetadataLoaded() {
    if (!this.currentAudio) return;
    this.updatePlayerInfo(
      null,
      "0:00",
      this.formatTime(this.currentAudio.duration)
    );
  }
  handleTimelineClick(e) {
    if (!this.currentAudio?.duration) return;
    const rect = this.elements.timeline.getBoundingClientRect();
    const pos = (e.clientX - rect.left) / rect.width;
    this.currentAudio.currentTime = pos * this.currentAudio.duration;
  }
  handleTimelineHover(e) {
    if (!this.currentAudio?.duration) return;
    const rect = this.elements.timeline.getBoundingClientRect();
    const pos = (e.clientX - rect.left) / rect.width;
    const hover = pos * this.currentAudio.duration;
    this.elements.timeline.title = `Seek to ${this.formatTime(hover)}`;
  }
  hideTimelineHover() {
    if (this.elements.timeline) this.elements.timeline.title = "";
  }

  createTimestampIndex(sections) {
    if (!this.elements.indexList) return;
    this.elements.indexList.innerHTML = "";
    sections.forEach((s) => {
      const item = document.createElement("div");
      item.className = "index-item";
      item.innerHTML = `<span>${s.label}</span><span>${this.formatTime(
        s.startTime
      )}</span>`;
      item.addEventListener("click", () => {
        this.seekToTimestamp(s.startTime, s.label);
        this.setActiveIndexItem(item);
      });
      this.elements.indexList.appendChild(item);
    });
  }

  seekToTimestamp(time, label) {
    if (!this.currentAudio) return;
    this.currentAudio.currentTime = time;
    this.currentAudio.play().catch(() => this.showError("Play error"));
    this.showToast(`Playing: ${label}`, "info");
  }
  setActiveIndexItem(active) {
    const items = this.elements.indexList?.querySelectorAll(".index-item");
    items?.forEach((i) => i.classList.remove("active"));
    if (active) active.classList.add("active");
  }

  // session monitoring (disabled unless backend provides /api/session/status)
  async updateSessionInfo() {
    /* optional */
  }

  async refreshFileList() {
    this.showToast("Refreshing...", "info");
    await this.loadAvailableFiles();
  }

  showAudioPlayer() {
    this.elements.audioPlayerContainer.style.display = "block";
  }
  hideAudioPlayer() {
    this.elements.audioPlayerContainer.style.display = "none";
    this.resetAudioView();
  }

  updatePlayerInfo(filename, cur, total) {
    if (filename && this.elements.currentFileName)
      this.elements.currentFileName.textContent = filename;
    if (cur && this.elements.currentTime)
      this.elements.currentTime.textContent = cur;
    if (total && this.elements.totalTime)
      this.elements.totalTime.textContent = total;
  }
  updateProgress(p) {
    if (this.elements.progress)
      this.elements.progress.style.width = `${Math.min(100, Math.max(0, p))}%`;
  }

  setLoginLoading(loading) {
    const btn = this.elements.loginBtn;
    const text = document.getElementById("loginText");
    const spinner = document.getElementById("loginSpinner");
    if (btn) btn.disabled = loading;
    if (text) text.style.display = loading ? "none" : "inline";
    if (spinner) spinner.style.display = loading ? "inline-block" : "none";
  }
  clearLoginForm() {
    if (this.elements.username) this.elements.username.value = "";
    if (this.elements.password) this.elements.password.value = "";
  }
  showLoading(text = "Loading...") {
    if (this.elements.loadingOverlay)
      this.elements.loadingOverlay.style.display = "flex";
    if (this.elements.loadingText) this.elements.loadingText.textContent = text;
  }
  hideLoading() {
    if (this.elements.loadingOverlay)
      this.elements.loadingOverlay.style.display = "none";
  }

  showModal(title, msg, onConfirm) {
    if (!this.elements.confirmModal) return;
    this.elements.confirmTitle.textContent = title;
    this.elements.confirmMessage.textContent = msg;
    this.modalConfirmCallback = onConfirm;
    this.elements.confirmModal.style.display = "flex";
  }
  hideModal() {
    if (this.elements.confirmModal)
      this.elements.confirmModal.style.display = "none";
    this.modalConfirmCallback = null;
  }
  handleModalConfirm() {
    if (this.modalConfirmCallback) this.modalConfirmCallback();
    this.hideModal();
  }

  showError(m) {
    this.showMessage(m, "error");
    this.showToast(m, "error");
  }
  showSuccess(m) {
    this.showMessage(m, "success");
    this.showToast(m, "success");
  }
  showMessage(m, t) {
    const el =
      t === "error" ? this.elements.errorMsg : this.elements.successMsg;
    if (!el) return;
    el.textContent = m;
    el.style.display = "block";
    setTimeout(() => (el.style.display = "none"), t === "error" ? 6000 : 4000);
  }
  hideMessages() {
    [this.elements.errorMsg, this.elements.successMsg].forEach((el) => {
      if (el) el.style.display = "none";
    });
  }
  showToast(m, t = "info", dur = 5000) {
    if (!this.elements.toastContainer) return;
    const toast = document.createElement("div");
    toast.className = `toast ${t}`;
    const icons = { success: "✅", error: "❌", warning: "⚠️", info: "ℹ️" };
    toast.innerHTML = `<div class=toast-icon>${
      icons[t] || icons.info
    }</div><div class=toast-content><div>${m}</div></div><button class=toast-close>×</button>`;
    toast
      .querySelector(".toast-close")
      .addEventListener("click", () => this.removeToast(toast));
    setTimeout(() => this.removeToast(toast), dur);
    this.elements.toastContainer.appendChild(toast);
  }
  removeToast(toast) {
    if (toast && toast.parentNode) {
      toast.style.animation = "fadeOut 0.3s";
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 300);
    }
  }
  formatTime(s) {
    if (!isFinite(s)) return "0:00";
    const m = Math.floor(s / 60),
      sec = Math.floor(s % 60);
    return `${m}:${sec.toString().padStart(2, "0")}`;
  }
  formatDuration(ms) {
    const sec = Math.floor(ms / 1000),
      min = Math.floor(sec / 60),
      h = Math.floor(min / 60);
    if (h > 0) return `${h}h ${min % 60}m`;
    else if (min > 0) return `${min}m ${sec % 60}s`;
    else return `${sec}s`;
  }
}

// Initialize the application when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  window.audioPlayer = new SecureAudioPlayer();
});

// Add fadeOut animation for toasts
const style = document.createElement("style");
style.textContent = `
    @keyframes fadeOut {
        from {
            opacity: 1;
            transform: translateX(0);
        }
        to {
            opacity: 0;
            transform: translateX(100%);
        }
    }
`;
document.head.appendChild(style);
