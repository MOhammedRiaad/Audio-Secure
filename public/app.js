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
    this.restoreSession();
    this.showToast("Application initialized", "info");
     this.initUserManagementModals();
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
      "userBadge",
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
      "sessionExtensionModal",
      "sessionExpiryTime",
      "sessionExtensionCancel",
      "sessionExtensionExtend",
      "toastContainer",
      "adminPanel",
      "permissionsTab",
      "usersTab",
      "filesTab",
      "permissionsTabContent",
      "usersTabContent",
      "filesTabContent",
      "permissionsMatrix",
      "usersContainer",
      "filesContainer",
      "refreshPermissionsBtn"
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
    
    // Admin panel event listeners
    if (this.elements.permissionsTab)
      this.elements.permissionsTab.addEventListener("click", () =>
        this.switchAdminTab("permissions")
      );
    if (this.elements.usersTab)
      this.elements.usersTab.addEventListener("click", () =>
        this.switchAdminTab("users")
      );
    if (this.elements.filesTab)
      this.elements.filesTab.addEventListener("click", () =>
        this.switchAdminTab("files")
      );
    if (this.elements.refreshPermissionsBtn)
      this.elements.refreshPermissionsBtn.addEventListener("click", () =>
        this.loadPermissionsMatrix()
      );
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
    
    // Session extension modal event listeners
    if (this.elements.sessionExtensionCancel)
      this.elements.sessionExtensionCancel.addEventListener("click", () =>
        this.handleSessionExtensionCancel()
      );
    if (this.elements.sessionExtensionExtend)
      this.elements.sessionExtensionExtend.addEventListener("click", () =>
        this.handleSessionExtensionExtend()
      );
    
    // Event delegation for data-action attributes and admin tabs
    document.addEventListener('click', (e) => {
      // Handle admin tab switching
      if (e.target.classList.contains('admin-tab')) {
        const tab = e.target.dataset.tab;
        if (tab) {
          this.switchAdminTab(tab);
        }
        return;
      }
      
      // Handle data-action clicks
      const action = e.target.dataset.action;
      if (action) {
        this.handleActionClick(e, action);
      }
    });
    
    // Handle select changes for role updates
    document.addEventListener('change', (e) => {
      if (e.target.dataset.action === 'update-user-role') {
        const userId = e.target.dataset.userId;
        const newRole = e.target.value;
        if (userId && newRole) {
          this.updateUserRole(userId, newRole);
        }
      }
    });
    
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
        this.currentUser = data.user;
        this.saveSession();
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
    this.clearStoredSession();
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

  // Session persistence methods
  saveSession() {
    try {
      const sessionData = {
        authToken: this.authToken,
        currentUser: this.currentUser,
        isSessionActive: this.isSessionActive,
        timestamp: Date.now()
      };
      localStorage.setItem('audioSecureSession', JSON.stringify(sessionData));
    } catch (error) {
      console.warn('Failed to save session:', error);
    }
  }

  restoreSession() {
    try {
      const sessionData = localStorage.getItem('audioSecureSession');
      if (!sessionData) return;
      
      const parsed = JSON.parse(sessionData);
      const sessionAge = Date.now() - parsed.timestamp;
      
      // Check if session is less than 30 minutes old (matching JWT expiry)
      if (sessionAge > 30 * 60 * 1000) {
        this.clearStoredSession();
        return;
      }
      
      // Verify token is still valid by making a test request
      this.verifyAndRestoreSession(parsed);
    } catch (error) {
      console.warn('Failed to restore session:', error);
      this.clearStoredSession();
    }
  }

  async verifyAndRestoreSession(sessionData) {
    try {
      // Test the token with a simple API call
      const response = await fetch(`${this.API_BASE}/api/audio/list`, {
        headers: { Authorization: `Bearer ${sessionData.authToken}` }
      });
      
      if (response.ok) {
        // Token is valid, restore session
        this.authToken = sessionData.authToken;
        this.currentUser = sessionData.currentUser;
        this.isSessionActive = sessionData.isSessionActive;
        
        // Calculate remaining session time based on original timestamp
        const sessionAge = Date.now() - sessionData.timestamp;
        const remainingTime = (30 * 60 * 1000) - sessionAge;
        
        // Start timer with remaining time if valid, otherwise start fresh
        if (remainingTime > 0) {
          this.startSessionTimer(remainingTime);
        } else {
          this.startSessionTimer();
        }
        
        // Mark that timer is already started to prevent switchToAudioView from restarting it
        this.timerAlreadyStarted = true;
        
        this.switchToAudioView(sessionData.currentUser.username);
        this.showToast('Session restored', 'success');
      } else {
        // Token is invalid, clear session
        this.clearStoredSession();
      }
    } catch (error) {
      console.warn('Session verification failed:', error);
      this.clearStoredSession();
    }
  }

  clearStoredSession() {
    try {
      localStorage.removeItem('audioSecureSession');
    } catch (error) {
      console.warn('Failed to clear stored session:', error);
    }
  }

  async switchToAudioView(username) {
    this.elements.loginContainer.style.display = "none";
    this.elements.audioContainer.style.display = "block";
    if (this.elements.userName) this.elements.userName.textContent = username;
    const badge = document.getElementById("userBadge");
    if (badge) badge.textContent = username === "admin" ? "Admin" : "User";
    
    // Start session timer only if not already started during session restoration
    if (!this.timerAlreadyStarted) {
      this.startSessionTimer();
    }
    // Reset the flag for future use
    this.timerAlreadyStarted = false;
    
    // Check if user is admin and show admin panel
    await this.checkAdminStatus();
    
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

  // Session timer functionality
  startSessionTimer(remainingTimeMs = null) {
     // Clear any existing timer
     if (this.sessionTimer) {
       clearInterval(this.sessionTimer);
     }
     
     // Reset session extension flag
     this.sessionExtensionShown = false;
     
     // Set session end time based on remaining time or default to 30 minutes
     if (remainingTimeMs !== null) {
       this.sessionEndTime = Date.now() + remainingTimeMs;
     } else {
       this.sessionEndTime = Date.now() + (30 * 60 * 1000);
     }
     
     // Update timer immediately
     this.updateSessionTimer();
     
     // Update timer every second
     this.sessionTimer = setInterval(() => {
       this.updateSessionTimer();
     }, 1000);
   }
  
  updateSessionTimer() {
     if (!this.sessionEndTime || !this.elements.timeRemaining) return;
     
     const now = Date.now();
     const timeLeft = this.sessionEndTime - now;
     
     if (timeLeft <= 0) {
       // Session expired
       this.elements.timeRemaining.textContent = "00:00";
       this.showToast("Session expired. Please login again.", "warning");
       this.performLogout();
       return;
     }
     
     // Convert to minutes and seconds
     const minutes = Math.floor(timeLeft / (1000 * 60));
     const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);
     
     // Format as MM:SS
     const formattedTime = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
     this.elements.timeRemaining.textContent = formattedTime;
     
     // Show session extension modal when 2 minutes remain (and not already shown)
     if (timeLeft <= 2 * 60 * 1000 && !this.sessionExtensionShown) {
       this.showSessionExtensionModal(timeLeft);
       this.sessionExtensionShown = true;
     }
     
     // Update modal timer if it's visible
     if (this.elements.sessionExtensionModal && this.elements.sessionExtensionModal.style.display !== 'none') {
       this.updateSessionExtensionModalTimer(timeLeft);
     }
     
     // Change color when less than 5 minutes remaining
     if (timeLeft < 5 * 60 * 1000) {
       this.elements.timeRemaining.style.color = '#e53e3e';
     } else {
       this.elements.timeRemaining.style.color = '#4a5568';
     }
   }
  
  // Session extension modal methods
   showSessionExtensionModal(timeLeft) {
     if (!this.elements.sessionExtensionModal) return;
     
     this.updateSessionExtensionModalTimer(timeLeft);
     this.elements.sessionExtensionModal.style.display = 'flex';
   }
   
   updateSessionExtensionModalTimer(timeLeft) {
     if (!this.elements.sessionExpiryTime) return;
     
     const minutes = Math.floor(timeLeft / (1000 * 60));
     const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);
     const formattedTime = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
     
     this.elements.sessionExpiryTime.textContent = formattedTime;
   }
   
   hideSessionExtensionModal() {
     if (this.elements.sessionExtensionModal) {
       this.elements.sessionExtensionModal.style.display = 'none';
     }
   }
   
   handleSessionExtensionCancel() {
     this.hideSessionExtensionModal();
     this.showToast('Session will expire naturally', 'info');
   }
   
   async handleSessionExtensionExtend() {
     this.showLoading('Extending session...');
     
     try {
       const response = await fetch(`${this.API_BASE}/api/auth/refresh`, {
         method: 'POST',
         headers: {
           'Authorization': `Bearer ${this.authToken}`,
           'Content-Type': 'application/json'
         }
       });
       
       const data = await response.json();
       
       if (response.ok && data.success) {
         // Update token and reset timer
         this.authToken = data.token;
         this.sessionEndTime = Date.now() + (30 * 60 * 1000);
         this.sessionExtensionShown = false;
         
         // Update stored session
         this.saveSession();
         
         this.hideSessionExtensionModal();
         this.showToast('Session extended for 30 minutes', 'success');
       } else {
         this.showError(data.error || 'Failed to extend session');
         this.hideSessionExtensionModal();
       }
     } catch (error) {
       console.error('Session extension error:', error);
       this.showError('Network error while extending session');
       this.hideSessionExtensionModal();
     } finally {
       this.hideLoading();
     }
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

  // Admin functionality methods
   async checkAdminStatus() {
     if (this.currentUser && this.currentUser.roles && this.currentUser.roles.includes('admin')) {
       if (this.elements.adminPanel) {
         this.elements.adminPanel.style.display = 'block';
         this.switchAdminTab('permissions');
         await this.loadPermissionsMatrix();
       }
     } else {
       if (this.elements.adminPanel) {
         this.elements.adminPanel.style.display = 'none';
       }
     }
   }

  switchAdminTab(tab) {
    // Hide all tab contents
    ['permissions', 'users', 'files'].forEach(t => {
      const tabEl = this.elements[`${t}Tab`];
      const contentEl = this.elements[`${t}TabContent`];
      if (tabEl) tabEl.classList.remove('active');
      if (contentEl) contentEl.style.display = 'none';
    });
    
    // Show selected tab
    const activeTab = this.elements[`${tab}Tab`];
    const activeContent = this.elements[`${tab}TabContent`];
    if (activeTab) activeTab.classList.add('active');
    if (activeContent) activeContent.style.display = 'block';
    
    // Load content based on tab
    switch(tab) {
      case 'permissions':
        this.loadPermissionsMatrix();
        break;
      case 'users':
        this.loadUsersManagement();
        break;
      case 'files':
        this.loadFilesManagement();
        break;
    }
  }

  async loadPermissionsMatrix() {
    if (!this.elements.permissionsMatrix) return;
    
    try {
      this.showLoading('Loading permissions...');
      
      // Load users, files, and current permissions
      const [usersResponse, filesResponse, permissionsResponse] = await Promise.all([
        fetch(`${this.API_BASE}/api/admin/users`, {
          headers: { Authorization: `Bearer ${this.authToken}` }
        }),
        fetch(`${this.API_BASE}/api/admin/files`, {
          headers: { Authorization: `Bearer ${this.authToken}` }
        }),
        fetch(`${this.API_BASE}/api/admin/permissions`, {
          headers: { Authorization: `Bearer ${this.authToken}` }
        })
      ]);
      
      if (usersResponse.ok && filesResponse.ok && permissionsResponse.ok) {
        const users = await usersResponse.json();
        const files = await filesResponse.json();
        const permissions = await permissionsResponse.json();
        
        this.renderPermissionsMatrix(users.users, files.files, permissions.permissions);
      } else {
        this.showError('Failed to load permission data');
      }
    } catch (error) {
      console.error('Error loading permissions:', error);
      this.showError('Failed to load permissions matrix');
    } finally {
      this.hideLoading();
    }
  }

  renderPermissionsMatrix(users, files, permissions) {
    const permissionLookup = {};
    permissions.forEach(perm => {
      const key = `${perm.userId}_${perm.fileId}`;
      permissionLookup[key] = perm.isActive;
    });
    
    let html = `
      <div class="permissions-container">
        <div class="permissions-header">
          <h3>🔐 Permission Management</h3>
          <div class="header-controls">
            <div class="view-toggle">
              <button class="view-btn active" data-view="user-centric">👥 By Users</button>
              <button class="view-btn" data-view="file-centric">📁 By Files</button>
            </div>
            <div class="search-container">
              <input type="text" class="search-input" placeholder="Search users or files..." id="permissionSearch">
              <button class="search-btn">🔍</button>
            </div>
            <button class="refresh-btn" data-action="refresh-permissions">🔄 Refresh</button>
          </div>
        </div>
        
        <div class="permissions-content">
          <div class="view-container user-centric-view active" id="userCentricView">
            ${this.renderUserCentricView(users, files, permissionLookup)}
          </div>
          
          <div class="view-container file-centric-view" id="fileCentricView">
            ${this.renderFileCentricView(users, files, permissionLookup)}
          </div>
        </div>
      </div>
    `;
    
    this.elements.permissionsMatrix.innerHTML = html;
    this.setupPermissionViewToggle();
    this.setupPermissionSearch();
  }
  
  renderUserCentricView(users, files, permissionLookup) {
    const nonAdminUsers = users.filter(user => !user.roles || !user.roles.includes('admin'));
    
    if (nonAdminUsers.length === 0) {
      return '<div class="empty-state">👤 No users found</div>';
    }
    
    let html = '<div class="permission-cards-grid">';
    
    nonAdminUsers.forEach(user => {
      const userPermissions = files.map(file => {
        const key = `${user.username}_${file._id}`;
        return {
          file,
          hasAccess: permissionLookup[key] === true
        };
      });
      
      const grantedCount = userPermissions.filter(p => p.hasAccess).length;
      
      html += `
        <div class="permission-card user-card" data-user="${user.username}">
          <div class="card-header">
            <div class="user-avatar">👤</div>
            <div class="user-details">
              <h4 class="user-name">${user.username}</h4>
              <span class="user-role ${user.roles ? user.roles[0] : 'user'}">${user.roles ? user.roles.join(', ') : 'user'}</span>
            </div>
            <div class="permission-summary">
              <span class="access-count">${grantedCount}/${files.length}</span>
              <span class="access-label">files</span>
            </div>
          </div>
          
          <div class="card-content">
            <div class="files-list">
              ${userPermissions.map(perm => `
                <div class="file-permission-item">
                  <div class="file-info">
                    <span class="file-icon">🎵</span>
                    <span class="file-name" title="${perm.file.filename}">${perm.file.filename.length > 25 ? perm.file.filename.substring(0, 25) + '...' : perm.file.filename}</span>
                  </div>
                  <button class="permission-toggle ${perm.hasAccess ? 'granted' : ''}" 
                          data-action="toggle-permission"
                          data-username="${user.username}"
                          data-file-id="${perm.file._id}"
                          data-current-permission="${perm.hasAccess}"
                          title="${perm.hasAccess ? 'Click to revoke access' : 'Click to grant access'}">
                    <span class="toggle-indicator"></span>
                  </button>
                </div>
              `).join('')}
            </div>
          </div>
          
          <div class="card-actions">
            <button class="bulk-action-btn grant-all" data-action="bulk-grant" data-username="${user.username}">✅ Grant All</button>
            <button class="bulk-action-btn revoke-all" data-action="bulk-revoke" data-username="${user.username}">❌ Revoke All</button>
          </div>
        </div>
      `;
    });
    
    html += '</div>';
    return html;
  }
  
  renderFileCentricView(users, files, permissionLookup) {
    if (files.length === 0) {
      return '<div class="empty-state">📁 No files found</div>';
    }
    
    let html = '<div class="permission-cards-grid">';
    
    files.forEach(file => {
      const nonAdminUsers = users.filter(user => !user.roles || !user.roles.includes('admin'));
      const filePermissions = nonAdminUsers.map(user => {
        const key = `${user.username}_${file._id}`;
        return {
          user,
          hasAccess: permissionLookup[key] === true
        };
      });
      
      const grantedCount = filePermissions.filter(p => p.hasAccess).length;
      
      html += `
        <div class="permission-card file-card" data-file-id="${file._id}">
          <div class="card-header">
            <div class="file-avatar">🎵</div>
            <div class="file-details">
              <h4 class="file-name" title="${file.filename}">${file.filename}</h4>
              <div class="file-meta">
                <span class="file-size">${this.formatFileSize(file.size)}</span>
                <span class="file-duration">${this.formatDuration(file.duration * 1000)}</span>
              </div>
            </div>
            <div class="permission-summary">
              <span class="access-count">${grantedCount}/${nonAdminUsers.length}</span>
              <span class="access-label">users</span>
            </div>
          </div>
          
          <div class="card-content">
            <div class="users-list">
              ${filePermissions.map(perm => `
                <div class="user-permission-item">
                  <div class="user-info">
                    <span class="user-icon">👤</span>
                    <span class="user-name">${perm.user.username}</span>
                    <span class="user-role-badge ${perm.user.roles ? perm.user.roles[0] : 'user'}">${perm.user.roles ? perm.user.roles[0] : 'user'}</span>
                  </div>
                  <button class="permission-toggle ${perm.hasAccess ? 'granted' : ''}" 
                          data-action="toggle-permission"
                          data-username="${perm.user.username}"
                          data-file-id="${file._id}"
                          data-current-permission="${perm.hasAccess}"
                          title="${perm.hasAccess ? 'Click to revoke access' : 'Click to grant access'}">
                    <span class="toggle-indicator"></span>
                  </button>
                </div>
              `).join('')}
            </div>
          </div>
          
          <div class="card-actions">
            <button class="bulk-action-btn grant-all" data-action="bulk-grant-file" data-file-id="${file._id}">✅ Grant All</button>
            <button class="bulk-action-btn revoke-all" data-action="bulk-revoke-file" data-file-id="${file._id}">❌ Revoke All</button>
          </div>
        </div>
      `;
    });
    
    html += '</div>';
    return html;
  }

  async loadUsersManagement() {
    if (!this.elements.usersContainer) return;
    
    try {
      this.showLoading('Loading users...');
      const response = await fetch(`${this.API_BASE}/api/admin/users`, {
        headers: { Authorization: `Bearer ${this.authToken}` }
      });
      
      if (!response.ok) throw new Error('Failed to load users');
      const data = await response.json();
      
      this.renderUsersManagement(data.users);
    } catch (error) {
      this.showError('Failed to load users');
    } finally {
      this.hideLoading();
    }
  }

   renderUsersManagement(users) {
    const container = document.getElementById('usersManagementContent');
    if (!container) return;

    let html = `
      <div class="management-header">
        <h3>System Users</h3>
        <button class="btn btn-primary" data-action="show-create-user-form">
          <span class="btn-icon">👤</span> Add New User
        </button>
      </div>
      <div class="users-grid">`;

    users.forEach(user => {
      const statusClass = user.accountStatus === 'active' ? 'status-active' : 'status-locked';
      const statusIcon = user.accountStatus === 'active' ? '🟢' : '🔒';
      const lastLogin = user.lastLogin ? new Date(user.lastLogin).toLocaleDateString() : 'Never';
      
      html += `
        <div class="user-card">
          <div class="user-info">
            <div class="user-header">
              <h4>${user.username}</h4>
              <span class="user-status ${statusClass}">${statusIcon} ${user.accountStatus}</span>
            </div>
            <div class="user-details">
              <p><strong>Role:</strong> ${user.role}</p>
              <p><strong>Created:</strong> ${new Date(user.createdAt).toLocaleDateString()}</p>
              <p><strong>Last Login:</strong> ${lastLogin}</p>
              ${user.createdBy ? `<p><strong>Created by:</strong> ${user.createdBy}</p>` : ''}
            </div>
          </div>
          <div class="user-actions">
            <button class="btn btn-sm btn-secondary" data-action="edit-user" data-user-id="${user._id}" title="Edit User">
              ✏️ Edit
            </button>
            <button class="btn btn-sm btn-info" data-action="view-user-sessions" data-user-id="${user._id}" title="View Sessions">
              📱 Sessions
            </button>
            <button class="btn btn-sm btn-warning" data-action="reset-user-password" data-user-id="${user._id}" title="Reset Password">
              🔑 Reset
            </button>
            ${user.accountStatus === 'active' ? 
              `<button class="btn btn-sm btn-danger" data-action="lock-user" data-user-id="${user._id}" title="Lock Account">
                🔒 Lock
              </button>` :
              `<button class="btn btn-sm btn-success" data-action="unlock-user" data-user-id="${user._id}" title="Unlock Account">
                🔓 Unlock
              </button>`
            }
            <button class="btn btn-sm btn-danger" data-action="delete-user" data-user-id="${user._id}" title="Delete User">
              🗑️ Delete
            </button>
          </div>
        </div>`;
    });

    html += '</div>';
    container.innerHTML = html;
  }

  async loadFilesManagement() {
    if (!this.elements.filesContainer) return;
    
    try {
      this.showLoading('Loading files...');
      const response = await fetch(`${this.API_BASE}/api/admin/files`, {
        headers: { Authorization: `Bearer ${this.authToken}` }
      });
      
      if (!response.ok) throw new Error('Failed to load files');
      const data = await response.json();
      
      this.renderFilesManagement(data.files);
    } catch (error) {
      this.showError('Failed to load files');
    } finally {
      this.hideLoading();
    }
  }

  renderFilesManagement(files) {
    if (!this.elements.filesContainer) return;
    
    let html = `
      <div class="files-list">
        <div class="section-header">
          <h3>📁 File Management</h3>
          <button class="add-btn" data-action="show-upload-form">📤 Upload New File</button>
        </div>
        <div class="files-grid">
    `;
    
    files.forEach(file => {
      html += `
        <div class="file-card">
          <div class="file-info">
            <div class="file-details">
              <div class="file-name">${file.filename}</div>
              <div class="file-stats">
                <span class="stat-item">📊 ${this.formatFileSize(file.size)}</span>
                <span class="stat-item">⏱️ ${this.formatDuration(file.duration * 1000)}</span>
                <span class="stat-item">📑 ${file.sections ? file.sections.length : 0} sections</span>
              </div>
            </div>
            <div class="file-meta">
              <div class="meta-item">Uploaded: ${new Date(file.uploadedAt).toLocaleDateString()}</div>
            </div>
          </div>
          <div class="action-buttons">
            <button class="action-btn edit" data-action="edit-file-metadata" data-file-id="${file._id}">Edit Metadata</button>
            <button class="action-btn manage" data-action="manage-file-sections" data-file-id="${file._id}">Manage Sections</button>
            <button class="action-btn delete" data-action="delete-file" data-file-id="${file._id}">Delete</button>
          </div>
        </div>
      `;
    });
    
    html += '</div></div>';
    this.elements.filesContainer.innerHTML = html;
  }

  formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  async updateUserRole(userId, newRole) {
    try {
      const response = await fetch(`${this.API_BASE}/api/admin/users/${userId}/role`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.authToken}`
        },
        body: JSON.stringify({ role: newRole })
      });
      
      if (!response.ok) throw new Error('Failed to update role');
      
      this.showToast('User role updated successfully', 'success');
      this.loadPermissionsMatrix();
    } catch (error) {
      this.showError('Failed to update user role');
    }
  }

  async deleteUser(userId) {
    this.showModal(
      'Delete User',
      'Are you sure you want to delete this user? This action cannot be undone.',
      async () => {
        try {
          const response = await fetch(`${this.API_BASE}/api/admin/users/${userId}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${this.authToken}` }
          });
          
          if (!response.ok) throw new Error('Failed to delete user');
          
          this.showToast('User deleted successfully', 'success');
          this.loadPermissionsMatrix();
          this.loadUsersManagement();
        } catch (error) {
          this.showError('Failed to delete user');
        }
      }
    );
  }

  async lockUserAccount(userId) {
    try {
      const response = await fetch(`${this.API_BASE}/api/admin/users/${userId}/status`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.authToken}`
        },
        body: JSON.stringify({ status: 'locked' })
      });
      
      if (response.ok) {
        this.showSuccess('User account locked successfully');
        this.loadUsersManagement(); // Refresh the list
      } else {
        this.showError('Failed to lock user account');
      }
    } catch (error) {
      this.showError('Network error while locking user');
    }
  }

  async unlockUserAccount(userId) {
    try {
      const response = await fetch(`${this.API_BASE}/api/admin/users/${userId}/status`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.authToken}`
        },
        body: JSON.stringify({ status: 'active' })
      });
      
      if (response.ok) {
        this.showSuccess('User account unlocked successfully');
        this.loadUsersManagement(); // Refresh the list
      } else {
        this.showError('Failed to unlock user account');
      }
    } catch (error) {
      this.showError('Network error while unlocking user');
    }
  }

  async deleteFile(fileId) {
    this.showModal(
      'Delete File',
      'Are you sure you want to delete this file? This action cannot be undone.',
      async () => {
        try {
          const response = await fetch(`${this.API_BASE}/api/admin/files/${fileId}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${this.authToken}` }
          });
          
          if (!response.ok) throw new Error('Failed to delete file');
          
          this.showToast('File deleted successfully', 'success');
          this.loadFilesManagement();
          this.loadAvailableFiles(); // Refresh the main file list
        } catch (error) {
          this.showError('Failed to delete file');
        }
      }
    );
  }

  async togglePermission(username, fileId, currentPermission) {
    try {
      const endpoint = currentPermission ? '/api/admin/permissions/revoke' : '/api/admin/permissions/grant';
      const method = currentPermission ? 'DELETE' : 'POST';
      
      const response = await fetch(`${this.API_BASE}${endpoint}`, {
        method: method,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.authToken}`
        },
        body: JSON.stringify({
          userId: username,
          fileId: fileId
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to update permission');
      }
      
      this.showToast(
        `Permission ${!currentPermission ? 'granted to' : 'revoked from'} ${username}`, 
        'success'
      );
      this.loadPermissionsMatrix();
    } catch (error) {
      console.error('Permission toggle error:', error);
      this.showError(error.message || 'Failed to update permission');
    }
  }

  refreshPermissionsMatrix() {
    this.loadPermissionsMatrix();
  }

  async bulkGrantPermissions(username) {
    try {
      const response = await fetch(`${this.API_BASE}/api/admin/files`, {
        headers: { Authorization: `Bearer ${this.authToken}` }
      });
      
      if (!response.ok) throw new Error('Failed to load files');
      const data = await response.json();
      
      const promises = data.files.map(file => 
        fetch(`${this.API_BASE}/api/admin/permissions/grant`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${this.authToken}`
          },
          body: JSON.stringify({ userId: username, fileId: file._id })
        })
      );
      
      await Promise.all(promises);
      this.showToast(`Granted access to all files for ${username}`, 'success');
      await this.loadPermissionsMatrix();
    } catch (error) {
      console.error('Bulk grant error:', error);
      this.showToast('Failed to grant bulk permissions', 'error');
    }
  }
  
  async bulkRevokePermissions(username) {
    try {
      const response = await fetch(`${this.API_BASE}/api/admin/files`, {
        headers: { Authorization: `Bearer ${this.authToken}` }
      });
      
      if (!response.ok) throw new Error('Failed to load files');
      const data = await response.json();
      
      const promises = data.files.map(file => 
        fetch(`${this.API_BASE}/api/admin/permissions/revoke`, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${this.authToken}`
          },
          body: JSON.stringify({ userId: username, fileId: file._id })
        })
      );
      
      await Promise.all(promises);
      this.showToast(`Revoked access to all files for ${username}`, 'success');
      await this.loadPermissionsMatrix();
    } catch (error) {
      console.error('Bulk revoke error:', error);
      this.showToast('Failed to revoke bulk permissions', 'error');
    }
  }
  
  async bulkGrantFilePermissions(fileId) {
    try {
      const response = await fetch(`${this.API_BASE}/api/admin/users`, {
        headers: { Authorization: `Bearer ${this.authToken}` }
      });
      
      if (!response.ok) throw new Error('Failed to load users');
      const data = await response.json();
      
      const nonAdminUsers = data.users.filter(user => !user.roles || !user.roles.includes('admin'));
      const promises = nonAdminUsers.map(user => 
        fetch(`${this.API_BASE}/api/admin/permissions/grant`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${this.authToken}`
          },
          body: JSON.stringify({ userId: user.username, fileId })
        })
      );
      
      await Promise.all(promises);
      this.showToast('Granted file access to all users', 'success');
      await this.loadPermissionsMatrix();
    } catch (error) {
      console.error('Bulk grant file error:', error);
      this.showToast('Failed to grant bulk file permissions', 'error');
    }
  }
  
  async bulkRevokeFilePermissions(fileId) {
    try {
      const response = await fetch(`${this.API_BASE}/api/admin/users`, {
        headers: { Authorization: `Bearer ${this.authToken}` }
      });
      
      if (!response.ok) throw new Error('Failed to load users');
      const data = await response.json();
      
      const nonAdminUsers = data.users.filter(user => !user.roles || !user.roles.includes('admin'));
      const promises = nonAdminUsers.map(user => 
        fetch(`${this.API_BASE}/api/admin/permissions/revoke`, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${this.authToken}`
          },
          body: JSON.stringify({ userId: user.username, fileId })
        })
      );
      
      await Promise.all(promises);
      this.showToast('Revoked file access from all users', 'success');
      await this.loadPermissionsMatrix();
    } catch (error) {
      console.error('Bulk revoke file error:', error);
      this.showToast('Failed to revoke bulk file permissions', 'error');
    }
  }
  
  setupPermissionViewToggle() {
    const viewButtons = document.querySelectorAll('.view-btn');
    const userView = document.getElementById('userCentricView');
    const fileView = document.getElementById('fileCentricView');
    
    if (!viewButtons.length || !userView || !fileView) return;
    
    viewButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        
        // Update button states
        viewButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Update view visibility
        if (view === 'user-centric') {
          userView.classList.add('active');
          fileView.classList.remove('active');
        } else {
          fileView.classList.add('active');
          userView.classList.remove('active');
        }
      });
    });
  }
  
  setupPermissionSearch() {
    const searchInput = document.getElementById('permissionSearch');
    const searchBtn = document.querySelector('.search-btn');
    
    if (!searchInput) return;
    
    const performSearch = () => {
      const query = searchInput.value.toLowerCase().trim();
      const cards = document.querySelectorAll('.permission-card');
      
      cards.forEach(card => {
        const isUserCard = card.classList.contains('user-card');
        const isFileCard = card.classList.contains('file-card');
        
        let shouldShow = false;
        
        if (isUserCard) {
          const usernameEl = card.querySelector('.user-name');
          const fileNameEls = card.querySelectorAll('.file-name');
          const username = usernameEl ? usernameEl.textContent.toLowerCase() : '';
          const fileNames = Array.from(fileNameEls).map(el => el.textContent.toLowerCase());
          shouldShow = username.includes(query) || fileNames.some(name => name.includes(query));
        } else if (isFileCard) {
          const filenameEl = card.querySelector('.file-name');
          const usernameEls = card.querySelectorAll('.user-name');
          const filename = filenameEl ? filenameEl.textContent.toLowerCase() : '';
          const usernames = Array.from(usernameEls).map(el => el.textContent.toLowerCase());
          shouldShow = filename.includes(query) || usernames.some(name => name.includes(query));
        }
        
        card.style.display = shouldShow || query === '' ? 'block' : 'none';
      });
    };
    
    searchInput.addEventListener('input', performSearch);
    if (searchBtn) searchBtn.addEventListener('click', performSearch);
    searchInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        performSearch();
      }
    });
  }

  // Handle all data-action clicks
  handleActionClick(e, action) {
    const target = e.target;
    
    switch (action) {
      case 'toggle-permission':
        const username = target.dataset.username;
        const fileId = target.dataset.fileId;
        const currentPermission = target.dataset.currentPermission === 'true';
        this.togglePermission(username, fileId, currentPermission);
        break;
        
      case 'bulk-grant':
        const grantUsername = target.dataset.username;
        this.bulkGrantPermissions(grantUsername);
        break;
        
      case 'bulk-revoke':
        const revokeUsername = target.dataset.username;
        this.bulkRevokePermissions(revokeUsername);
        break;
        
      case 'bulk-grant-file':
        const grantFileId = target.dataset.fileId;
        this.bulkGrantFilePermissions(grantFileId);
        break;
        
      case 'bulk-revoke-file':
        const revokeFileId = target.dataset.fileId;
        this.bulkRevokeFilePermissions(revokeFileId);
        break;
        
      case 'refresh-permissions':
        this.refreshPermissionsMatrix();
        break;
        
      case 'show-create-user-form':
        this.showCreateUserForm();
        break;
        
      case 'edit-user':
        const editUserId = target.dataset.userId;
        this.editUser(editUserId);
        break;
        
      case 'reset-user-password':
        const resetUserId = target.dataset.userId;
        this.resetUserPassword(resetUserId);
        break;
        
      case 'delete-user':
        const deleteUserId = target.dataset.userId;
        this.deleteUser(deleteUserId);
        break;
        
      case 'show-upload-form':
        this.showUploadForm();
        break;
        
      case 'edit-file-metadata':
        const editFileId = target.dataset.fileId;
        this.editFileMetadata(editFileId);
        break;
        
      case 'manage-file-sections':
        const sectionsFileId = target.dataset.fileId;
        this.manageFileSections(sectionsFileId);
        break;
        
      case 'delete-file':
        const deleteFileId = target.dataset.fileId;
        this.deleteFile(deleteFileId);
        break;

      case 'show-user-sessions-modal':
        this.showUserSessionsModal();
        break;
        
      case 'view-user-sessions':
        const viewUserId = target.dataset.userId;
        this.showUserSessionsModal(viewUserId);
        break;
        
      case 'lock-user':
        const lockUserId = target.dataset.userId;
        this.lockUserAccount(lockUserId);
        break;
        
      case 'unlock-user':
        const unlockUserId = target.dataset.userId;
        this.unlockUserAccount(unlockUserId);
        break;
        
      default:
        console.warn('Unknown action:', action);
    }
  }
    // ... existing code ...

  // User Management Modal Functions
  initUserManagementModals() {
    this.setupCreateUserModal();
    this.setupPasswordChangeModal();
    this.setupDeviceAgreementModal();
    this.setupUserSessionsModal();
  }

  setupCreateUserModal() {
    const modal = document.getElementById('createUserModal');
    const form = document.getElementById('createUserForm');
    const submitBtn = document.getElementById('createUserSubmit');
    const cancelBtn = document.getElementById('createUserCancel');
    const passwordInput = document.getElementById('temporaryPassword');
    const confirmPasswordInput = document.getElementById('confirmPassword');

    if (!modal || !form) return;

    // Password strength validation
    passwordInput?.addEventListener('input', (e) => {
      this.validatePasswordStrength(e.target.value, 'passwordStrength');
      this.validatePasswordRequirements(e.target.value, '');
    });

    // Confirm password validation
    confirmPasswordInput?.addEventListener('input', (e) => {
      this.validatePasswordMatch(passwordInput.value, e.target.value, 'confirmPasswordError');
    });

    // Form submission
    submitBtn?.addEventListener('click', async (e) => {
      e.preventDefault();
      await this.handleCreateUser(form);
    });

    // Cancel button
    cancelBtn?.addEventListener('click', () => {
      this.hideCreateUserModal();
    });

    // Close on backdrop click
    modal.querySelector('.modal-backdrop')?.addEventListener('click', () => {
      this.hideCreateUserModal();
    });
  }

  setupPasswordChangeModal() {
    const modal = document.getElementById('passwordChangeModal');
    const form = document.getElementById('passwordChangeForm');
    const submitBtn = document.getElementById('passwordChangeSubmit');
    const newPasswordInput = document.getElementById('newPassword');
    const confirmNewPasswordInput = document.getElementById('confirmNewPassword');

    if (!modal || !form) return;

    // New password strength validation
    newPasswordInput?.addEventListener('input', (e) => {
      this.validatePasswordStrength(e.target.value, 'newPasswordStrength');
      this.validatePasswordRequirements(e.target.value, 'new');
    });

    // Confirm new password validation
    confirmNewPasswordInput?.addEventListener('input', (e) => {
      this.validatePasswordMatch(newPasswordInput.value, e.target.value, 'confirmNewPasswordError');
    });

    // Form submission
    submitBtn?.addEventListener('click', async (e) => {
      e.preventDefault();
      await this.handlePasswordChange(form);
    });
  }

  setupDeviceAgreementModal() {
    const modal = document.getElementById('deviceAgreementModal');
    const checkbox = document.getElementById('agreeToPolicy');
    const acceptBtn = document.getElementById('deviceAgreementAccept');
    const declineBtn = document.getElementById('deviceAgreementDecline');

    if (!modal) return;

    // Enable/disable accept button based on checkbox
    checkbox?.addEventListener('change', (e) => {
      if (acceptBtn) {
        acceptBtn.disabled = !e.target.checked;
      }
    });

    // Accept button
    acceptBtn?.addEventListener('click', async () => {
      await this.handleDeviceAgreementAccept();
    });

    // Decline button
    declineBtn?.addEventListener('click', async () => {
      await this.handleDeviceAgreementDecline();
    });
  }

  setupUserSessionsModal() {
    const modal = document.getElementById('userSessionsModal');
    const userSelect = document.getElementById('userSelect');
    const closeBtn = document.getElementById('userSessionsClose');
    const lockAllBtn = document.getElementById('lockAllSessions');
    const unlockAllBtn = document.getElementById('unlockAllSessions');

    if (!modal) return;

    // User selection change
    userSelect?.addEventListener('change', async (e) => {
      if (e.target.value) {
        await this.loadUserSessions(e.target.value);
      } else {
        document.getElementById('userSessionsContent').style.display = 'none';
      }
    });

    // Close button
    closeBtn?.addEventListener('click', () => {
      this.hideUserSessionsModal();
    });

    // Lock all sessions
    lockAllBtn?.addEventListener('click', async () => {
      const userId = userSelect?.value;
      if (userId) {
        await this.lockAllUserSessions(userId);
      }
    });

    // Unlock all sessions
    unlockAllBtn?.addEventListener('click', async () => {
      const userId = userSelect?.value;
      if (userId) {
        await this.unlockAllUserSessions(userId);
      }
    });

    // Close on backdrop click
    modal.querySelector('.modal-backdrop')?.addEventListener('click', () => {
      this.hideUserSessionsModal();
    });
  }

  // Password validation functions
  validatePasswordStrength(password, strengthElementId) {
    const strengthElement = document.getElementById(strengthElementId);
    if (!strengthElement) return;

    const strength = this.calculatePasswordStrength(password);
    const strengthBar = strengthElement.querySelector('.password-strength-bar');
    
    strengthElement.className = `password-strength ${strength.level}`;
    if (strengthBar) {
      strengthBar.style.width = `${strength.percentage}%`;
    }
  }

  calculatePasswordStrength(password) {
    let score = 0;
    if (password.length >= 8) score += 25;
    if (/[a-z]/.test(password)) score += 25;
    if (/[A-Z]/.test(password)) score += 25;
    if (/[0-9]/.test(password)) score += 15;
    if (/[^A-Za-z0-9]/.test(password)) score += 10;

    let level = 'weak';
    if (score >= 85) level = 'strong';
    else if (score >= 70) level = 'good';
    else if (score >= 50) level = 'fair';

    return { level, percentage: Math.min(score, 100) };
  }

  validatePasswordRequirements(password, prefix = '') {
    const requirements = [
      { id: `${prefix}lengthReq`, test: password.length >= 8 },
      { id: `${prefix}upperReq`, test: /[A-Z]/.test(password) },
      { id: `${prefix}lowerReq`, test: /[a-z]/.test(password) },
      { id: `${prefix}numberReq`, test: /[0-9]/.test(password) },
      { id: `${prefix}specialReq`, test: /[^A-Za-z0-9]/.test(password) }
    ];

    requirements.forEach(req => {
      const element = document.getElementById(req.id);
      if (element) {
        element.className = req.test ? 'valid' : 'invalid';
      }
    });
  }

  validatePasswordMatch(password, confirmPassword, errorElementId) {
    const errorElement = document.getElementById(errorElementId);
    if (!errorElement) return;

    if (confirmPassword && password !== confirmPassword) {
      errorElement.textContent = 'Passwords do not match';
      errorElement.style.display = 'block';
      return false;
    } else {
      errorElement.style.display = 'none';
      return true;
    }
  }

  // Modal display functions
  showCreateUserModal() {
    const modal = document.getElementById('createUserModal');
    if (modal) {
      modal.style.display = 'flex';
      this.clearCreateUserForm();
    }
  }

  hideCreateUserModal() {
    const modal = document.getElementById('createUserModal');
    if (modal) {
      modal.style.display = 'none';
      this.clearCreateUserForm();
    }
  }

  showPasswordChangeModal() {
    const modal = document.getElementById('passwordChangeModal');
    if (modal) {
      modal.style.display = 'flex';
      this.clearPasswordChangeForm();
    }
  }

  hidePasswordChangeModal() {
    const modal = document.getElementById('passwordChangeModal');
    if (modal) {
      modal.style.display = 'none';
    }
  }

  showDeviceAgreementModal(deviceInfo) {
    const modal = document.getElementById('deviceAgreementModal');
    if (modal) {
      this.populateDeviceInfo(deviceInfo);
      modal.style.display = 'flex';
    }
  }

  hideDeviceAgreementModal() {
    const modal = document.getElementById('deviceAgreementModal');
    if (modal) {
      modal.style.display = 'none';
    }
  }

  showUserSessionsModal(userId = null) {
    const modal = document.getElementById('userSessionsModal');
    if (modal) {
      modal.style.display = 'flex';
      // Load users first, then select specific user if provided
      this.loadUsersForSessionManagement().then(() => {
        if (userId) {
          const userSelect = document.getElementById('userSelect');
          if (userSelect) {
            userSelect.value = userId;
            // Trigger change event to load sessions
            userSelect.dispatchEvent(new Event('change'));
          }
        }
      });
    }
  }

  hideUserSessionsModal() {
    const modal = document.getElementById('userSessionsModal');
    if (modal) {
      modal.style.display = 'none';
    }
  }

  // Form handling functions
  async handleCreateUser(form) {
    const formData = new FormData(form);
    const userData = {
      username: formData.get('username'),
      password: formData.get('password'),
      confirmPassword: formData.get('confirmPassword'),
      role: formData.get('role')
    };

    // Validate form
    if (!this.validateCreateUserForm(userData)) {
      return;
    }

    try {
      const response = await fetch('/api/admin/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        },
        body: JSON.stringify({
          username: userData.username,
          password: userData.password,
          role: userData.role
        })
      });

      const result = await response.json();

      if (response.ok) {
        this.showSuccess(`User '${userData.username}' created successfully`);
        this.hideCreateUserModal();
        // Refresh users list if on admin panel
        if (this.currentAdminTab === 'users') {
          await this.loadUsersManagement();
        }
      } else {
        this.showError(result.error || 'Failed to create user');
      }
    } catch (error) {
      this.showError('Network error occurred while creating user');
    }
  }

  async handlePasswordChange(form) {
    const formData = new FormData(form);
    const passwordData = {
      currentPassword: formData.get('currentPassword'),
      newPassword: formData.get('newPassword'),
      confirmNewPassword: formData.get('confirmNewPassword')
    };

    // Validate form
    if (!this.validatePasswordChangeForm(passwordData)) {
      return;
    }

    try {
      const response = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        },
        body: JSON.stringify({
          currentPassword: passwordData.currentPassword,
          newPassword: passwordData.newPassword
        })
      });

      const result = await response.json();

      if (response.ok) {
        this.showSuccess('Password changed successfully');
        this.hidePasswordChangeModal();
        // Update user session to reflect password change
        await this.updateSessionInfo();
      } else {
        this.showError(result.error || 'Failed to change password');
      }
    } catch (error) {
      this.showError('Network error occurred while changing password');
    }
  }

  async handleDeviceAgreementAccept() {
    try {
      const deviceFingerprint = this.generateDeviceFingerprint();
      
      const response = await fetch('/api/auth/device-agreement', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        },
        body: JSON.stringify({
          deviceFingerprint,
          agreed: true
        })
      });

      const result = await response.json();

      if (response.ok) {
        this.hideDeviceAgreementModal();
        this.showSuccess('Device policy accepted. You can now continue.');
      } else {
        this.showError(result.error || 'Failed to accept device policy');
      }
    } catch (error) {
      this.showError('Network error occurred');
    }
  }

  async handleDeviceAgreementDecline() {
    this.hideDeviceAgreementModal();
    this.showError('Device policy declined. You will be logged out.');
    setTimeout(() => {
      this.handleLogout();
    }, 2000);
  }

  // Device fingerprinting
  generateDeviceFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Device fingerprint', 2, 2);
    
    const fingerprint = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      screenResolution: `${screen.width}x${screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      canvas: canvas.toDataURL(),
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack
    };

    return btoa(JSON.stringify(fingerprint));
  }

  populateDeviceInfo(deviceInfo) {
    const elements = {
      deviceBrowser: document.getElementById('deviceBrowser'),
      deviceOS: document.getElementById('deviceOS'),
      deviceIP: document.getElementById('deviceIP'),
      loginTime: document.getElementById('loginTime')
    };

    if (elements.deviceBrowser) {
      elements.deviceBrowser.textContent = this.getBrowserInfo();
    }
    if (elements.deviceOS) {
      elements.deviceOS.textContent = this.getOSInfo();
    }
    if (elements.deviceIP && deviceInfo?.ip) {
      elements.deviceIP.textContent = deviceInfo.ip;
    }
    if (elements.loginTime) {
      elements.loginTime.textContent = new Date().toLocaleString();
    }
  }

  getBrowserInfo() {
    const ua = navigator.userAgent;
    if (ua.includes('Chrome')) return 'Google Chrome';
    if (ua.includes('Firefox')) return 'Mozilla Firefox';
    if (ua.includes('Safari')) return 'Safari';
    if (ua.includes('Edge')) return 'Microsoft Edge';
    return 'Unknown Browser';
  }

  getOSInfo() {
    const platform = navigator.platform;
    if (platform.includes('Win')) return 'Windows';
    if (platform.includes('Mac')) return 'macOS';
    if (platform.includes('Linux')) return 'Linux';
    if (platform.includes('iPhone') || platform.includes('iPad')) return 'iOS';
    if (platform.includes('Android')) return 'Android';
    return 'Unknown OS';
  }

  // Session management functions
  async loadUsersForSessionManagement() {
    try {
      const response = await fetch('/api/admin/users', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      });

      if (response.ok) {
        const users = await response.json();
        this.populateUserSelect(users);
        return users;
      } else {
        this.showError('Failed to load users for session management');
        return [];
      }
    } catch (error) {
      this.showError('Network error while loading users');
      return [];
    }
  }

  populateUserSelect(users) {
    const userSelect = document.getElementById('userSelect');
    if (!userSelect) return;

    userSelect.innerHTML = '<option value="">🔍 Select a user to view sessions...</option>';
    users.forEach(user => {
      const option = document.createElement('option');
      option.value = user._id;
      const statusIcon = user.accountStatus === 'active' ? '🟢' : '🔴';
      option.textContent = `${statusIcon} ${user.username} (${user.role})`;
      userSelect.appendChild(option);
    });
  }

  async loadUserSessions(userId) {
    try {
      const response = await fetch(`/api/admin/users/${userId}/sessions`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      });

      if (response.ok) {
        const sessions = await response.json();
        this.renderUserSessions(sessions, userId);
      } else {
        this.showError('Failed to load user sessions');
      }
    } catch (error) {
      this.showError('Network error occurred');
    }
  }

  renderUserSessions(sessions, userId) {
    const contentDiv = document.getElementById('userSessionsContent');
    const tableBody = document.getElementById('sessionsTableBody');
    const userNameSpan = document.getElementById('selectedUserName');
    const sessionCount = document.getElementById('sessionCount');

    if (!contentDiv || !tableBody) return;

    // Show content and set user name
    contentDiv.style.display = 'block';
    if (userNameSpan) {
      const userSelect = document.getElementById('userSelect');
      const selectedOption = userSelect?.selectedOptions[0];
      userNameSpan.textContent = selectedOption?.textContent || 'Unknown User';
    }

    // Update session count
    if (sessionCount) {
      sessionCount.textContent = `${sessions.length} session(s)`;
    }

    // Clear existing rows
    tableBody.innerHTML = '';

    if (sessions.length === 0) {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td colspan="6" class="no-sessions">
          <div class="empty-state">
            <span class="empty-icon">📱</span>
            <p>No active sessions found</p>
            <small>This user has no current login sessions</small>
          </div>
        </td>`;
      tableBody.appendChild(row);
      return;
    }

    // Render session rows with improved styling
    sessions.forEach((session, index) => {
      const row = document.createElement('tr');
      const statusClass = session.status === 'active' ? 'status-active' : 'status-locked';
      const statusIcon = session.status === 'active' ? '🟢' : '🔒';
      
      row.innerHTML = `
        <td class="device-info">
          <div class="device-details">
            <span class="device-name">${this.formatDeviceInfo(session.deviceInfo)}</span>
            <small class="device-ip">IP: ${session.ipAddress || 'Unknown'}</small>
          </div>
        </td>
        <td class="time-info">
          <div class="time-details">
            <span class="login-time">${new Date(session.loginTime).toLocaleString()}</span>
            <small class="last-activity">Last: ${new Date(session.lastActivity).toLocaleString()}</small>
          </div>
        </td>
        <td class="status-cell">
          <span class="session-status ${statusClass}">
            ${statusIcon} ${session.status}
          </span>
        </td>
        <td class="actions-cell">
          <div class="session-actions">
            ${session.status === 'active' ? 
              `<button class="btn btn-sm btn-warning" onclick="audioPlayer.lockUserSession('${userId}', '${session._id}')" title="Lock Session">
                🔒 Lock
              </button>` :
              `<button class="btn btn-sm btn-success" onclick="audioPlayer.unlockUserSession('${userId}', '${session._id}')" title="Unlock Session">
                🔓 Unlock
              </button>`
            }
            <button class="btn btn-sm btn-danger" onclick="audioPlayer.terminateUserSession('${userId}', '${session._id}')" title="Terminate Session">
              ❌ End
            </button>
          </div>
        </td>
      `;
      tableBody.appendChild(row);
    });
  }

  formatDeviceInfo(deviceInfo) {
    if (!deviceInfo) return 'Unknown Device';
    try {
      const info = typeof deviceInfo === 'string' ? JSON.parse(deviceInfo) : deviceInfo;
      return `${info.browser || 'Unknown'} on ${info.os || 'Unknown'}`;
    } catch {
      return 'Unknown Device';
    }
  }

  async lockUserSession(userId, sessionId) {
    await this.updateSessionStatus(userId, sessionId, 'locked');
  }

  async unlockUserSession(userId, sessionId) {
    await this.updateSessionStatus(userId, sessionId, 'active');
  }

  async terminateUserSession(userId, sessionId) {
    await this.updateSessionStatus(userId, sessionId, 'terminated');
  }

  async updateSessionStatus(userId, sessionId, status) {
    try {
      const response = await fetch(`/api/admin/users/${userId}/sessions/${sessionId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        },
        body: JSON.stringify({ status })
      });

      if (response.ok) {
        this.showSuccess(`Session ${status} successfully`);
        await this.loadUserSessions(userId);
      } else {
        const result = await response.json();
        this.showError(result.error || `Failed to ${status} session`);
      }
    } catch (error) {
      this.showError('Network error occurred');
    }
  }

  async lockAllUserSessions(userId) {
    await this.bulkUpdateUserSessions(userId, 'locked');
  }

  async unlockAllUserSessions(userId) {
    await this.bulkUpdateUserSessions(userId, 'active');
  }

  async bulkUpdateUserSessions(userId, status) {
    try {
      const response = await fetch(`/api/admin/users/${userId}/sessions/bulk`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        },
        body: JSON.stringify({ status })
      });

      if (response.ok) {
        this.showSuccess(`All sessions ${status} successfully`);
        await this.loadUserSessions(userId);
      } else {
        const result = await response.json();
        this.showError(result.error || `Failed to ${status} sessions`);
      }
    } catch (error) {
      this.showError('Network error occurred');
    }
  }

  // Form validation functions
  validateCreateUserForm(userData) {
    let isValid = true;

    // Clear previous errors
    this.clearFormErrors(['usernameError', 'passwordError', 'confirmPasswordError', 'roleError']);

    // Username validation
    if (!userData.username || userData.username.length < 3) {
      this.showFormError('usernameError', 'Username must be at least 3 characters long');
      isValid = false;
    }

    // Password validation
    if (!userData.password || userData.password.length < 8) {
      this.showFormError('passwordError', 'Password must be at least 8 characters long');
      isValid = false;
    }

    // Password confirmation
    if (userData.password !== userData.confirmPassword) {
      this.showFormError('confirmPasswordError', 'Passwords do not match');
      isValid = false;
    }

    // Role validation
    if (!userData.role || !['user', 'admin'].includes(userData.role)) {
      this.showFormError('roleError', 'Please select a valid role');
      isValid = false;
    }

    return isValid;
  }

  validatePasswordChangeForm(passwordData) {
    let isValid = true;

    // Clear previous errors
    this.clearFormErrors(['currentPasswordError', 'newPasswordError', 'confirmNewPasswordError']);

    // Current password validation
    if (!passwordData.currentPassword) {
      this.showFormError('currentPasswordError', 'Current password is required');
      isValid = false;
    }

    // New password validation
    if (!passwordData.newPassword || passwordData.newPassword.length < 8) {
      this.showFormError('newPasswordError', 'New password must be at least 8 characters long');
      isValid = false;
    }

    // New password confirmation
    if (passwordData.newPassword !== passwordData.confirmNewPassword) {
      this.showFormError('confirmNewPasswordError', 'Passwords do not match');
      isValid = false;
    }

    // Check if new password is different from current
    if (passwordData.currentPassword === passwordData.newPassword) {
      this.showFormError('newPasswordError', 'New password must be different from current password');
      isValid = false;
    }

    return isValid;
  }

  showFormError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
      errorElement.textContent = message;
      errorElement.style.display = 'block';
    }
  }

  clearFormErrors(errorIds) {
    errorIds.forEach(id => {
      const errorElement = document.getElementById(id);
      if (errorElement) {
        errorElement.style.display = 'none';
        errorElement.textContent = '';
      }
    });
  }

  clearCreateUserForm() {
    const form = document.getElementById('createUserForm');
    if (form) {
      form.reset();
      this.clearFormErrors(['usernameError', 'passwordError', 'confirmPasswordError', 'roleError']);
      
      // Reset password strength indicator
      const strengthElement = document.getElementById('passwordStrength');
      if (strengthElement) {
        strengthElement.className = 'password-strength';
        const strengthBar = strengthElement.querySelector('.password-strength-bar');
        if (strengthBar) strengthBar.style.width = '0%';
      }
    }
  }

  clearPasswordChangeForm() {
    const form = document.getElementById('passwordChangeForm');
    if (form) {
      form.reset();
      this.clearFormErrors(['currentPasswordError', 'newPasswordError', 'confirmNewPasswordError']);
      
      // Reset password strength indicator
      const strengthElement = document.getElementById('newPasswordStrength');
      if (strengthElement) {
        strengthElement.className = 'password-strength';
        const strengthBar = strengthElement.querySelector('.password-strength-bar');
        if (strengthBar) strengthBar.style.width = '0%';
      }
    }
  }

  // Override the existing showCreateUserForm method
  showCreateUserForm() {
    this.showCreateUserModal();
  }


  // Placeholder methods for additional admin functionality
  editUserPermissions(userId) {
    this.showToast('Edit permissions feature coming soon', 'info');
  }


  editUser(userId) {
    this.showToast('Edit user feature coming soon', 'info');
  }

  resetUserPassword(userId) {
    this.showToast('Reset password feature coming soon', 'info');
  }

  showUploadForm() {
    this.showToast('Upload file feature coming soon', 'info');
  }

  editFileMetadata(fileId) {
    this.showToast('Edit metadata feature coming soon', 'info');
  }

  manageFileSections(fileId) {
    this.showToast('Manage sections feature coming soon', 'info');
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
