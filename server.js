const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
// ----------------------------
// Config
// ----------------------------
const app = express();
dotenv.config();
const PORT = process.env.PORT || 3000;
const MONGO_URL = process.env.MONGO_URL || "mongodb://localhost:27017/audio";
const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(48).toString("hex");
const ENC_KEY = process.env.ENC_KEY
  ? Buffer.from(process.env.ENC_KEY, "hex")
  : crypto.randomBytes(32);
const SIGNED_URL_SECRET =
  process.env.SIGNED_URL_SECRET || crypto.randomBytes(48).toString("hex");
const CHUNK_SIZE = Number(process.env.CHUNK_SIZE_BYTES || 8 * 1024 * 1024);

// ----------------------------
// Security middleware
// ----------------------------
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        mediaSrc: ["'self'", "blob:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-origin" },
    referrerPolicy: { policy: "no-referrer" },
    hidePoweredBy: true,
  })
);
app.disable("x-powered-by");

app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.json({ limit: "25mb" }));
app.use(express.static("public"));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const streamLimiter = rateLimit({ windowMs: 60 * 1000, max: 200 });

// ----------------------------
// DB (Mongoose)
// ----------------------------
mongoose.set("strictQuery", true);
mongoose
  .connect(MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected"));

const UserSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true },
    passwordHash: String,
    roles: [String],
    // New fields for user management
    isTemporaryPassword: { type: Boolean, default: false },
    mustChangePassword: { type: Boolean, default: false },
    accountStatus: { type: String, enum: ['active', 'locked', 'suspended'], default: 'active' },
    lastLogin: { type: Date },
    failedLoginAttempts: { type: Number, default: 0 },
    lockoutUntil: { type: Date },
    deviceAgreementAccepted: { type: Boolean, default: false },
    allowedDeviceFingerprint: { type: String },
    createdBy: { type: String }, // admin who created this user
  },
  { timestamps: true }
);
const User = mongoose.model("User", UserSchema);

const SectionSchema = new mongoose.Schema(
  { label: String, startTime: Number },
  { _id: false }
);

const AudioFileSchema = new mongoose.Schema(
  {
    filename: { type: String, index: true },
    contentType: { type: String, default: "audio/mpeg" },
    sizeBytes: Number,
    chunkSize: { type: Number, default: CHUNK_SIZE },
    totalChunks: Number,
    sections: [SectionSchema],
    permissions: [{ type: String, index: true }], // userId (username)
  },
  { timestamps: true }
);
const AudioFile = mongoose.model("AudioFile", AudioFileSchema);

// Encrypted chunks: AES-256-GCM (iv + authTag per chunk)
const AudioChunkSchema = new mongoose.Schema(
  {
    fileId: {
      type: mongoose.Schema.Types.ObjectId,
      index: true,
      required: true,
    },
    index: { type: Number, index: true, required: true },
    iv: Buffer, // 12 bytes recommended for GCM
    tag: Buffer, // 16 bytes auth tag
    data: Buffer, // ciphertext
    plainSize: Number, // plaintext size for this chunk
  },
  { versionKey: false }
);
AudioChunkSchema.index({ fileId: 1, index: 1 }, { unique: true });
const AudioChunk = mongoose.model("AudioChunk", AudioChunkSchema);

// Permission Management Schema
const PermissionSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true }, // username
    fileId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    grantedBy: { type: String, required: true }, // admin username who granted access
    grantedAt: { type: Date, default: Date.now },
    revokedAt: { type: Date, default: null },
    revokedBy: { type: String, default: null },
    isActive: { type: Boolean, default: true, index: true }
  },
  { timestamps: true }
);
PermissionSchema.index({ userId: 1, fileId: 1 }, { unique: true });
const Permission = mongoose.model("Permission", PermissionSchema);

// Audit Log Schema for tracking permission changes
const AuditLogSchema = new mongoose.Schema(
  {
    action: { type: String, required: true, enum: ['grant', 'revoke'], index: true },
    userId: { type: String, required: true, index: true }, // target user
    fileId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    filename: { type: String, required: true }, // for easier reading
    performedBy: { type: String, required: true }, // admin who performed the action
    timestamp: { type: Date, default: Date.now, index: true },
    details: { type: String } // optional additional details
  },
  { timestamps: true }
);
AuditLogSchema.index({ timestamp: -1 }); // for efficient querying by date
const AuditLog = mongoose.model("AuditLog", AuditLogSchema);

const UserSessionSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true },
    deviceFingerprint: { type: String, required: true },
    deviceInfo: {
      browser: String,
      os: String,
      screen: String,
      timezone: String,
      language: String,
      userAgent: String
    },
    ipAddress: { type: String, required: true },
    loginTime: { type: Date, default: Date.now },
    lastActivity: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    sessionToken: { type: String, unique: true },
    status: { type: String, enum: ['active', 'locked', 'terminated'], default: 'active' }
  },
  { timestamps: true }
);
UserSessionSchema.index({ userId: 1, deviceFingerprint: 1 });
const UserSession = mongoose.model("UserSession", UserSessionSchema);

const PasswordChangeLogSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, index: true },
    changedBy: { type: String, required: true }, // 'self' or admin username
    reason: { type: String, enum: ['forced', 'voluntary', 'reset'], required: true },
    timestamp: { type: Date, default: Date.now }
  },
  { timestamps: true }
);
const PasswordChangeLog = mongoose.model("PasswordChangeLog", PasswordChangeLogSchema);

// ----------------------------
// Permission checking utilities
// ----------------------------
async function hasFileAccess(userId, fileId) {
  try {
    // Check new Permission schema first
    const permission = await Permission.findOne({
      userId: userId,
      fileId: fileId,
      isActive: true,
      revokedAt: null
    });
    
    if (permission) {
      return true;
    }
    
    // Fallback to legacy permissions array in AudioFile
    const audioFile = await AudioFile.findById(fileId);
    if (audioFile && audioFile.permissions.includes(userId)) {
      return true;
    }
    
    return false;
  } catch (error) {
    console.error('Error checking file access:', error);
    return false;
  }
}

// ----------------------------
// JWT utilities
// ----------------------------
function signJWT(payload, expiresIn = "30m") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "no token" });
  
  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) return res.status(403).json({ error: "invalid token" });
    
    try {
      // Check if user still exists and account is active
      const user = await User.findOne({ username: decoded.userId });
      if (!user) {
        return res.status(401).json({ error: "user not found" });
      }
      
      if (user.accountStatus !== 'active') {
        return res.status(403).json({ 
          error: "Account is not active",
          accountStatus: user.accountStatus
        });
      }
      
      // For non-admin users, validate device session
      if (!user.roles.includes('admin') && decoded.deviceFingerprint) {
        const session = await UserSession.findOne({
          userId: decoded.userId,
          deviceFingerprint: decoded.deviceFingerprint,
          status: 'active'
        });
        
        if (!session) {
          return res.status(403).json({ 
            error: "Invalid or terminated session",
            sessionTerminated: true
          });
        }
        
        // Update last activity
        await UserSession.findByIdAndUpdate(session._id, {
          lastActivity: new Date()
        });
      }
      
      // Fix: Use userId instead of username to match endpoint expectations
      req.user = { userId: decoded.userId, roles: user.roles };
      next();
    } catch (error) {
      console.error("Auth middleware error:", error);
      return res.status(500).json({ error: "authentication error" });
    }
  });
}
// --- Helper to convert BSON Binary to Node Buffer ---
function toBuffer(b) {
  if (!b) return null;
  if (Buffer.isBuffer(b)) return b;
  if (b.buffer) return Buffer.from(b.buffer, b.byteOffset, b.length);
  return Buffer.from(b);
}

app.get("/", authenticateToken, async (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { username, password, deviceFingerprint, deviceInfo } = req.body || {};
    
    if (!username || !password) {
      return res.status(400).json({ error: "username & password required" });
    }

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "invalid credentials" });
    }

    // Check account status
    if (user.accountStatus === 'locked') {
      return res.status(403).json({ 
        error: "Account is locked. Contact administrator.",
        accountLocked: true
      });
    }

    if (user.accountStatus === 'suspended') {
      return res.status(403).json({ 
        error: "Account is suspended. Contact administrator.",
        accountSuspended: true
      });
    }

    // Check for account lockout due to failed attempts
    if (user.lockoutUntil && user.lockoutUntil > new Date()) {
      return res.status(423).json({ 
        error: "Account temporarily locked due to failed login attempts. Try again later.",
        lockoutUntil: user.lockoutUntil
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      // Increment failed login attempts
      const failedAttempts = (user.failedLoginAttempts || 0) + 1;
      const updateData = { failedLoginAttempts: failedAttempts };
      
      // Lock account after 5 failed attempts for 15 minutes
      if (failedAttempts >= 5) {
        updateData.lockoutUntil = new Date(Date.now() + 15 * 60 * 1000);
      }
      
      await User.findByIdAndUpdate(user._id, updateData);
      return res.status(401).json({ error: "invalid credentials" });
    }

    // Reset failed login attempts on successful password verification
    await User.findByIdAndUpdate(user._id, {
      failedLoginAttempts: 0,
      lockoutUntil: null,
      lastLogin: new Date()
    });

    // Check if password change is required
    if (user.mustChangePassword || user.isTemporaryPassword) {
      return res.status(200).json({
        success: false,
        requirePasswordChange: true,
        isTemporaryPassword: user.isTemporaryPassword,
        message: user.isTemporaryPassword 
          ? "You must change your temporary password before accessing the system."
          : "Password change required.",
        user: { username: user.username, roles: user.roles }
      });
    }

    // Device validation for non-admin users
    if (!user.roles.includes('admin') && deviceFingerprint && deviceInfo) {
      // Check if device agreement is required
      if (!user.deviceAgreementAccepted) {
        return res.status(200).json({
          success: false,
          requireDeviceAgreement: true,
          deviceInfo: deviceInfo,
          message: "Please confirm single-device access policy.",
          user: { username: user.username, roles: user.roles }
        });
      }

      // Check if this is a different device
      if (user.allowedDeviceFingerprint && user.allowedDeviceFingerprint !== deviceFingerprint) {
        // Lock account due to different device access
        await User.findByIdAndUpdate(user._id, {
          accountStatus: 'locked'
        });
        
        // Terminate all existing sessions
        await UserSession.updateMany(
          { userId: user.username, status: 'active' },
          { status: 'terminated' }
        );

        return res.status(403).json({
          error: "Account locked due to access from unauthorized device. Contact administrator.",
          deviceViolation: true,
          accountLocked: true
        });
      }

      // Create or update user session
      const sessionToken = crypto.randomBytes(32).toString('hex');
      await UserSession.findOneAndUpdate(
        { userId: user.username, deviceFingerprint },
        {
          deviceInfo,
          ipAddress: req.ip || req.connection.remoteAddress,
          loginTime: new Date(),
          lastActivity: new Date(),
          isActive: true,
          sessionToken,
          status: 'active'
        },
        { upsert: true }
      );
    }

    // Generate JWT token
    const token = signJWT({ 
      userId: user.username,
      deviceFingerprint: deviceFingerprint || null
    }, "30m");

    res.json({
      success: true,
      token,
      user: { 
        username: user.username, 
        roles: user.roles,
        accountStatus: user.accountStatus,
        deviceAgreementAccepted: user.deviceAgreementAccepted
      },
      expiresIn: 1800,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "server error" });
  }
});

app.post("/api/auth/refresh", authenticateToken, async (req, res) => {
  try {
    // Get user from the authenticated token
    const u = await User.findOne({ username: req.user.userId });
    if (!u) return res.status(401).json({ error: "user not found" });
    
    // Generate new token with fresh 30-minute expiry
    const newToken = signJWT({ userId: u.username }, "30m");
    
    res.json({
      success: true,
      token: newToken,
      user: { username: u.username, roles: u.roles },
      expiresIn: 1800,
      message: "Session extended successfully"
    });
  } catch (e) {
    console.error("Refresh token error:", e);
    res.status(500).json({ error: "server error" });
  }
});

app.post("/api/auth/logout", authenticateToken, async (req, res) => {
  try {
    // In a more sophisticated implementation, you might maintain a blacklist of tokens
    // For now, we'll just acknowledge the logout request
    res.json({
      success: true,
      message: "Logged out successfully"
    });
  } catch (e) {
    console.error("Logout error:", e);
    res.status(500).json({ error: "server error" });
  }
});

// Check login requirements endpoint
app.post("/api/auth/check-requirements", async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({ error: "Username required" });
    }
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    
    res.json({
      requirePasswordChange: user.mustChangePassword || user.isTemporaryPassword,
      requireDeviceAgreement: !user.deviceAgreementAccepted && !user.roles.includes('admin'),
      accountStatus: user.accountStatus,
      isTemporaryPassword: user.isTemporaryPassword
    });
  } catch (error) {
    console.error("Check requirements error:", error);
    res.status(500).json({ error: "server error" });
  }
});

// ----------------------------
// Crypto helpers (AES‑256‑GCM per chunk)
// ----------------------------
// --- Encryption helpers ---
function encryptChunkGCM(buffer, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, tag, data: encrypted, plainSize: buffer.length };
}

function decryptChunkGCM(chunk, key) {
  const iv = toBuffer(chunk.iv);
  const tag = toBuffer(chunk.tag);
  const data = toBuffer(chunk.data);
  console.log("Decrypting chunk with key:", key.toString("hex"));
  if (!iv || !tag || !data) throw new Error("Invalid chunk data");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ----------------------------
// Ingest: read ./assets/<filename>, encrypt into chunks
// ----------------------------
app.post("/api/admin/ingest", authenticateToken, async (req, res) => {
  try {
    // simple gate: allow if user has role admin
    const me = await User.findOne({ username: req.user.userId });
    if (!me || !me.roles?.includes("admin"))
      return res.status(403).json({ error: "admin only" });

    const {
      filename,
      sections = [],
      permissions = [req.user.userId],
      contentType = "audio/mpeg",
    } = req.body || {};
    if (!filename) return res.status(400).json({ error: "filename required" });

    const full = path.resolve("./assets/" + filename);
    if (!fs.existsSync(full))
      return res.status(404).json({ error: "file not found on server" });

    // remove old entries if re-ingesting
    await AudioFile.deleteMany({ filename });

    const sizeBytes = fs.statSync(full).size;
    const meta = await AudioFile.create({
      filename,
      contentType,
      sizeBytes,
      chunkSize: CHUNK_SIZE,
      totalChunks: 0,
      sections,
      permissions,
    });

    const fd = fs.openSync(full, "r");
    let offset = 0,
      index = 0;
    const buf = Buffer.alloc(CHUNK_SIZE);

    while (offset < sizeBytes) {
      const toRead = Math.min(CHUNK_SIZE, sizeBytes - offset);
      const { bytesRead } = fs.readSync(fd, buf, 0, toRead, offset);
      const slice = Buffer.from(buf.subarray(0, bytesRead));
      const { iv, enc, tag } = encryptChunkGCM(slice);
      await AudioChunk.create({
        fileId: meta._id,
        index,
        iv,
        tag,
        data: enc,
        plainSize: slice.length,
      });
      offset += bytesRead;
      index += 1;
    }
    fs.closeSync(fd);

    meta.totalChunks = index;
    await meta.save();

    res.json({
      success: true,
      fileId: meta._id,
      totalChunks: meta.totalChunks,
      sizeBytes,
    });
  } catch (e) {
    console.error("ingest error", e);
    res.status(500).json({ error: "ingest failed" });
  }
});

// ----------------------------
// Admin Permission Management APIs
// ----------------------------

// Get all users (admin only)
app.get("/api/admin/users", authenticateToken, async (req, res) => {
  try {
    const me = await User.findOne({ username: req.user.userId });
    if (!me || !me.roles?.includes("admin"))
      return res.status(403).json({ error: "admin only" });

    const users = await User.find({}).select("username roles createdAt");
    res.json({ users });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

// Get all files (admin only)
app.get("/api/admin/files", authenticateToken, async (req, res) => {
  try {
    const me = await User.findOne({ username: req.user.userId });
    if (!me || !me.roles?.includes("admin"))
      return res.status(403).json({ error: "admin only" });

    const files = await AudioFile.find({}).select("filename sizeBytes totalChunks sections permissions createdAt");
    res.json({ files });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

// Get all permissions (admin only)
app.get("/api/admin/permissions", authenticateToken, async (req, res) => {
  try {
    const me = await User.findOne({ username: req.user.userId });
    if (!me || !me.roles?.includes("admin"))
      return res.status(403).json({ error: "admin only" });

    const permissions = await Permission.find({ isActive: true })
      .populate('fileId', 'filename')
      .sort({ grantedAt: -1 });
    
    res.json({ permissions });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

// Grant permission to user for specific file (admin only)
app.post("/api/admin/permissions/grant", authenticateToken, async (req, res) => {
  try {
    const me = await User.findOne({ username: req.user.userId });
    if (!me || !me.roles?.includes("admin"))
      return res.status(403).json({ error: "admin only" });

    const { userId, fileId } = req.body;
    if (!userId || !fileId)
      return res.status(400).json({ error: "userId and fileId required" });

    // Check if user exists
    const user = await User.findOne({ username: userId });
    if (!user)
      return res.status(404).json({ error: "user not found" });

    // Check if file exists
    const file = await AudioFile.findById(fileId);
    if (!file)
      return res.status(404).json({ error: "file not found" });

    // Check if permission already exists
    let permission = await Permission.findOne({ userId, fileId });
    
    if (permission) {
      if (permission.isActive) {
        return res.status(400).json({ error: "permission already exists" });
      }
      // Reactivate revoked permission
      permission.isActive = true;
      permission.grantedBy = req.user.userId;
      permission.grantedAt = new Date();
      permission.revokedAt = null;
      permission.revokedBy = null;
      await permission.save();
    } else {
      // Create new permission
      permission = await Permission.create({
        userId,
        fileId,
        grantedBy: req.user.userId
      });
    }

    // Also update the legacy permissions array in AudioFile
    if (!file.permissions.includes(userId)) {
      file.permissions.push(userId);
      await file.save();
    }

    // Log the permission grant action
    await AuditLog.create({
      action: 'grant',
      userId,
      fileId,
      filename: file.filename,
      performedBy: req.user.userId,
      details: permission.isActive ? 'Permission reactivated' : 'New permission granted'
    });

    res.json({ success: true, permission });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

// Revoke permission from user for specific file (admin only)
app.delete("/api/admin/permissions/revoke", authenticateToken, async (req, res) => {
  try {
    const me = await User.findOne({ username: req.user.userId });
    if (!me || !me.roles?.includes("admin"))
      return res.status(403).json({ error: "admin only" });

    const { userId, fileId } = req.body;
    if (!userId || !fileId)
      return res.status(400).json({ error: "userId and fileId required" });

    // Find and revoke permission
    const permission = await Permission.findOne({ userId, fileId, isActive: true });
    if (!permission)
      return res.status(404).json({ error: "active permission not found" });

    permission.isActive = false;
    permission.revokedAt = new Date();
    permission.revokedBy = req.user.userId;
    await permission.save();

    // Also update the legacy permissions array in AudioFile
    const file = await AudioFile.findById(fileId);
    if (file) {
      file.permissions = file.permissions.filter(p => p !== userId);
      await file.save();
    }

    // Log the permission revoke action
    await AuditLog.create({
      action: 'revoke',
      userId,
      fileId,
      filename: file ? file.filename : 'Unknown file',
      performedBy: req.user.userId,
      details: 'Permission revoked'
    });

    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

// Get audit logs (admin only)
app.get("/api/admin/audit-logs", authenticateToken, async (req, res) => {
  try {
    const me = await User.findOne({ username: req.user.userId });
    if (!me || !me.roles?.includes("admin"))
      return res.status(403).json({ error: "admin only" });

    const { page = 1, limit = 50, action, userId, fileId } = req.query;
    const skip = (page - 1) * limit;
    
    // Build filter
    const filter = {};
    if (action) filter.action = action;
    if (userId) filter.userId = userId;
    if (fileId) filter.fileId = fileId;

    const logs = await AuditLog.find(filter)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const total = await AuditLog.countDocuments(filter);

    res.json({
      logs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

// Create new user endpoint
app.post("/api/admin/users/create", authenticateToken, async (req, res) => {
  try {
    if (!req.user.roles.includes("admin")) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { username, temporaryPassword, role } = req.body;

    if (!username || !temporaryPassword || !role) {
      return res.status(400).json({ error: "Username, temporary password, and role are required" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ error: "User already exists" });
    }

    // Validate role
    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ error: "Invalid role. Must be 'user' or 'admin'" });
    }

    // Hash the temporary password
    const passwordHash = await bcrypt.hash(temporaryPassword, 10);

    // Create new user
    const newUser = await User.create({
      username,
      passwordHash,
      roles: [role],
      isTemporaryPassword: true,
      mustChangePassword: true,
      accountStatus: 'active',
      createdBy: req.user.username
    });

    res.json({ 
      message: "User created successfully", 
      user: {
        id: newUser._id,
        username: newUser.username,
        roles: newUser.roles,
        accountStatus: newUser.accountStatus,
        mustChangePassword: newUser.mustChangePassword
      }
    });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Failed to create user" });
  }
});

// Change password endpoint
app.post("/api/auth/change-password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: "All password fields are required" });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: "New passwords do not match" });
    }

    // Get user
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword, 10);

    // Update user
    await User.findByIdAndUpdate(user._id, {
      passwordHash: newPasswordHash,
      isTemporaryPassword: false,
      mustChangePassword: false
    });

    // Log password change
    await PasswordChangeLog.create({
      userId: user.username,
      changedBy: 'self',
      reason: user.mustChangePassword ? 'forced' : 'voluntary'
    });

    res.json({ message: "Password changed successfully" });
  } catch (error) {
    console.error("Error changing password:", error);
    res.status(500).json({ error: "Failed to change password" });
  }
});

// Device agreement endpoint
app.post("/api/auth/device-agreement", authenticateToken, async (req, res) => {
  try {
    const { deviceFingerprint, deviceInfo, agreed } = req.body;

    if (!deviceFingerprint || !deviceInfo || agreed === undefined) {
      return res.status(400).json({ error: "Device fingerprint, device info, and agreement status are required" });
    }

    if (!agreed) {
      return res.status(400).json({ error: "Device agreement must be accepted" });
    }

    // Update user with device agreement
    await User.findOneAndUpdate(
      { username: req.user.username },
      {
        deviceAgreementAccepted: true,
        allowedDeviceFingerprint: deviceFingerprint
      }
    );

    // Create or update user session
    await UserSession.findOneAndUpdate(
      { userId: req.user.username, deviceFingerprint },
      {
        deviceInfo,
        ipAddress: req.ip,
        lastActivity: new Date(),
        isActive: true,
        status: 'active'
      },
      { upsert: true }
    );

    res.json({ message: "Device agreement accepted successfully" });
  } catch (error) {
    console.error("Error processing device agreement:", error);
    res.status(500).json({ error: "Failed to process device agreement" });
  }
});

// Get user sessions for admin
app.get("/api/admin/users/:userId/sessions", authenticateToken, async (req, res) => {
  try {
    if (!req.user.roles.includes("admin")) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { userId } = req.params;
    const sessions = await UserSession.find({ userId }).sort({ lastActivity: -1 });

    res.json({ sessions });
  } catch (error) {
    console.error("Error fetching user sessions:", error);
    res.status(500).json({ error: "Failed to fetch user sessions" });
  }
});

// Update session status
app.patch("/api/admin/sessions/:sessionId/status", authenticateToken, async (req, res) => {
  try {
    if (!req.user.roles.includes("admin")) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { sessionId } = req.params;
    const { status } = req.body;

    if (!['active', 'locked', 'terminated'].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    await UserSession.findByIdAndUpdate(sessionId, { status });

    res.json({ message: "Session status updated successfully" });
  } catch (error) {
    console.error("Error updating session status:", error);
    res.status(500).json({ error: "Failed to update session status" });
  }
});

// Lock/unlock user account
app.patch("/api/admin/users/:userId/status", authenticateToken, async (req, res) => {
  try {
    if (!req.user.roles.includes("admin")) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { userId } = req.params;
    const { accountStatus } = req.body;

    if (!['active', 'locked', 'suspended'].includes(accountStatus)) {
      return res.status(400).json({ error: "Invalid account status" });
    }

    await User.findOneAndUpdate(
      { username: userId },
      { accountStatus }
    );

    // If locking account, terminate all active sessions
    if (accountStatus === 'locked' || accountStatus === 'suspended') {
      await UserSession.updateMany(
        { userId, status: 'active' },
        { status: 'terminated' }
      );
    }

    res.json({ message: "User account status updated successfully" });
  } catch (error) {
    console.error("Error updating user status:", error);
    res.status(500).json({ error: "Failed to update user status" });
  }
});

// ----------------------------
// Metadata & listing
// ----------------------------
app.get("/api/audio/list", authenticateToken, async (req, res) => {
  try {
    // Get all audio files
    const allFiles = await AudioFile.find({}).select(
      "filename sizeBytes totalChunks sections"
    );
    
    // Filter files based on user permissions
    const accessibleFiles = [];
    for (const file of allFiles) {
      const hasAccess = await hasFileAccess(req.user.userId, file._id);
      if (hasAccess) {
        accessibleFiles.push(file);
      }
    }
    
    res.json({ files: accessibleFiles });
  } catch (error) {
    console.error('Error listing audio files:', error);
    res.status(500).json({ error: 'server error' });
  }
});

app.get("/api/audio/:id/metadata", authenticateToken, async (req, res) => {
  try {
    const meta = await AudioFile.findById(req.params.id);
    if (!meta) return res.status(404).json({ error: "not found" });
    
    const hasAccess = await hasFileAccess(req.user.userId, meta._id);
    if (!hasAccess) {
      return res.status(403).json({ error: "no access" });
    }
    
    res.json({
      _id: meta._id,
      filename: meta.filename,
      contentType: meta.contentType,
      sizeBytes: meta.sizeBytes,
      chunkSize: meta.chunkSize,
      totalChunks: meta.totalChunks,
      sections: meta.sections,
    });
  } catch (error) {
    console.error('Error getting audio metadata:', error);
    res.status(500).json({ error: 'server error' });
  }
});

// ----------------------------
// Signed URL utilities
// ----------------------------
function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}
function hmacSign(parts) {
  const msg = parts.join("|");
  return b64url(
    crypto.createHmac("sha256", SIGNED_URL_SECRET).update(msg).digest()
  );
}
function verifySignature({ fileRef, start, end, expires, ip, sig }) {
  const expected = hmacSign([
    String(fileRef),
    String(start),
    String(end),
    String(expires),
    String(ip || "-"),
  ]);
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

// Create a signed URL for a specific byte range (client can omit range for full file)
app.post("/api/audio/:id/signed-url", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      start = 0,
      end = -1,
      ttlSeconds = 300,
      bindIp = true,
    } = req.body || {};
    
    const meta = await AudioFile.findById(id);
    if (!meta) return res.status(404).json({ error: "not found" });
    
    const hasAccess = await hasFileAccess(req.user.userId, meta._id);
    if (!hasAccess) {
      return res.status(403).json({ error: "no access" });
    }
    
    const expires = Date.now() + Math.max(1, Math.min(3600, ttlSeconds)) * 1000;
    const ip = bindIp ? req.ip || "-" : "-";
    const sig = hmacSign([id, start, end, expires, ip]);
    // Client calls GET /api/audio/:id/stream-signed?start=&end=&expires=&sig=
    res.json({
      url: `/api/audio/${id}/stream-signed?start=${start}&end=${end}&expires=${expires}&sig=${sig}`,
    });
  } catch (error) {
    console.error('Error creating signed URL:', error);
    res.status(500).json({ error: 'server error' });
  }
});

// ----------------------------
// Core streaming logic (decrypt only needed chunks)
// ----------------------------
// async function streamDecryptedRange({ res, meta, start, end }) {
//   const fileSize = meta.sizeBytes;
//   const startChunk = Math.floor(start / meta.chunkSize);
//   const endChunk = Math.floor(end / meta.chunkSize);

//   for (let idx = startChunk; idx <= endChunk; idx++) {
//     const doc = await AudioChunk.findOne(
//       { fileId: meta._id, index: idx },
//       { data: 1, iv: 1, tag: 1, plainSize: 1 }
//     ).lean();
//     if (!doc) throw new Error(`missing chunk ${idx}`);
//     const plain = decryptChunkGCM(doc.data, doc.iv, doc.tag);

//     const chunkStartByte = idx * meta.chunkSize;
//     const sliceStart = Math.max(0, start - chunkStartByte);
//     const sliceEnd = Math.min(plain.length - 1, end - chunkStartByte);
//     const slice = plain.subarray(sliceStart, sliceEnd + 1);

//     if (slice.length) {
//       const ok = res.write(slice);
//       if (!ok) await new Promise((r) => res.once("drain", r));
//     }
//   }
// }
async function streamDecryptedRange({ res, meta, start, end, key }) {
  const startChunk = Math.floor(start / meta.chunkSize);
  const endChunk = Math.floor(end / meta.chunkSize);

  for (let idx = startChunk; idx <= endChunk; idx++) {
    const doc = await AudioChunk.findOne(
      { fileId: meta._id, index: idx },
      { data: 1, iv: 1, tag: 1, plainSize: 1 }
    ).lean();
    if (!doc) throw new Error(`Missing chunk ${idx}`);

    // Proper buffer conversion + decryption
    const plain = decryptChunkGCM(doc, key);

    // Compute slice offsets
    const chunkStartByte = idx * meta.chunkSize;
    const sliceStart = Math.max(0, start - chunkStartByte);
    const sliceEnd = Math.min(plain.length, end - chunkStartByte + 1);
    const slice = plain.subarray(sliceStart, sliceEnd);

    if (slice.length) {
      const ok = res.write(slice);
      if (!ok) await new Promise((r) => res.once("drain", r));
    }
  }
}

function setRangeHeaders(res, { status, start, end, fileSize, contentType }) {
  res.status(status);
  res.set({
    "Content-Type": contentType || "audio/mpeg",
    "Accept-Ranges": "bytes",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    Pragma: "no-cache",
    Expires: "0",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    ...(status === 206
      ? {
          "Content-Range": `bytes ${start}-${end}/${fileSize}`,
          "Content-Length": end - start + 1,
        }
      : { "Content-Length": fileSize }),
  });
}

// ----------------------------
// KEEP ORIGINAL ROUTE: /api/audio/:filename/stream  (auth header)
// ----------------------------
app.get(
  "/api/audio/:filename/stream",
  streamLimiter,
  authenticateToken,
  async (req, res) => {
    try {
      const { filename } = req.params;
      const meta = await AudioFile.findOne({ filename });
      if (!meta) return res.status(404).json({ error: "Audio file not found" });
      
      const hasAccess = await hasFileAccess(req.user.userId, meta._id);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      const fileSize = meta.sizeBytes;
      const range = req.headers.range;
      let start = 0,
        end = fileSize - 1;

      if (range) {
        const [s, e] = range.replace(/bytes=/, "").split("-");
        start = parseInt(s, 10);
        end = e ? parseInt(e, 10) : end;
        if (isNaN(start) || isNaN(end) || start > end || end >= fileSize) {
          return res
            .status(416)
            .set({ "Content-Range": `bytes */${fileSize}` })
            .end();
        }
        setRangeHeaders(res, {
          status: 206,
          start,
          end,
          fileSize,
          contentType: meta.contentType,
        });
      } else {
        setRangeHeaders(res, {
          status: 200,
          start,
          end,
          fileSize,
          contentType: meta.contentType,
        });
      }

      await streamDecryptedRange({ res, meta, start, end, ENC_KEY });
      res.end();
    } catch (e) {
      console.error("/filename/stream error", e);
      if (!res.headersSent) res.status(500).json({ error: "stream failed" });
      else res.end();
    }
  }
);

// ----------------------------
// NEW: ID route with auth header (convenience)
// ----------------------------
app.get(
  "/api/audio/:id/stream",
  streamLimiter,
  authenticateToken,
  async (req, res) => {
    try {
      const meta = await AudioFile.findById(req.params.id);
      if (!meta) return res.status(404).json({ error: "not found" });
      
      const hasAccess = await hasFileAccess(req.user.userId, meta._id);
      if (!hasAccess) {
        return res.status(403).json({ error: "no access" });
      }

      const fileSize = meta.sizeBytes;
      const range = req.headers.range;
      let start = 0,
        end = fileSize - 1;

      if (range) {
        const [s, e] = range.replace(/bytes=/, "").split("-");
        start = parseInt(s, 10);
        end = e ? parseInt(e, 10) : end;
        if (isNaN(start) || isNaN(end) || start > end || end >= fileSize) {
          return res
            .status(416)
            .set({ "Content-Range": `bytes */${fileSize}` })
            .end();
        }
        setRangeHeaders(res, {
          status: 206,
          start,
          end,
          fileSize,
          contentType: meta.contentType,
        });
      } else {
        setRangeHeaders(res, {
          status: 200,
          start,
          end,
          fileSize,
          contentType: meta.contentType,
        });
      }

      await streamDecryptedRange({ res, meta, start, end });
      res.end();
    } catch (e) {
      console.error("/id/stream error", e);
      if (!res.headersSent) res.status(500).json({ error: "stream failed" });
      else res.end();
    }
  }
);

// ----------------------------
// NEW: Signed URL route (no JWT in request)
// ----------------------------
app.get("/api/audio/:id/stream-signed", streamLimiter, async (req, res) => {
  try {
    const { id } = req.params;
    const { start = "0", end = "-1", expires, sig } = req.query;
    if (!expires || !sig)
      return res.status(400).json({ error: "missing signed parameters" });

    const now = Date.now();
    const exp = parseInt(expires, 10);
    if (!exp || now > exp)
      return res.status(403).json({ error: "link expired" });

    const meta = await AudioFile.findById(id);
    if (!meta) return res.status(404).json({ error: "not found" });

    // Verify signature (IP bound)
    const s = String(start),
      e = String(end);
    const ok = verifySignature({
      fileRef: id,
      start: s,
      end: e,
      expires: exp,
      ip: req.ip,
      sig,
    });
    if (!ok) return res.status(403).json({ error: "invalid signature" });

    const fileSize = meta.sizeBytes;
    let a = parseInt(s, 10);
    let b = e === "-1" ? fileSize - 1 : parseInt(e, 10);
    if (isNaN(a) || isNaN(b) || a < 0 || b >= fileSize || a > b) {
      return res
        .status(416)
        .set({ "Content-Range": `bytes */${fileSize}` })
        .end();
    }

    // NOTE: Range header is ignored on signed URLs; start/end come from the query params
    setRangeHeaders(res, {
      status: a === 0 && b === fileSize - 1 ? 200 : 206,
      start: a,
      end: b,
      fileSize,
      contentType: meta.contentType,
    });
    await streamDecryptedRange({ res, meta, start: a, end: b, key: ENC_KEY });
    res.end();
  } catch (e) {
    console.error("/stream-signed error", e);
    if (!res.headersSent) res.status(500).json({ error: "stream failed" });
    else res.end();
  }
});

// ----------------------------
// Sections helper (jump points by seconds; client seeks accordingly)
// ----------------------------
app.get("/api/audio/:id/section", authenticateToken, async (req, res) => {
  try {
    const meta = await AudioFile.findById(req.params.id);
    if (!meta) return res.status(404).json({ error: "not found" });
    
    const hasAccess = await hasFileAccess(req.user.userId, meta._id);
    if (!hasAccess) {
      return res.status(403).json({ error: "no access" });
    }
    
    const sec = meta.sections.find((s) => s.label === req.query.label);
    if (!sec) return res.status(404).json({ error: "section not found" });
    res.json({ startTime: sec.startTime });
  } catch (error) {
    console.error('Error getting section:', error);
    res.status(500).json({ error: 'server error' });
  }
});

// ----------------------------
// Dev seed (optional): admin user
// ----------------------------
(async () => {
  if (!(await User.findOne({ username: "admin" }))) {
    const passwordHash = await bcrypt.hash("SecureAudio2025", 10);
    await User.create({ username: "admin", passwordHash, roles: ["admin"] });
    console.log("👤 Seeded admin / SecureAudio2025");

    // Clear collections
    await User.deleteMany({});
    await AudioFile.deleteMany({});
    await AudioChunk.deleteMany({});

    // Seed users
    const adminHash = await bcrypt.hash("SecureAudio2025", 10);
    const userHash = await bcrypt.hash("UserPass2025", 10);

    const admin = await User.create({
      username: "admin",
      passwordHash: adminHash,
      roles: ["admin"],
    });

    const user1 = await User.create({
      username: "user1",
      passwordHash: userHash,
      roles: ["user"],
    });

    console.log("✅ Users seeded");

    // // Seed audio files (example from old static AUDIO_FILES)
    // const filesToSeed = [
    //   {
    //     filename: "voice.mp3",
    //     path: path.resolve("./assets/voice.mp3"),
    //     permissions: ["admin", "user1"],
    //     sections: [
    //       { label: "Introduction", startTime: 0 },
    //       { label: "Topic 1", startTime: 240 },
    //       { label: "Topic 2", startTime: 1200 },
    //       { label: "Conclusion", startTime: 2100 },
    //     ],
    //   },
    //   {
    //     filename: "BY WAY OF ACCIDENT.mp3",
    //     path: path.resolve("./assets/BY WAY OF ACCIDENT.mp3"),
    //     permissions: ["admin"],
    //     sections: [
    //       { label: "Opening Credits", startTime: 0 },
    //       { label: "Acknowledgements", startTime: 14 },
    //       { label: "Foreword", startTime: 222 },
    //       { label: "Introduction", startTime: 2726 },
    //       { label: "Notes", startTime: 3554 },

    //       // Chapters
    //       { label: "Chapter 1", startTime: 3663 },
    //       { label: "Chapter 2", startTime: 6148 },
    //       { label: "Chapter 3", startTime: 9026 },
    //       { label: "Chapter 4", startTime: 10987 },
    //       { label: "Chapter 5", startTime: 13626 },
    //       { label: "Chapter 6", startTime: 15516 },
    //       { label: "Chapter 7", startTime: 18234 },
    //       { label: "Chapter 8", startTime: 20920 },
    //       { label: "Chapter 9", startTime: 24280 },
    //       { label: "Chapter 10", startTime: 26298 },
    //       { label: "Chapter 11", startTime: 28293 },
    //       { label: "Chapter 12", startTime: 31875 },
    //       { label: "Chapter 13", startTime: 34156 },
    //       { label: "Chapter 14", startTime: 36520 },
    //       { label: "Chapter 15", startTime: 38745 },
    //       { label: "Chapter 16", startTime: 40818 },
    //       { label: "Chapter 17", startTime: 43279 },
    //       { label: "Chapter 18", startTime: 45397 },
    //       { label: "Chapter 19", startTime: 47568 },
    //       { label: "Chapter 20", startTime: 49737 },

    //       // Closing Sections
    //       { label: "Epilogue", startTime: 51820 },
    //       { label: "Closing Credits", startTime: 52550 },
    //       { label: "The End", startTime: 52567 },
    //     ],
    //   },
    // ];

    // for (const f of filesToSeed) {
    //   if (!fs.existsSync(f.path)) {
    //     console.warn(`⚠️ Skipping ${f.filename}, file not found`);
    //     continue;
    //   }

    //   const stat = fs.statSync(f.path);
    //   const totalChunks = Math.ceil(stat.size / CHUNK_SIZE);

    //   const audioDoc = await AudioFile.create({
    //     filename: f.filename,
    //     sizeBytes: stat.size,
    //     chunkSize: CHUNK_SIZE,
    //     totalChunks,
    //     sections: f.sections,
    //     permissions: f.permissions,
    //   });

    //   // Chunk + encrypt
    //   const fd = fs.openSync(f.path, "r");
    //   for (let i = 0; i < totalChunks; i++) {
    //     const start = i * CHUNK_SIZE;
    //     const end = Math.min(stat.size, start + CHUNK_SIZE);
    //     const size = end - start;
    //     const buffer = Buffer.alloc(size);
    //     fs.readSync(fd, buffer, 0, size, start);

    //     const iv = crypto.randomBytes(12); // 96-bit for GCM
    //     const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
    //     const encrypted = Buffer.concat([
    //       cipher.update(buffer),
    //       cipher.final(),
    //     ]);
    //     const tag = cipher.getAuthTag();

    //     await AudioChunk.create({
    //       fileId: audioDoc._id,
    //       index: i,
    //       iv,
    //       tag,
    //       data: encrypted,
    //       plainSize: size,
    //     });

    //     process.stdout.write(`Chunk ${i + 1}/${totalChunks} seeded…\\r`);
    //   }
    //   fs.closeSync(fd);

    //   console.log(`\\n✅ Seeded ${f.filename} (${totalChunks} chunks)`);
    // }
  }
  //await mongoose.disconnect();
  console.log("🎉 Seeding complete!");
})();

// ----------------------------
// Error handling
// ----------------------------
app.use((err, req, res, next) => {
  console.error("Unhandled error", err);
  res.status(500).json({ error: "internal error" });
});

app.listen(PORT, () => console.log(`🔒 Server listening on :${PORT}`));
