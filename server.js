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

// ----------------------------
// Auth
// ----------------------------
function signJWT(payload, expiresIn = "30m") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "token required" });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "invalid/expired token" });
    req.user = { userId: decoded.userId };
    next();
  });
}
// --- Helper to convert BSON Binary to Node Buffer ---
function toBuffer(b) {
  if (!b) return null;
  if (Buffer.isBuffer(b)) return b;
  if (b.buffer) return Buffer.from(b.buffer, b.byteOffset, b.length);
  return Buffer.from(b);
}
app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password)
      return res.status(400).json({ error: "username & password required" });
    const u = await User.findOne({ username });
    if (!u) return res.status(401).json({ error: "invalid credentials" });
    const ok = await bcrypt.compare(password, u.passwordHash);
    if (!ok) return res.status(401).json({ error: "invalid credentials" });
    const token = signJWT({ userId: u.username }, "30m");
    res.json({
      success: true,
      token,
      user: { username: u.username },
      expiresIn: 1800,
    });
  } catch (e) {
    console.error(e);
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
// Metadata & listing
// ----------------------------
app.get("/api/audio/list", authenticateToken, async (req, res) => {
  const files = await AudioFile.find({ permissions: req.user.userId }).select(
    "filename sizeBytes totalChunks sections"
  );
  res.json({ files });
});

app.get("/api/audio/:id/metadata", authenticateToken, async (req, res) => {
  const meta = await AudioFile.findById(req.params.id);
  if (!meta) return res.status(404).json({ error: "not found" });
  if (!meta.permissions.includes(req.user.userId))
    return res.status(403).json({ error: "no access" });
  res.json({
    _id: meta._id,
    filename: meta.filename,
    contentType: meta.contentType,
    sizeBytes: meta.sizeBytes,
    chunkSize: meta.chunkSize,
    totalChunks: meta.totalChunks,
    sections: meta.sections,
  });
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
  const { id } = req.params;
  const {
    start = 0,
    end = -1,
    ttlSeconds = 300,
    bindIp = true,
  } = req.body || {};
  const meta = await AudioFile.findById(id);
  if (!meta) return res.status(404).json({ error: "not found" });
  if (!meta.permissions.includes(req.user.userId))
    return res.status(403).json({ error: "no access" });
  const expires = Date.now() + Math.max(1, Math.min(3600, ttlSeconds)) * 1000;
  const ip = bindIp ? req.ip || "-" : "-";
  const sig = hmacSign([id, start, end, expires, ip]);
  // Client calls GET /api/audio/:id/stream-signed?start=&end=&expires=&sig=
  res.json({
    url: `/api/audio/${id}/stream-signed?start=${start}&end=${end}&expires=${expires}&sig=${sig}`,
  });
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
      if (!meta.permissions.includes(req.user.userId))
        return res.status(403).json({ error: "Access denied" });

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
      if (!meta.permissions.includes(req.user.userId))
        return res.status(403).json({ error: "no access" });

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
  const meta = await AudioFile.findById(req.params.id);
  if (!meta) return res.status(404).json({ error: "not found" });
  if (!meta.permissions.includes(req.user.userId))
    return res.status(403).json({ error: "no access" });
  const sec = meta.sections.find((s) => s.label === req.query.label);
  if (!sec) return res.status(404).json({ error: "section not found" });
  res.json({ startTime: sec.startTime });
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

    // Seed audio files (example from old static AUDIO_FILES)
    const filesToSeed = [
      {
        filename: "voice.mp3",
        path: path.resolve("./assets/voice.mp3"),
        permissions: ["admin", "user1"],
        sections: [
          { label: "Introduction", startTime: 0 },
          { label: "Topic 1", startTime: 240 },
          { label: "Topic 2", startTime: 1200 },
          { label: "Conclusion", startTime: 2100 },
        ],
      },
    ];

    for (const f of filesToSeed) {
      if (!fs.existsSync(f.path)) {
        console.warn(`⚠️ Skipping ${f.filename}, file not found`);
        continue;
      }

      const stat = fs.statSync(f.path);
      const totalChunks = Math.ceil(stat.size / CHUNK_SIZE);

      const audioDoc = await AudioFile.create({
        filename: f.filename,
        sizeBytes: stat.size,
        chunkSize: CHUNK_SIZE,
        totalChunks,
        sections: f.sections,
        permissions: f.permissions,
      });

      // Chunk + encrypt
      const fd = fs.openSync(f.path, "r");
      for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(stat.size, start + CHUNK_SIZE);
        const size = end - start;
        const buffer = Buffer.alloc(size);
        fs.readSync(fd, buffer, 0, size, start);

        const iv = crypto.randomBytes(12); // 96-bit for GCM
        const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
        const encrypted = Buffer.concat([
          cipher.update(buffer),
          cipher.final(),
        ]);
        const tag = cipher.getAuthTag();

        await AudioChunk.create({
          fileId: audioDoc._id,
          index: i,
          iv,
          tag,
          data: encrypted,
          plainSize: size,
        });

        process.stdout.write(`Chunk ${i + 1}/${totalChunks} seeded…\\r`);
      }
      fs.closeSync(fd);

      console.log(`\\n✅ Seeded ${f.filename} (${totalChunks} chunks)`);
    }
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
