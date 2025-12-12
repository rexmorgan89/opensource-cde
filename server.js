// server.js - Express CDE Backend
// Phase 1 Starter - PostgreSQL + JWT + File Storage

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const multer = require("multer");
const fs = require("fs").promises;
const path = require("path");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

// Initialize
const app = express();
const db = new Pool({
  connectionString:
    process.env.DATABASE_URL ||
    "postgresql://user:password@localhost:5432/cde_db",
});

// Middleware
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb" }));

// File storage setup
const uploadDir = process.env.UPLOAD_DIR || "./file_storage";
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const projectDir = path.join(uploadDir, req.params.project_id);
    await fs.mkdir(projectDir, { recursive: true });
    cb(null, projectDir);
  },
  filename: (req, file, cb) => {
    // Store with UUID to avoid conflicts, original name in DB
    cb(null, `${uuidv4()}_${Date.now()}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2 GB
});

const JWT_SECRET = process.env.JWT_SECRET || "change_me_in_production";

// Utility: Hash password
async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

// Utility: Verify password
async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// Utility: Generate JWT
function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "24h" });
}

// Middleware: Authenticate JWT
async function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await db.query("SELECT * FROM users WHERE id = $1", [
      decoded.userId,
    ]);
    if (!result.rows.length)
      return res.status(401).json({ error: "User not found" });
    req.user = result.rows[0];
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
}

// Middleware: Log audit trail
async function auditLog(
  userId,
  action,
  resourceType,
  resourceId,
  details,
  ipAddress
) {
  try {
    await db.query(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address) 
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        userId,
        action,
        resourceType,
        resourceId,
        JSON.stringify(details),
        ipAddress,
      ]
    );
  } catch (err) {
    console.error("Audit log error:", err);
  }
}

// Middleware: Check permissions
async function checkPermission(req, res, next) {
  const { project_id, folder_id } = req.params;

  // Admin bypass
  if (req.user.is_admin) {
    return next();
  }

  // Check if user is project member with correct role
  if (project_id) {
    const result = await db.query(
      `SELECT pm.*, r.name FROM project_members pm
       JOIN roles r ON pm.role_id = r.id
       WHERE pm.project_id = $1 AND pm.user_id = $2`,
      [project_id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(403).json({ error: "Not a project member" });
    }

    req.userRole = result.rows[0];
  }

  next();
}

// ============== AUTH ENDPOINTS ==============

app.post("/api/v1/auth/register", async (req, res) => {
  try {
    const { username, email, password, full_name } = req.body;

    const passwordHash = await hashPassword(password);
    const result = await db.query(
      `INSERT INTO users (username, email, password_hash, full_name, is_active)
       VALUES ($1, $2, $3, $4, true)
       RETURNING id, username, email, full_name`,
      [username, email, passwordHash, full_name]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res
      .status(400)
      .json({ error: "Registration failed", message: err.message });
  }
});

app.post("/api/v1/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await db.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);
    if (!result.rows.length) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const passwordValid = await verifyPassword(password, user.password_hash);

    if (!passwordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = generateToken(user.id);
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        is_admin: user.is_admin,
      },
    });
  } catch (err) {
    res.status(500).json({ error: "Login failed", message: err.message });
  }
});

app.get("/api/v1/auth/me", authenticate, async (req, res) => {
  try {
    const rolesResult = await db.query(
      `SELECT r.name FROM user_roles ur
       JOIN roles r ON ur.role_id = r.id
       WHERE ur.user_id = $1`,
      [req.user.id]
    );

    res.json({
      id: req.user.id,
      username: req.user.username,
      full_name: req.user.full_name,
      is_admin: req.user.is_admin,
      roles: rolesResult.rows.map((r) => r.name),
    });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Error fetching user", message: err.message });
  }
});

// ============== PROJECT ENDPOINTS ==============

app.post("/api/v1/projects", authenticate, async (req, res) => {
  try {
    const { name, description, code } = req.body;

    const result = await db.query(
      `INSERT INTO projects (name, description, code, created_by)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, description, code, req.user.id]
    );

    await auditLog(
      req.user.id,
      "project.create",
      "project",
      result.rows[0].id,
      { name },
      req.ip
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to create project", message: err.message });
  }
});

app.get("/api/v1/projects", authenticate, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT DISTINCT p.* FROM projects p
       JOIN project_members pm ON p.id = pm.project_id
       WHERE pm.user_id = $1 OR p.created_by = $1
       ORDER BY p.created_at DESC
       LIMIT 100`,
      [req.user.id]
    );

    res.json({
      data: result.rows,
      total: result.rows.length,
      page: 1,
      limit: 100,
    });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Failed to fetch projects", message: err.message });
  }
});

app.get(
  "/api/v1/projects/:project_id",
  authenticate,
  checkPermission,
  async (req, res) => {
    try {
      const { project_id } = req.params;

      const project = await db.query("SELECT * FROM projects WHERE id = $1", [
        project_id,
      ]);
      if (!project.rows.length)
        return res.status(404).json({ error: "Project not found" });

      const members = await db.query(
        "SELECT COUNT(*) FROM project_members WHERE project_id = $1",
        [project_id]
      );
      const folders = await db.query(
        "SELECT COUNT(*) FROM folders WHERE project_id = $1",
        [project_id]
      );
      const files = await db.query(
        "SELECT COUNT(*) FROM files WHERE folder_id IN (SELECT id FROM folders WHERE project_id = $1)",
        [project_id]
      );

      res.json({
        ...project.rows[0],
        member_count: parseInt(members.rows[0].count),
        folder_count: parseInt(folders.rows[0].count),
        file_count: parseInt(files.rows[0].count),
      });
    } catch (err) {
      res
        .status(500)
        .json({ error: "Failed to fetch project", message: err.message });
    }
  }
);

// ============== FOLDER ENDPOINTS ==============

app.post(
  "/api/v1/projects/:project_id/folders",
  authenticate,
  checkPermission,
  async (req, res) => {
    try {
      const { project_id } = req.params;
      const { name, description, parent_id } = req.body;

      const result = await db.query(
        `INSERT INTO folders (project_id, parent_id, name, description, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
        [project_id, parent_id || null, name, description, req.user.id]
      );

      await auditLog(
        req.user.id,
        "folder.create",
        "folder",
        result.rows[0].id,
        { name },
        req.ip
      );
      res.status(201).json(result.rows[0]);
    } catch (err) {
      res
        .status(400)
        .json({ error: "Failed to create folder", message: err.message });
    }
  }
);

app.get(
  "/api/v1/projects/:project_id/folders/:folder_id",
  authenticate,
  checkPermission,
  async (req, res) => {
    try {
      const { folder_id } = req.params;

      const folder = await db.query("SELECT * FROM folders WHERE id = $1", [
        folder_id,
      ]);
      if (!folder.rows.length)
        return res.status(404).json({ error: "Folder not found" });

      const subFolders = await db.query(
        "SELECT * FROM folders WHERE parent_id = $1",
        [folder_id]
      );
      const files = await db.query(
        `SELECT f.*, fv.file_size_bytes, u.full_name as created_by_name
       FROM files f
       LEFT JOIN file_versions fv ON f.id = fv.file_id AND fv.version_number = f.current_version
       LEFT JOIN users u ON f.created_by = u.id
       WHERE f.folder_id = $1
       ORDER BY f.filename`,
        [folder_id]
      );

      res.json({
        ...folder.rows[0],
        folders: subFolders.rows,
        files: files.rows,
      });
    } catch (err) {
      res
        .status(500)
        .json({ error: "Failed to fetch folder", message: err.message });
    }
  }
);

// ============== FILE ENDPOINTS ==============

app.post(
  "/api/v1/projects/:project_id/folders/:folder_id/files/upload",
  authenticate,
  checkPermission,
  upload.single("file"),
  async (req, res) => {
    try {
      const { project_id, folder_id } = req.params;
      const { change_description } = req.body;

      if (!req.file) return res.status(400).json({ error: "No file uploaded" });

      const filename = path.basename(req.file.originalname);
      const fileHash = crypto.createHash("sha256");
      const fileData = await fs.readFile(req.file.path);
      fileHash.update(fileData);

      let file = await db.query(
        "SELECT * FROM files WHERE folder_id = $1 AND filename = $2",
        [folder_id, filename]
      );

      let versionNumber = 1;
      if (file.rows.length) {
        versionNumber = file.rows[0].current_version + 1;
        await db.query(
          "UPDATE files SET current_version = $1, updated_at = NOW() WHERE id = $2",
          [versionNumber, file.rows[0].id]
        );
      } else {
        const newFile = await db.query(
          `INSERT INTO files (folder_id, filename, created_by, current_version)
         VALUES ($1, $2, $3, 1)
         RETURNING *`,
          [folder_id, filename, req.user.id]
        );
        file = newFile;
      }

      const fileId =
        file.rows[0]?.id ||
        (
          await db.query(
            "SELECT id FROM files WHERE folder_id = $1 AND filename = $2",
            [folder_id, filename]
          )
        ).rows[0].id;

      await db.query(
        `INSERT INTO file_versions (file_id, version_number, file_size_bytes, file_path, file_hash, uploaded_by, change_description, storage_location)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'local')`,
        [
          fileId,
          versionNumber,
          req.file.size,
          req.file.path,
          fileHash.digest("hex"),
          req.user.id,
          change_description,
        ]
      );

      await auditLog(
        req.user.id,
        "file.upload",
        "file",
        fileId,
        { filename, version: versionNumber },
        req.ip
      );

      res.status(201).json({
        id: fileId,
        filename,
        version: versionNumber,
        file_size_bytes: req.file.size,
        uploaded_by: req.user.id,
        uploaded_at: new Date(),
        status: "Draft",
      });
    } catch (err) {
      res.status(500).json({ error: "Upload failed", message: err.message });
    }
  }
);

app.get(
  "/api/v1/projects/:project_id/folders/:folder_id/files",
  authenticate,
  checkPermission,
  async (req, res) => {
    try {
      const { folder_id } = req.params;
      const { status } = req.query;

      let query = `SELECT f.*, u.full_name as created_by_name
                 FROM files f
                 LEFT JOIN users u ON f.created_by = u.id
                 WHERE f.folder_id = $1`;
      const params = [folder_id];

      if (status) {
        query += ` AND f.status = $2`;
        params.push(status);
      }

      query += " ORDER BY f.updated_at DESC LIMIT 100";

      const result = await db.query(query, params);
      res.json({
        data: result.rows,
        total: result.rows.length,
        page: 1,
        limit: 100,
      });
    } catch (err) {
      res
        .status(500)
        .json({ error: "Failed to list files", message: err.message });
    }
  }
);

app.get(
  "/api/v1/projects/:project_id/files/:file_id",
  authenticate,
  checkPermission,
  async (req, res) => {
    try {
      const { file_id } = req.params;

      const file = await db.query("SELECT * FROM files WHERE id = $1", [
        file_id,
      ]);
      if (!file.rows.length)
        return res.status(404).json({ error: "File not found" });

      const versions = await db.query(
        `SELECT version_number, file_size_bytes, uploaded_by, uploaded_at, change_description
       FROM file_versions WHERE file_id = $1 ORDER BY version_number DESC`,
        [file_id]
      );

      const approvals = await db.query(
        "SELECT * FROM file_approvals WHERE file_id = $1",
        [file_id]
      );

      const metadata = await db.query(
        "SELECT key, value FROM file_metadata WHERE file_id = $1",
        [file_id]
      );

      res.json({
        ...file.rows[0],
        versions: versions.rows,
        approvals: approvals.rows,
        metadata: Object.fromEntries(
          metadata.rows.map((m) => [m.key, m.value])
        ),
      });
    } catch (err) {
      res
        .status(500)
        .json({ error: "Failed to fetch file", message: err.message });
    }
  }
);

app.post(
  "/api/v1/projects/:project_id/files/:file_id/checkout",
  authenticate,
  checkPermission,
  async (req, res) => {
    try {
      const { file_id } = req.params;
      const { reason } = req.body;

      const file = await db.query("SELECT * FROM files WHERE id = $1", [
        file_id,
      ]);
      if (!file.rows.length)
        return res.status(404).json({ error: "File not found" });
      if (file.rows[0].is_locked)
        return res.status(409).json({ error: "File already locked" });

      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      await db.query(
        `UPDATE files SET is_locked = true, locked_by = $1, locked_at = NOW() WHERE id = $2`,
        [req.user.id, file_id]
      );

      await db.query(
        `INSERT INTO file_locks (file_id, locked_by, expires_at, reason) VALUES ($1, $2, $3, $4)`,
        [file_id, req.user.id, expiresAt, reason]
      );

      await auditLog(
        req.user.id,
        "file.checkout",
        "file",
        file_id,
        { reason },
        req.ip
      );

      res.json({
        file_id,
        locked_by: req.user.id,
        locked_at: new Date(),
        expires_at: expiresAt,
      });
    } catch (err) {
      res.status(500).json({ error: "Checkout failed", message: err.message });
    }
  }
);

app.post(
  "/api/v1/projects/:project_id/files/:file_id/request-approval",
  authenticate,
  checkPermission,
  async (req, res) => {
    try {
      const { file_id } = req.params;
      const { approver_id, message } = req.body;

      const result = await db.query(
        `INSERT INTO file_approvals (file_id, status, requested_by, approver_id, approval_status)
       VALUES ($1, $2, $3, $4, 'pending')
       RETURNING *`,
        [file_id, "pending", req.user.id, approver_id]
      );

      await auditLog(
        req.user.id,
        "file.request_approval",
        "file",
        file_id,
        { approver_id, message },
        req.ip
      );

      res.status(201).json(result.rows[0]);
    } catch (err) {
      res
        .status(500)
        .json({ error: "Failed to request approval", message: err.message });
    }
  }
);

app.post(
  "/api/v1/projects/:project_id/files/:file_id/approve",
  authenticate,
  checkPermission,
  async (req, res) => {
    try {
      const { file_id } = req.params;
      const { approval_id } = req.body;

      await db.query(
        `UPDATE file_approvals SET status = 'approved', approval_status = 'approved', approver_id = $1, approved_at = NOW()
       WHERE id = $2`,
        [req.user.id, approval_id]
      );

      await db.query(
        "UPDATE files SET status = $1, updated_at = NOW() WHERE id = $2",
        ["Approved", file_id]
      );

      await auditLog(
        req.user.id,
        "file.approve",
        "file",
        file_id,
        { approval_id },
        req.ip
      );

      res.json({
        file_id,
        status: "Approved",
        approved_by: req.user.id,
        approved_at: new Date(),
      });
    } catch (err) {
      res.status(500).json({ error: "Approval failed", message: err.message });
    }
  }
);

app.get(
  "/api/v1/projects/:project_id/audit",
  authenticate,
  checkPermission,
  async (req, res) => {
    try {
      const { project_id } = req.params;
      const { action, limit = 100, offset = 0 } = req.query;

      let query = `SELECT al.*, u.full_name FROM audit_logs al
                 LEFT JOIN users u ON al.user_id = u.id
                 WHERE resource_type IN ('file', 'folder')
                 AND (al.details->>'project_id' = $1 OR TRUE)`;
      const params = [project_id];

      if (action) {
        query += ` AND al.action = $2`;
        params.push(action);
      }

      query += ` ORDER BY al.timestamp DESC LIMIT $${
        params.length + 1
      } OFFSET $${params.length + 2}`;
      params.push(limit, offset);

      const result = await db.query(query, params);
      res.json({ data: result.rows, total: result.rows.length, page: 1 });
    } catch (err) {
      res
        .status(500)
        .json({ error: "Failed to fetch audit logs", message: err.message });
    }
  }
);

// ============== ERROR HANDLING ==============

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Server error", message: err.message });
});

// ============== START SERVER ==============

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`CDE API running on http://localhost:${PORT}`);
});
