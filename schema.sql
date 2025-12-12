
-- Phase 1 CDE Database Schema
-- PostgreSQL 12+

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "citext"; -- Case-insensitive text

-- Users table (local authentication for MVP)
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username CITEXT UNIQUE NOT NULL,
  email CITEXT UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255),
  is_active BOOLEAN DEFAULT true,
  is_admin BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Roles table
CREATE TABLE roles (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(100) UNIQUE NOT NULL,
  description TEXT,
  is_system BOOLEAN DEFAULT false, -- System roles cannot be deleted
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default system roles
INSERT INTO roles (id, name, description, is_system) VALUES
  (uuid_generate_v4(), 'System Administrator', 'Full system access', true),
  (uuid_generate_v4(), 'Project Administrator', 'Project-level control', true),
  (uuid_generate_v4(), 'Project Manager', 'Coordination and oversight', true),
  (uuid_generate_v4(), 'Lead Designer', 'Check-in, approve, publish', true),
  (uuid_generate_v4(), 'Designer', 'Check-in, check-out, modify', true),
  (uuid_generate_v4(), 'Reviewer', 'Read, comment, markup', true),
  (uuid_generate_v4(), 'Viewer', 'Read-only access', true);

-- User-role assignments
CREATE TABLE user_roles (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, role_id)
);

-- Permissions table
CREATE TABLE permissions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(100) UNIQUE NOT NULL,
  description TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert standard permissions
INSERT INTO permissions (id, name, description) VALUES
  (uuid_generate_v4(), 'file.read', 'Read/view files'),
  (uuid_generate_v4(), 'file.write', 'Modify files'),
  (uuid_generate_v4(), 'file.delete', 'Delete files'),
  (uuid_generate_v4(), 'file.download', 'Download files'),
  (uuid_generate_v4(), 'file.checkout', 'Check out files (lock for editing)'),
  (uuid_generate_v4(), 'file.checkin', 'Check in files (upload new version)'),
  (uuid_generate_v4(), 'file.approve', 'Approve files for publication'),
  (uuid_generate_v4(), 'folder.create', 'Create folders'),
  (uuid_generate_v4(), 'folder.delete', 'Delete folders'),
  (uuid_generate_v4(), 'permission.manage', 'Manage folder/file permissions'),
  (uuid_generate_v4(), 'project.admin', 'Project administration');

-- Role-permission assignments
CREATE TABLE role_permissions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  UNIQUE(role_id, permission_id)
);

-- Projects table
CREATE TABLE projects (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  code VARCHAR(50) UNIQUE,
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  is_active BOOLEAN DEFAULT true
);

-- Project members and their roles
CREATE TABLE project_members (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES roles(id),
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, user_id)
);

-- Folders (hierarchical structure)
CREATE TABLE folders (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  parent_id UUID REFERENCES folders(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, parent_id, name)
);

-- Folder permissions (granular access control)
CREATE TABLE folder_permissions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  folder_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
  can_read BOOLEAN DEFAULT false,
  can_write BOOLEAN DEFAULT false,
  can_delete BOOLEAN DEFAULT false,
  can_approve BOOLEAN DEFAULT false,
  can_manage_permissions BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CHECK (user_id IS NOT NULL OR role_id IS NOT NULL)
);

-- Files table
CREATE TABLE files (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  folder_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
  filename VARCHAR(500) NOT NULL,
  description TEXT,
  file_type VARCHAR(20), -- 'dgn', 'dwg', 'rvt', 'pdf', 'docx', etc.
  status VARCHAR(50) DEFAULT 'Draft', -- Draft, Review, Approved, Superseded, Archived
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  current_version INT DEFAULT 1,
  is_locked BOOLEAN DEFAULT false,
  locked_by UUID REFERENCES users(id),
  locked_at TIMESTAMP,
  UNIQUE(folder_id, filename)
);

-- File versions (complete version history)
CREATE TABLE file_versions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  version_number INT NOT NULL,
  file_size_bytes BIGINT,
  file_path VARCHAR(500) NOT NULL, -- Path on disk or storage
  file_hash VARCHAR(64), -- SHA-256 for integrity checking
  uploaded_by UUID NOT NULL REFERENCES users(id),
  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  change_description TEXT,
  storage_location VARCHAR(255), -- 'local' or storage type
  UNIQUE(file_id, version_number)
);

-- File metadata (extensible key-value for custom fields)
CREATE TABLE file_metadata (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  key VARCHAR(255) NOT NULL,
  value TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(file_id, key)
);

-- File locks (for check-out state)
CREATE TABLE file_locks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  locked_by UUID NOT NULL REFERENCES users(id),
  locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP + INTERVAL '7 days',
  reason VARCHAR(255),
  UNIQUE(file_id)
);

-- Approvals/Workflow state
CREATE TABLE file_approvals (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  status VARCHAR(50) NOT NULL, -- 'pending', 'approved', 'rejected'
  requested_by UUID NOT NULL REFERENCES users(id),
  requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  approver_id UUID REFERENCES users(id),
  approved_at TIMESTAMP,
  rejection_reason TEXT,
  approval_status VARCHAR(50) DEFAULT 'pending' -- pending, approved, rejected
);

-- Audit log (immutable record of all operations)
CREATE TABLE audit_logs (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  user_id UUID REFERENCES users(id),
  action VARCHAR(100) NOT NULL, -- 'file.upload', 'file.approve', 'permission.change', etc.
  resource_type VARCHAR(50), -- 'file', 'folder', 'user', 'permission'
  resource_id VARCHAR(255),
  details JSONB, -- Flexible field for action-specific details
  ip_address INET,
  user_agent TEXT
);

-- Create indexes for common queries
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_files_folder ON files(folder_id);
CREATE INDEX idx_files_status ON files(status);
CREATE INDEX idx_files_locked_by ON files(locked_by);
CREATE INDEX idx_file_versions_file ON file_versions(file_id);
CREATE INDEX idx_file_locks_file ON file_locks(file_id);
CREATE INDEX idx_file_locks_user ON file_locks(locked_by);
CREATE INDEX idx_file_approvals_file ON file_approvals(file_id);
CREATE INDEX idx_file_approvals_status ON file_approvals(status);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_folders_project ON folders(project_id);
CREATE INDEX idx_folders_parent ON folders(parent_id);
CREATE INDEX idx_project_members_project ON project_members(project_id);
CREATE INDEX idx_project_members_user ON project_members(user_id);
CREATE INDEX idx_folder_permissions_folder ON folder_permissions(folder_id);
CREATE INDEX idx_folder_permissions_user ON folder_permissions(user_id);

-- Create view for file current status (useful for queries)
CREATE VIEW file_current_info AS
SELECT 
  f.id,
  f.folder_id,
  f.filename,
  f.status,
  f.current_version,
  f.is_locked,
  f.locked_by,
  fv.file_size_bytes,
  fv.file_path,
  fv.uploaded_at,
  fv.uploaded_by,
  u.full_name as uploaded_by_name
FROM files f
LEFT JOIN file_versions fv ON f.id = fv.file_id AND fv.version_number = f.current_version
LEFT JOIN users u ON fv.uploaded_by = u.id;

