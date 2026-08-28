-- Forensic Database Schema for Police Narratives & Crime Analysis
-- Normalized SQLite DDL with 4 tables, cascade relations, check constraints, and performance indexes.

PRAGMA foreign_keys = ON;

-- 1. Incidents Table (Core forensic event table)
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_type TEXT NOT NULL,
    date_approx TEXT,
    location TEXT,
    risk_level TEXT CHECK(risk_level IN ('Bajo', 'Medio', 'Alto', 'Crítico')),
    summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Suspects Table (Individuals tied to an incident)
CREATE TABLE IF NOT EXISTS suspects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    alias_or_name TEXT NOT NULL,
    physical_description TEXT,
    status TEXT CHECK(status IN ('Identificado', 'Detenido', 'En fuga', 'Desconocido'))
);

-- 3. Evidences Table (Forensic items, weapons, traces, digital data)
CREATE TABLE IF NOT EXISTS evidences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    item TEXT NOT NULL,
    location_found TEXT,
    evidence_type TEXT NOT NULL DEFAULT 'Otro'
);

-- 4. Victims Table (Affected persons or entities, injuries, testimonies)
CREATE TABLE IF NOT EXISTS victims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    name_or_identity TEXT,
    injury_status TEXT,
    statement_summary TEXT
);

-- Indexes for performance & search optimization
CREATE INDEX IF NOT EXISTS idx_incidents_type ON incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_incidents_date ON incidents(date_approx);
CREATE INDEX IF NOT EXISTS idx_incidents_risk ON incidents(risk_level);

-- Foreign Key Indexes for fast join operations
CREATE INDEX IF NOT EXISTS idx_suspects_incident_id ON suspects(incident_id);
CREATE INDEX IF NOT EXISTS idx_evidences_incident_id ON evidences(incident_id);
CREATE INDEX IF NOT EXISTS idx_victims_incident_id ON victims(incident_id);
