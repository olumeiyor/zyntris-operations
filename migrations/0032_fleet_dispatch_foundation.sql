CREATE UNIQUE INDEX IF NOT EXISTS idx_employees_id_org_fleet
  ON employees(id,organization_id);

CREATE TABLE IF NOT EXISTS fleet_vehicles (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  registration TEXT NOT NULL,
  make TEXT NOT NULL,
  model TEXT NOT NULL,
  vehicle_type TEXT NOT NULL,
  model_year INTEGER CHECK (model_year IS NULL OR model_year BETWEEN 1900 AND 2200),
  capacity TEXT,
  odometer_km REAL NOT NULL DEFAULT 0 CHECK (odometer_km >= 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','maintenance','retired')),
  notes TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, registration),
  UNIQUE (id, organization_id)
);
CREATE INDEX IF NOT EXISTS idx_fleet_vehicles_status ON fleet_vehicles(organization_id,status,registration);

CREATE TABLE IF NOT EXISTS fleet_trips (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  vehicle_id TEXT NOT NULL,
  driver_employee_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  destination TEXT NOT NULL,
  scheduled_departure TEXT NOT NULL,
  scheduled_return TEXT,
  actual_departure TEXT,
  actual_return TEXT,
  status TEXT NOT NULL DEFAULT 'planned' CHECK (status IN ('planned','in_progress','completed','cancelled')),
  distance_km REAL CHECK (distance_km IS NULL OR distance_km >= 0),
  reference TEXT,
  notes TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (vehicle_id,organization_id) REFERENCES fleet_vehicles(id,organization_id),
  FOREIGN KEY (driver_employee_id,organization_id) REFERENCES employees(id,organization_id),
  UNIQUE (id,organization_id)
);
CREATE INDEX IF NOT EXISTS idx_fleet_trips_schedule ON fleet_trips(organization_id,status,scheduled_departure);
CREATE INDEX IF NOT EXISTS idx_fleet_trips_driver ON fleet_trips(organization_id,driver_employee_id,scheduled_departure);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fleet_one_active_trip_per_vehicle
  ON fleet_trips(organization_id,vehicle_id) WHERE status='in_progress';

CREATE TABLE IF NOT EXISTS fleet_service_records (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  vehicle_id TEXT NOT NULL,
  service_type TEXT NOT NULL,
  due_date TEXT NOT NULL,
  completed_at TEXT,
  cost REAL NOT NULL DEFAULT 0 CHECK (cost >= 0),
  odometer_km REAL CHECK (odometer_km IS NULL OR odometer_km >= 0),
  vendor TEXT,
  status TEXT NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled','completed','cancelled')),
  notes TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (vehicle_id,organization_id) REFERENCES fleet_vehicles(id,organization_id),
  UNIQUE (id,organization_id)
);
CREATE INDEX IF NOT EXISTS idx_fleet_service_due ON fleet_service_records(organization_id,status,due_date);

CREATE TABLE IF NOT EXISTS fleet_fuel_records (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  vehicle_id TEXT NOT NULL,
  driver_employee_id TEXT,
  fueled_at TEXT NOT NULL,
  quantity_litres REAL NOT NULL CHECK (quantity_litres > 0),
  amount REAL NOT NULL CHECK (amount >= 0),
  odometer_km REAL NOT NULL CHECK (odometer_km >= 0),
  station TEXT,
  receipt_reference TEXT,
  notes TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (vehicle_id,organization_id) REFERENCES fleet_vehicles(id,organization_id),
  FOREIGN KEY (driver_employee_id,organization_id) REFERENCES employees(id,organization_id)
);
CREATE INDEX IF NOT EXISTS idx_fleet_fuel_date ON fleet_fuel_records(organization_id,fueled_at DESC);

CREATE TABLE IF NOT EXISTS fleet_incidents (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  vehicle_id TEXT NOT NULL,
  trip_id TEXT,
  driver_employee_id TEXT,
  occurred_at TEXT NOT NULL,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','resolved')),
  resolution TEXT,
  reported_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (vehicle_id,organization_id) REFERENCES fleet_vehicles(id,organization_id),
  FOREIGN KEY (trip_id,organization_id) REFERENCES fleet_trips(id,organization_id),
  FOREIGN KEY (driver_employee_id,organization_id) REFERENCES employees(id,organization_id)
);
CREATE INDEX IF NOT EXISTS idx_fleet_incidents_status ON fleet_incidents(organization_id,status,occurred_at DESC);
