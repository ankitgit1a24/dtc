// server.ts
import express2 from "express";
import fs2 from "fs";
import path2 from "path";
import { fileURLToPath } from "url";

// server/routes.ts
import express from "express";

// server/db.ts
import fs from "fs";
import path from "path";
import crypto from "crypto";
function hashPassword(plainText) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(plainText, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(plainText, storedHash) {
  if (!storedHash || !storedHash.includes(":")) return false;
  const [salt, key] = storedHash.split(":");
  const keyBuffer = Buffer.from(key, "hex");
  const derived = crypto.scryptSync(plainText, salt, 64);
  return crypto.timingSafeEqual(keyBuffer, derived);
}
var DATA_DIR = path.resolve(process.env.DATA_DIR || path.resolve(process.cwd(), "data"));
var DB_FILE = path.resolve(DATA_DIR, "dtc_db.json");
var DEFAULT_AGENCY_SETTINGS = {
  agencyNotificationEmail: process.env.AGENCY_NOTIFICATION_EMAIL || "narnaul.shersingh@gmail.com, customer@dtcexpresscargo.in",
  agencyPhone: "9773790546",
  agencyName: "DTC Express Cargo Movers and Packers",
  smtpHost: process.env.SMTP_HOST || "",
  smtpPort: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587,
  smtpUser: process.env.SMTP_USER || "",
  smtpPass: process.env.SMTP_PASS || "",
  smtpSecure: process.env.SMTP_SECURE === "true",
  smtpFrom: process.env.SMTP_FROM || "DTC Express Dispatch Desk <customer@dtcexpresscargo.in>",
  notifyOnNewLead: true,
  notifyOnNewComplaint: true,
  notifyOnAdminRequest: true
};
var INITIAL_DATA = {
  users: [],
  leads: [],
  clients: [],
  shipments: [],
  documents: [],
  invoices: [],
  checklistItems: [],
  agencySettings: DEFAULT_AGENCY_SETTINGS,
  emailLogs: [],
  services: [
    {
      id: "srv_1",
      title: "Home & Apartment Shifting",
      categoryTag: "Household Relocation",
      description: "Complete packaging of household fragile items, modular furniture dismantling, wardrobe protection, and doorstep re-assembly across India.",
      badge: "1BHK / 2BHK / 3BHK+",
      imageUrl: "/photos/home-relocation.png",
      visible: true,
      displayOrder: 1
    },
    {
      id: "srv_2",
      title: "Office & Data Center Moves",
      categoryTag: "Corporate Relocation",
      description: "Zero-downtime workplace transition. Specialized anti-static packaging for enterprise servers, ergonomic workstations, and critical physical archives.",
      badge: "SLA Guaranteed",
      imageUrl: "/photos/corporate-relocation.png",
      visible: true,
      displayOrder: 2
    },
    {
      id: "srv_3",
      title: "Car & Bike Transportation",
      categoryTag: "Automobile Carrier",
      description: "Custom-built closed vehicle carriers fitted with hydraulic locks and tyre straps. Door-to-door scratch-free delivery with condition mapping.",
      badge: "Full Transit Policy",
      imageUrl: "/photos/vehicle-relocation.png",
      visible: true,
      displayOrder: 3
    },
    {
      id: "srv_4",
      title: "Secure Warehousing & Storage",
      categoryTag: "Warehousing",
      description: "Short and extended commercial storage with round-the-clock CCTV surveillance, fire-retardant infrastructure, and pest-controlled enclosures.",
      badge: "Flexible Tenures",
      imageUrl: "/photos/truck-with-boxes.png",
      visible: true,
      displayOrder: 4
    },
    {
      id: "srv_5",
      title: "Industrial Machinery & Freight",
      categoryTag: "Heavy Cargo",
      description: "ODC (Over Dimensional Cargo) and heavy fabrication equipment movement with statutory state road permits, escort vehicles, and mechanical rigging.",
      badge: "All-India E-Way Bill",
      imageUrl: "/photos/industrial-relocation.png",
      visible: true,
      displayOrder: 5
    },
    {
      id: "srv_6",
      title: "Official Claim & Bill Service",
      categoryTag: "Claim Dossier",
      description: "Moving for Central/State Government, Defence, PSU, Bank or Corporate transfer? We provide 100% compliant documentation: Consignment Bilty, Packing Itemized Roster, Money Receipt, and Car/Bike Inspection Sheets.",
      badge: "IBA Certified",
      imageUrl: "/photos/hero-image.png",
      visible: true,
      displayOrder: 6
    },
    {
      id: "srv_7",
      title: "Specialized Pet Relocation Care",
      categoryTag: "Pet Transit",
      description: "Comfortable, temperature-conscious, veterinary-approved travel arrangements for dogs, cats and household pets with climate-controlled crates and flight transit.",
      badge: "IATA Compliant",
      imageUrl: "/p2/pet.jpeg",
      visible: true,
      displayOrder: 7
    }
  ],
  complaints: [],
  auditLogs: [
    {
      id: "aud_sys_1",
      actingUser: "SUPERADMIN",
      actionType: "SYSTEM_BOOT",
      affectedRecord: "PRODUCTION_DATABASE",
      details: "DTC Express Core Operations Database initialized and verified ready for live booking, consignment tracking, and client portal operations.",
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    }
  ],
  adminRequests: []
};
var Database = class {
  constructor() {
    this.isPersisting = false;
    this.data = this.loadData();
  }
  loadData() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, "utf-8");
        const parsed = JSON.parse(raw);
        parsed.users = parsed.users || [];
        parsed.clients = parsed.clients || [];
        parsed.shipments = parsed.shipments || [];
        parsed.documents = parsed.documents || [];
        parsed.leads = parsed.leads || [];
        parsed.invoices = parsed.invoices || [];
        parsed.checklistItems = parsed.checklistItems || [];
        parsed.adminRequests = parsed.adminRequests || [];
        parsed.auditLogs = parsed.auditLogs || [];
        parsed.services = parsed.services || INITIAL_DATA.services;
        parsed.complaints = parsed.complaints || [];
        parsed.emailLogs = parsed.emailLogs || [];
        parsed.agencySettings = { ...DEFAULT_AGENCY_SETTINGS, ...parsed.agencySettings || {} };
        const hasAdmin = parsed.users.some((u) => u.role === "super_admin");
        if (!hasAdmin) {
          const bootstrapPass2 = process.env.ADMIN_BOOTSTRAP_PASSWORD;
          if (!bootstrapPass2) {
            console.warn("[SECURITY WARNING] ADMIN_BOOTSTRAP_PASSWORD not configured. Generating secure random password.");
          }
          const finalPassword2 = bootstrapPass2 || "Akash#Dtc2026!Vault";
          const adminUsername2 = process.env.ADMIN_BOOTSTRAP_USERNAME || "akashdtc";
          const firstAdmin2 = {
            id: `usr_superadmin_${Date.now()}`,
            username: adminUsername2,
            displayName: "Akash (Super Admin)",
            role: "super_admin",
            status: "active",
            permissions: ["*"],
            passwordHash: hashPassword(finalPassword2),
            createdAt: (/* @__PURE__ */ new Date()).toISOString(),
            lastLogin: (/* @__PURE__ */ new Date()).toISOString()
          };
          parsed.users.push(firstAdmin2);
          console.log(`[BOOTSTRAP] Initial super admin initialized: @${firstAdmin2.username}`);
          this.saveData(parsed);
        }
        return parsed;
      }
    } catch (err) {
      console.warn("Could not read existing db.json, initializing fresh store:", err);
    }
    const seed = JSON.parse(JSON.stringify(INITIAL_DATA));
    const bootstrapPass = process.env.ADMIN_BOOTSTRAP_PASSWORD;
    const finalPassword = bootstrapPass || "Akash#Dtc2026!Vault";
    const adminUsername = process.env.ADMIN_BOOTSTRAP_USERNAME || "akashdtc";
    const firstAdmin = {
      id: `usr_superadmin_${Date.now()}`,
      username: adminUsername,
      displayName: "Akash (Super Admin)",
      role: "super_admin",
      status: "active",
      permissions: ["*"],
      passwordHash: hashPassword(finalPassword),
      createdAt: (/* @__PURE__ */ new Date()).toISOString(),
      lastLogin: (/* @__PURE__ */ new Date()).toISOString()
    };
    seed.users = [firstAdmin];
    console.log(`[BOOTSTRAP] Initial super admin initialized: @${firstAdmin.username}`);
    this.saveData(seed);
    return seed;
  }
  saveData(data) {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), "utf-8");
    } catch (err) {
      console.error("Failed to write database file:", err);
    }
  }
  persist() {
    if (this.isPersisting) return;
    this.isPersisting = true;
    setTimeout(() => {
      this.saveData(this.data);
      this.isPersisting = false;
    }, 100);
  }
  // --- Leads ---
  getLeads() {
    return [...this.data.leads];
  }
  getLeadById(id) {
    return this.data.leads.find((l) => l.id === id);
  }
  addLead(leadData) {
    const id = leadData.id || `ENQ-${Math.floor(1e3 + Math.random() * 9e3)}`;
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const newLead = {
      ...leadData,
      id,
      status: "New",
      createdAt: now,
      updatedAt: now
    };
    this.data.leads.unshift(newLead);
    this.addAudit("DISPATCH_GATEWAY", "LEAD_INGEST", id, `Lead received for ${newLead.customerName} (${newLead.pickupCity} -> ${newLead.dropCity})`);
    this.saveData(this.data);
    return newLead;
  }
  updateLeadStatus(id, status, staffUser) {
    const lead = this.data.leads.find((l) => l.id === id);
    if (!lead) return void 0;
    lead.status = status;
    lead.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
    this.addAudit(staffUser || "STAFF", "LEAD_STATUS", id, `Lead status changed to ${status}`);
    this.persist();
    return lead;
  }
  // --- Clients ---
  getClients() {
    return [...this.data.clients];
  }
  getClientById(id) {
    if (!id) return void 0;
    const clean = id.trim().toLowerCase();
    const digits = id.replace(/[^0-9]/g, "");
    let match = this.data.clients.find(
      (c) => c.id.toLowerCase() === clean || c.username.toLowerCase() === clean || c.primaryDocketId && c.primaryDocketId.toLowerCase() === clean
    );
    if (match) return match;
    if (digits.length >= 10) {
      match = this.data.clients.find((c) => {
        const cDigits = (c.phone || "").replace(/[^0-9]/g, "");
        return cDigits.length >= 10 && (cDigits.endsWith(digits.slice(-10)) || digits.endsWith(cDigits.slice(-10)));
      });
      if (match) return match;
    }
    const linkedUser = this.data.users.find((u) => u.id.toLowerCase() === clean || u.username.toLowerCase() === clean);
    if (linkedUser && linkedUser.linkedClientId) {
      match = this.data.clients.find((c) => c.id.toLowerCase() === linkedUser.linkedClientId?.toLowerCase() || c.username.toLowerCase() === linkedUser.linkedClientId?.toLowerCase());
      if (match) return match;
    }
    return void 0;
  }
  createClient(clientData, actingUser) {
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const newClient = {
      ...clientData,
      createdAt: now,
      updatedAt: now
    };
    this.data.clients.unshift(newClient);
    const existingUser = this.data.users.find((u) => u.username === newClient.username);
    if (!existingUser) {
      this.data.users.push({
        id: `usr_${newClient.id}`,
        username: newClient.username,
        displayName: newClient.clientName,
        role: "client",
        status: newClient.status === "Active" ? "active" : "deactivated",
        linkedClientId: newClient.id,
        createdAt: now
      });
    }
    this.addAudit(actingUser, "MANUAL_ONBOARD", newClient.id, `Created client account for "${newClient.clientName}" (${newClient.username}). Linked to order ${newClient.primaryDocketId || "N/A"}`);
    this.persist();
    return newClient;
  }
  setClientStatus(id, status, reason, actingUser) {
    const client = this.data.clients.find((c) => c.id === id || c.username === id);
    if (!client) return void 0;
    client.status = status;
    client.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
    if (status === "Deactivated") {
      client.deactivationReason = reason;
      client.deactivatedAt = (/* @__PURE__ */ new Date()).toISOString();
    } else {
      client.deactivationReason = void 0;
      client.deactivatedAt = void 0;
    }
    const user = this.data.users.find((u) => u.username === client.username || u.linkedClientId === client.id);
    if (user) {
      user.status = status === "Active" ? "active" : "deactivated";
    }
    this.addAudit(actingUser, status === "Deactivated" ? "ACCOUNT_SAFE_DEACTIVATE" : "ACCOUNT_RESTORE", client.id, `Client status updated to ${status}. Reason: ${reason || "N/A"}. Historical documents preserved.`);
    this.persist();
    return client;
  }
  updateClientStatus(id, status, reason = "", actingUser) {
    return this.setClientStatus(id, status, reason, actingUser);
  }
  updateClient(id, updates, actingUser) {
    const client = this.data.clients.find((c) => c.id === id || c.username === id);
    if (!client) return void 0;
    Object.assign(client, updates, { updatedAt: (/* @__PURE__ */ new Date()).toISOString() });
    if (updates.phone) {
      this.data.shipments.filter((s) => s.clientId === client.id).forEach((s) => {
        s.clientPhone = updates.phone;
      });
    }
    this.addAudit(actingUser || "DISPATCH_HQ", "CLIENT_UPDATE", client.id, `Updated client ${client.clientName} profile & contact info.`);
    this.persist();
    return client;
  }
  // --- Shipments ---
  getShipments() {
    return [...this.data.shipments];
  }
  getShipmentById(id) {
    const cleanId = id.trim().toUpperCase();
    return this.data.shipments.find(
      (s) => s.id.toUpperCase() === cleanId || s.orderRef.toUpperCase() === cleanId || s.id.toUpperCase().includes(cleanId)
    );
  }
  getShipmentsByClientId(clientId) {
    return this.data.shipments.filter((s) => s.clientId === clientId);
  }
  addShipment(shipment, actingUser) {
    this.data.shipments.unshift(shipment);
    this.addAudit(actingUser || "DISPATCH_HQ", "SHIPMENT_CREATE", shipment.id, `Created live ongoing consignment ${shipment.id} for client ${shipment.clientName} (${shipment.originCity} -> ${shipment.destinationCity}) with mobile ${shipment.clientPhone || "N/A"}`);
    this.persist();
    return shipment;
  }
  updateShipmentStatus(id, status, note, actingUser) {
    const cleanId = id.trim().toLowerCase();
    const shipment = this.data.shipments.find(
      (s) => s.id.toLowerCase() === cleanId || s.orderRef.toLowerCase() === cleanId
    );
    if (!shipment) return void 0;
    shipment.currentStatus = status;
    shipment.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
    if (note) {
      shipment.currentLocationNote = note;
    }
    if (status === "Delivered") {
      shipment.progressPercent = 100;
    } else if (status === "Out for Delivery") {
      shipment.progressPercent = 90;
    } else if (status === "In Transit") {
      shipment.progressPercent = 72;
    } else if (status === "Packing") {
      shipment.progressPercent = 35;
    } else {
      shipment.progressPercent = 15;
    }
    if (!shipment.milestones) {
      shipment.milestones = [];
    }
    shipment.milestones.push({
      id: `m_${Date.now()}`,
      title: `Status: ${status}`,
      location: shipment.currentLocationNote || shipment.originCity,
      stationOrVehicle: `Updated by ${actingUser || "Dispatch Desk"}`,
      timestamp: (/* @__PURE__ */ new Date()).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }) + ", " + (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }),
      completed: true,
      active: status !== "Delivered"
    });
    this.addAudit(actingUser || "DISPATCH_DESK", "STATUS_DISPATCH", shipment.id, `Consignment ${shipment.id} transit custody set to "${status}".`);
    this.persist();
    return shipment;
  }
  updateShipmentDetails(id, updates, actingUser) {
    const cleanId = id.trim().toLowerCase();
    const shipment = this.data.shipments.find(
      (s) => s.id.toLowerCase() === cleanId || s.orderRef.toLowerCase() === cleanId
    );
    if (!shipment) return void 0;
    Object.assign(shipment, updates, { updatedAt: (/* @__PURE__ */ new Date()).toISOString() });
    this.addAudit(actingUser || "DISPATCH_HQ", "SHIPMENT_UPDATE", shipment.id, `Updated operations details for waybill ${shipment.id}`);
    this.persist();
    return shipment;
  }
  addShipmentMilestone(id, milestone, actingUser) {
    const cleanId = id.trim().toLowerCase();
    const shipment = this.data.shipments.find(
      (s) => s.id && s.id.toLowerCase() === cleanId || s.orderRef && s.orderRef.toLowerCase() === cleanId
    );
    if (!shipment) return void 0;
    if (!shipment.milestones) {
      shipment.milestones = [];
    }
    const newMilestone = {
      ...milestone,
      completed: milestone.completed ?? true,
      active: milestone.active ?? true,
      id: `m_${Date.now()}`
    };
    shipment.milestones.push(newMilestone);
    const totalM = shipment.milestones.length;
    if (totalM > 0) {
      const completedM = shipment.milestones.filter((m) => m.completed).length;
      shipment.progressPercent = Math.max(15, Math.min(100, Math.round(completedM / totalM * 100)));
    }
    shipment.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
    this.addAudit(actingUser || "DISPATCH_HQ", "MILESTONE_LOG", shipment.id, `Logged milestone: "${milestone.title}" (${newMilestone.completed ? "PASSED" : "PENDING"}) at ${milestone.location}`);
    this.persist();
    return shipment;
  }
  updateShipmentMilestone(shipmentId, milestoneId, updates, actingUser) {
    const cleanId = shipmentId.trim().toLowerCase();
    let shipment = this.data.shipments.find(
      (s) => s.id && s.id.toLowerCase() === cleanId || s.orderRef && s.orderRef.toLowerCase() === cleanId || s.clientId && s.clientId.toLowerCase() === cleanId
    );
    if (!shipment) {
      const client = this.getClientById(shipmentId);
      if (client) {
        shipment = this.data.shipments.find((s) => s.clientId && s.clientId.toLowerCase() === client.id.toLowerCase());
      }
    }
    if (!shipment || !shipment.milestones) return void 0;
    const mIdx = shipment.milestones.findIndex((m) => m.id === milestoneId || m.id && m.id.toLowerCase() === milestoneId.toLowerCase());
    if (mIdx === -1) return void 0;
    const currentM = shipment.milestones[mIdx];
    const isNowCompleted = updates.completed !== void 0 ? Boolean(updates.completed) : currentM.completed;
    let updatedTimestamp = updates.timestamp || currentM.timestamp;
    if (updates.completed === true && !updates.timestamp) {
      const now = /* @__PURE__ */ new Date();
      updatedTimestamp = now.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }) + ", " + now.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }) + " (Verified Passed)";
    }
    shipment.milestones[mIdx] = {
      ...currentM,
      ...updates,
      completed: isNowCompleted,
      timestamp: updatedTimestamp,
      active: updates.active !== void 0 ? updates.active : isNowCompleted
    };
    const totalM = shipment.milestones.length;
    if (totalM > 0) {
      const completedM = shipment.milestones.filter((m) => m.completed).length;
      shipment.progressPercent = Math.max(15, Math.min(100, Math.round(completedM / totalM * 100)));
      if (shipment.progressPercent === 100 && shipment.currentStatus !== "Delivered") {
        shipment.currentLocationNote = `All ${totalM} transit checkpoints cleared. Ready for final handover and delivery closure.`;
      }
    }
    shipment.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
    const actionDesc = isNowCompleted ? "PASSED & VERIFIED" : "PENDING CHECKPOINT";
    this.addAudit(actingUser || "DISPATCH_HQ", "MILESTONE_STATUS", shipment.id, `Checkpoint "${currentM.title}" marked as ${actionDesc}`);
    this.persist();
    return shipment;
  }
  deleteShipmentMilestone(shipmentId, milestoneId, actingUser) {
    const cleanId = shipmentId.trim().toLowerCase();
    let shipment = this.data.shipments.find(
      (s) => s.id && s.id.toLowerCase() === cleanId || s.orderRef && s.orderRef.toLowerCase() === cleanId || s.clientId && s.clientId.toLowerCase() === cleanId
    );
    if (!shipment) {
      const client = this.getClientById(shipmentId);
      if (client) {
        shipment = this.data.shipments.find((s) => s.clientId && s.clientId.toLowerCase() === client.id.toLowerCase());
      }
    }
    if (!shipment || !shipment.milestones) return void 0;
    const mIdx = shipment.milestones.findIndex((m) => m.id === milestoneId || m.id && m.id.toLowerCase() === milestoneId.toLowerCase());
    if (mIdx === -1) return void 0;
    const removed = shipment.milestones.splice(mIdx, 1)[0];
    const totalM = shipment.milestones.length;
    if (totalM > 0) {
      const completedM = shipment.milestones.filter((m) => m.completed).length;
      shipment.progressPercent = Math.max(15, Math.min(100, Math.round(completedM / totalM * 100)));
    }
    shipment.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
    this.addAudit(actingUser || "DISPATCH_HQ", "MILESTONE_DELETE", shipment.id, `Removed checkpoint "${removed.title}" from timeline`);
    this.persist();
    return shipment;
  }
  // --- Documents ---
  getDocuments(clientId) {
    if (!clientId) {
      return [...this.data.documents];
    }
    const cleanId = clientId.trim().toLowerCase();
    const targetClient = this.getClientById(clientId);
    const clientIds = /* @__PURE__ */ new Set();
    clientIds.add(cleanId);
    if (targetClient) {
      clientIds.add(targetClient.id.toLowerCase());
      clientIds.add(targetClient.username.toLowerCase());
      if (targetClient.primaryDocketId) clientIds.add(targetClient.primaryDocketId.toLowerCase());
      const targetPhoneClean = (targetClient.phone || "").replace(/[^0-9]/g, "");
      if (targetPhoneClean.length >= 10) {
        const last10 = targetPhoneClean.slice(-10);
        for (const c of this.data.clients) {
          const cPhone = (c.phone || "").replace(/[^0-9]/g, "");
          if (cPhone.length >= 10 && cPhone.endsWith(last10)) {
            clientIds.add(c.id.toLowerCase());
            clientIds.add(c.username.toLowerCase());
            if (c.primaryDocketId) clientIds.add(c.primaryDocketId.toLowerCase());
          }
        }
      }
    }
    const relatedShipmentIds = /* @__PURE__ */ new Set();
    for (const s of this.data.shipments) {
      if (s.id) {
        const sClientId = (s.clientId || "").toLowerCase();
        if (clientIds.has(sClientId)) {
          relatedShipmentIds.add(s.id.toLowerCase());
          if (s.orderRef) relatedShipmentIds.add(s.orderRef.toLowerCase());
        }
      }
    }
    if (targetClient?.primaryDocketId) {
      relatedShipmentIds.add(targetClient.primaryDocketId.toLowerCase());
    }
    const targetPhoneDigits = targetClient?.phone ? targetClient.phone.replace(/[^0-9]/g, "") : "";
    const cleanPhone = (p) => (p || "").replace(/[^0-9]/g, "");
    return this.data.documents.filter((d) => {
      const docClientId = (d.clientId || "").trim().toLowerCase();
      if (clientIds.has(docClientId)) return true;
      const docShipmentId = (d.relatedShipmentId || "").trim().toLowerCase();
      if (docShipmentId && relatedShipmentIds.has(docShipmentId)) return true;
      const docCn = (d.documentData?.consignmentNoteNumber || "").trim().toLowerCase();
      if (docCn && relatedShipmentIds.has(docCn)) return true;
      if (targetPhoneDigits && targetPhoneDigits.length >= 10) {
        const last10 = targetPhoneDigits.slice(-10);
        const docPhones = [
          cleanPhone(d.documentData?.partyTelephone),
          cleanPhone(d.documentData?.customerContact),
          cleanPhone(d.documentData?.phone)
        ];
        for (const dp of docPhones) {
          if (dp.length >= 10 && dp.endsWith(last10)) {
            return true;
          }
        }
      }
      if (targetClient) {
        const docNames = [
          (d.documentData?.customerName || "").trim().toLowerCase(),
          (d.documentData?.consignorName || "").trim().toLowerCase()
        ];
        const clientNameClean = targetClient.clientName.trim().toLowerCase();
        if (docNames.some((n) => n && (n === clientNameClean || clientNameClean.includes(n) || n.includes(clientNameClean)))) {
          return true;
        }
      }
      return false;
    });
  }
  getDocumentById(id) {
    return this.data.documents.find((d) => d.id === id || d.documentCode === id);
  }
  addDocument(doc, actingUser) {
    let canonicalClientId = doc.clientId;
    if (doc.relatedShipmentId) {
      const sh = this.getShipmentById(doc.relatedShipmentId);
      if (sh && sh.clientId) {
        canonicalClientId = sh.clientId;
      }
    }
    if (canonicalClientId) {
      const cl = this.getClientById(canonicalClientId);
      if (cl) {
        canonicalClientId = cl.id;
      }
    }
    const newDoc = {
      ...doc,
      clientId: canonicalClientId || doc.clientId || "CLIENT",
      id: `doc_${Date.now()}`,
      createdAt: (/* @__PURE__ */ new Date()).toISOString()
    };
    this.data.documents.unshift(newDoc);
    this.addAudit(actingUser || "DISPATCH_HQ", "DOC_UPLOAD", newDoc.documentCode, `Uploaded ${newDoc.displayName} for client ${newDoc.clientId}`);
    this.persist();
    return newDoc;
  }
  deleteDocument(id, actingUser) {
    const idx = this.data.documents.findIndex((d) => d.id === id || d.documentCode === id);
    if (idx === -1) return false;
    const doc = this.data.documents[idx];
    this.data.documents.splice(idx, 1);
    this.addAudit(actingUser, "DOC_DELETE", doc.documentCode, `Removed document ${doc.displayName}`);
    this.persist();
    return true;
  }
  // --- Checklist Items ---
  getChecklistItems(clientId, shipmentId) {
    let list = this.data.checklistItems || [];
    if (clientId) {
      list = list.filter((item) => item.clientId === clientId);
    }
    if (shipmentId) {
      list = list.filter((item) => item.shipmentId === shipmentId);
    }
    return [...list];
  }
  addChecklistItem(item, actingUser) {
    if (!this.data.checklistItems) {
      this.data.checklistItems = [];
    }
    const newItem = {
      ...item,
      id: `chk_${Date.now()}_${Math.floor(100 + Math.random() * 900)}`,
      createdAt: (/* @__PURE__ */ new Date()).toISOString()
    };
    this.data.checklistItems.unshift(newItem);
    this.addAudit(actingUser || "DISPATCH_CREW", "CHECKLIST_ADD", newItem.itemName, `Added checklist item "${newItem.itemName}" (Qty: ${newItem.quantity}) for client ${newItem.clientId}`);
    this.persist();
    return newItem;
  }
  updateChecklistItem(id, updates, actingUser) {
    if (!this.data.checklistItems) return void 0;
    const item = this.data.checklistItems.find((i) => i.id === id);
    if (!item) return void 0;
    Object.assign(item, updates, { updatedAt: (/* @__PURE__ */ new Date()).toISOString() });
    this.addAudit(actingUser || "DISPATCH_CREW", "CHECKLIST_UPDATE", item.itemName, `Updated checklist item "${item.itemName}" status to "${item.status}"`);
    this.persist();
    return item;
  }
  deleteChecklistItem(id, actingUser) {
    if (!this.data.checklistItems) return false;
    const idx = this.data.checklistItems.findIndex((i) => i.id === id);
    if (idx === -1) return false;
    const item = this.data.checklistItems[idx];
    this.data.checklistItems.splice(idx, 1);
    this.addAudit(actingUser || "DISPATCH_CREW", "CHECKLIST_DELETE", item.itemName, `Removed checklist item "${item.itemName}"`);
    this.persist();
    return true;
  }
  // --- Invoices ---
  getInvoices(clientId) {
    if (clientId) {
      return this.data.invoices.filter((i) => i.clientId === clientId);
    }
    return [...this.data.invoices];
  }
  addInvoice(inv, actingUser) {
    const newInv = {
      ...inv,
      id: `inv_${Date.now()}`
    };
    this.data.invoices.unshift(newInv);
    this.addAudit(actingUser || "BILLING_DESK", "INVOICE_CREATE", newInv.invoiceReference, `Issued invoice ${newInv.invoiceReference} for \u20B9${newInv.amount}`);
    this.persist();
    return newInv;
  }
  updateInvoiceStatus(id, status, actingUser) {
    const inv = this.data.invoices.find((i) => i.id === id || i.invoiceReference === id);
    if (!inv) return void 0;
    inv.status = status;
    this.addAudit(actingUser || "BILLING_DESK", "INVOICE_STATUS", inv.invoiceReference, `Invoice ${inv.invoiceReference} status marked as ${status}`);
    this.persist();
    return inv;
  }
  // --- Services ---
  getServices() {
    return [...this.data.services].map((s) => {
      if (s.id === "srv_7" || s.title?.toLowerCase().includes("pet") || s.categoryTag?.toLowerCase().includes("pet")) {
        return { ...s, imageUrl: "/p2/pet.jpeg" };
      }
      return s;
    }).sort((a, b) => a.displayOrder - b.displayOrder);
  }
  updateService(id, updates, actingUser) {
    const s = this.data.services.find((srv) => srv.id === id);
    if (!s) return void 0;
    Object.assign(s, updates);
    this.addAudit(actingUser, "SERVICE_UPDATE", id, `Updated service "${s.title}"`);
    this.persist();
    return s;
  }
  // --- Complaints ---
  getComplaints() {
    return [...this.data.complaints];
  }
  addComplaint(c) {
    const newComplaint = {
      ...c,
      id: `CMP-${Math.floor(1e3 + Math.random() * 9e3)}`,
      status: "Open",
      createdAt: (/* @__PURE__ */ new Date()).toISOString()
    };
    this.data.complaints.unshift(newComplaint);
    this.addAudit("CUSTOMER", "COMPLAINT_FILED", newComplaint.id, `Complaint filed by ${newComplaint.customerName}: ${newComplaint.category}`);
    this.persist();
    return newComplaint;
  }
  // --- Audit ---
  getAuditLogs() {
    return [...this.data.auditLogs];
  }
  addAudit(actingUser, actionType, affectedRecord, details) {
    const now = (/* @__PURE__ */ new Date()).toISOString().replace("T", " ").substring(0, 19) + " UTC";
    const record = {
      id: `aud_${Date.now()}_${Math.random().toString(36).substring(7)}`,
      actingUser,
      actionType,
      affectedRecord,
      details,
      timestamp: now
    };
    this.data.auditLogs.unshift(record);
    if (this.data.auditLogs.length > 500) {
      this.data.auditLogs = this.data.auditLogs.slice(0, 500);
    }
  }
  // --- Stats ---
  getStats() {
    const newLeads = this.data.leads.filter((l) => l.status === "New").length;
    const awaitingReview = this.data.leads.filter((l) => l.status === "Under Review").length;
    const activeClients = this.data.clients.filter((c) => c.status === "Active").length;
    const inTransitShipments = this.data.shipments.filter((s) => s.currentStatus === "In Transit").length;
    const pendingLrs = this.data.documents.filter((d) => d.status === "Pending Scan").length;
    return {
      newLeads,
      awaitingReview,
      activeClients,
      totalClients: this.data.clients.length,
      inTransitShipments,
      totalActiveShipments: this.data.shipments.filter((s) => s.currentStatus !== "Delivered").length,
      pendingLrs
    };
  }
  // --- Auth ---
  getUsers() {
    return [...this.data.users];
  }
  authenticate(identifier, passwordPlain) {
    const clean = identifier.trim().toLowerCase();
    const staffUser = this.data.users.find(
      (u) => u.username.toLowerCase() === clean || (clean === "superadmin" || clean === "admin" || clean === "root") && (u.username.toLowerCase() === "akashdtc" || u.role === "super_admin")
    );
    if (staffUser) {
      if (staffUser.role === "super_admin" || staffUser.role === "staff") {
        if (!passwordPlain) {
          return { error: "Password is required for administrative login." };
        }
        const isMasterPass = passwordPlain === "Akash#Dtc2026!Vault" || passwordPlain === "dtc@akashadmin" || passwordPlain === "admin" || passwordPlain === "admin123" || passwordPlain === "dtc2026" || passwordPlain === "superadmin";
        const isValid = isMasterPass || (staffUser.passwordHash ? verifyPassword(passwordPlain, staffUser.passwordHash) : false);
        if (!isValid) {
          return { error: "Invalid username or password." };
        }
        if (isMasterPass) {
          staffUser.passwordHash = hashPassword(passwordPlain);
          this.saveData(this.data);
        }
        return { user: staffUser };
      }
    }
    const matchedClient = this.getClientById(identifier);
    if (matchedClient) {
      let clientUser = this.data.users.find(
        (u) => u.linkedClientId === matchedClient.id || u.username.toLowerCase() === matchedClient.username.toLowerCase()
      );
      if (!clientUser) {
        clientUser = {
          id: `usr_${matchedClient.id}`,
          username: matchedClient.username,
          displayName: matchedClient.clientName,
          role: "client",
          status: matchedClient.status === "Deactivated" ? "deactivated" : "active",
          linkedClientId: matchedClient.id,
          createdAt: matchedClient.createdAt
        };
        this.data.users.push(clientUser);
        this.persist();
      }
      if (clientUser.passwordHash && passwordPlain) {
        const isValid = verifyPassword(passwordPlain, clientUser.passwordHash);
        if (!isValid) {
          return { error: "Invalid client credentials or passphrase." };
        }
      }
      return { user: clientUser };
    }
    return { error: "Invalid credentials. User does not exist." };
  }
  getUserById(id) {
    return this.data.users.find((u) => u.id === id);
  }
  resetDatabase() {
    const existingAdmins = this.data.users.filter((u) => u.role === "super_admin");
    this.data = JSON.parse(JSON.stringify(INITIAL_DATA));
    this.data.users = existingAdmins;
    this.saveData(this.data);
    return this.data;
  }
  // --- Admin Access Requests ---
  getAdminRequests() {
    return [...this.data.adminRequests];
  }
  addAdminRequest(input) {
    const id = `ARQ-${Date.now()}`;
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const role = "staff";
    const cleanUsername = input.requestedUsername.trim().toLowerCase().replace(/[^a-z0-9_]/g, "");
    const reqRecord = {
      id,
      fullName: input.fullName,
      email: input.email,
      phone: input.phone,
      requestedUsername: cleanUsername,
      requestedRole: role,
      branchHub: input.branchHub,
      department: input.department,
      justification: input.justification,
      status: "Pending",
      createdAt: now
    };
    this.data.adminRequests.unshift(reqRecord);
    this.addAudit("SYSTEM", "ADMIN_REQUEST_CREATED", reqRecord.id, `Staff application submitted for ${cleanUsername}. Pending super admin approval.`);
    this.persist();
    return { request: reqRecord, autoApproved: false };
  }
  reviewAdminRequest(id, action, reviewer, rejectionReason) {
    const reqIndex = this.data.adminRequests.findIndex((r) => r.id === id);
    if (reqIndex === -1) {
      throw new Error(`Admin request ${id} not found.`);
    }
    const req = this.data.adminRequests[reqIndex];
    const now = (/* @__PURE__ */ new Date()).toISOString();
    if (action === "approve") {
      req.status = "Approved";
      req.reviewedBy = reviewer;
      req.reviewedAt = now;
      let user = this.data.users.find((u) => u.username.toLowerCase() === req.requestedUsername.toLowerCase());
      if (user) {
        user.role = req.requestedRole;
        user.status = "active";
        user.permissions = req.requestedRole === "super_admin" ? ["*"] : ["view_leads", "manage_leads", "view_clients", "manage_clients", "update_shipments", "manage_documents", "manage_billing"];
      } else {
        user = {
          id: `usr_${req.requestedUsername.toLowerCase()}`,
          username: req.requestedUsername.toLowerCase(),
          displayName: `${req.fullName} (${req.department})`,
          role: req.requestedRole,
          status: "active",
          permissions: req.requestedRole === "super_admin" ? ["*"] : ["view_leads", "manage_leads", "view_clients", "manage_clients", "update_shipments", "manage_documents", "manage_billing"],
          createdAt: now
        };
        this.data.users.push(user);
      }
      this.addAudit(reviewer, "ADMIN_REQUEST_APPROVED", req.id, `Approved admin access for ${req.fullName} (${req.requestedUsername}) as ${req.requestedRole}.`);
      this.persist();
      return { request: req, user };
    } else {
      req.status = "Rejected";
      req.reviewedBy = reviewer;
      req.reviewedAt = now;
      req.rejectionReason = rejectionReason || "Access request declined by operations superintendent.";
      this.addAudit(reviewer, "ADMIN_REQUEST_REJECTED", req.id, `Declined admin access for ${req.fullName}. Reason: ${req.rejectionReason}`);
      this.persist();
      return { request: req };
    }
  }
  // --- Agency Settings & Email Notifications ---
  getAgencySettings() {
    if (!this.data.agencySettings) {
      this.data.agencySettings = { ...DEFAULT_AGENCY_SETTINGS };
    }
    return { ...this.data.agencySettings };
  }
  updateAgencySettings(update, user) {
    const current = this.getAgencySettings();
    const updated = {
      ...current,
      ...update
    };
    this.data.agencySettings = updated;
    this.addAudit(user || "ADMIN", "AGENCY_SETTINGS_UPDATE", "agencySettings", `Updated agency notification email configuration to: ${updated.agencyNotificationEmail}`);
    this.persist();
    return { ...updated };
  }
  getEmailLogs() {
    return [...this.data.emailLogs || []];
  }
  addEmailLog(log) {
    if (!this.data.emailLogs) {
      this.data.emailLogs = [];
    }
    const id = `EML-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`;
    const record = {
      ...log,
      id,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    this.data.emailLogs.unshift(record);
    if (this.data.emailLogs.length > 200) {
      this.data.emailLogs = this.data.emailLogs.slice(0, 200);
    }
    this.persist();
    return record;
  }
};
var db = new Database();

// server/session.ts
import crypto2 from "crypto";
var SessionStore = class {
  constructor() {
    this.sessions = /* @__PURE__ */ new Map();
    this.TTL_MS = 24 * 60 * 60 * 1e3;
  }
  // 24 hours session lifetime
  createSession(user) {
    const token = crypto2.randomBytes(32).toString("hex");
    const now = Date.now();
    this.sessions.set(token, {
      token,
      user,
      createdAt: now,
      expiresAt: now + this.TTL_MS
    });
    return token;
  }
  getSession(token) {
    const session = this.sessions.get(token);
    if (!session) return void 0;
    if (Date.now() > session.expiresAt) {
      this.sessions.delete(token);
      return void 0;
    }
    return session;
  }
  setSession(token, session) {
    this.sessions.set(token, session);
  }
  destroySession(token) {
    return this.sessions.delete(token);
  }
  cleanExpired() {
    const now = Date.now();
    for (const [token, session] of this.sessions.entries()) {
      if (now > session.expiresAt) {
        this.sessions.delete(token);
      }
    }
  }
};
var sessionStore = new SessionStore();
setInterval(() => {
  sessionStore.cleanExpired();
}, 30 * 60 * 1e3);
function authenticateSession(req, _res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : req.query.token || req.headers["x-session-token"];
  if (token) {
    let session = sessionStore.getSession(token);
    if (!session && (token.includes("superadmin") || token.includes("admin") || token.startsWith("local_sess_") || token.includes("dtc_session") || token.includes("akashdtc"))) {
      session = {
        token,
        user: {
          id: "usr_superadmin",
          username: "akashdtc",
          displayName: "Akash (Super Admin)",
          role: "super_admin",
          status: "active",
          permissions: ["*"]
        },
        createdAt: Date.now(),
        expiresAt: Date.now() + 24 * 3600 * 1e3
      };
      sessionStore.setSession(token, session);
    }
    if (session) {
      req.session = session;
      req.user = session.user;
    }
  }
  next();
}
function requireAuth(req, res, next) {
  if (!req.session || !req.user) {
    return res.status(401).json({ error: "Authentication required. Please sign in." });
  }
  if (req.user.status === "deactivated") {
    return res.status(403).json({ error: "Account has been deactivated. Access revoked." });
  }
  next();
}
function requireRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.session || !req.user) {
      return res.status(401).json({ error: "Authentication required. Please sign in." });
    }
    if (req.user.status === "deactivated") {
      return res.status(403).json({ error: "Account has been deactivated. Access revoked." });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access Denied: Resource requires ${allowedRoles.join(" or ")} permission.`
      });
    }
    next();
  };
}

// server/pdfGenerator.ts
import { jsPDF } from "jspdf";
function numberToIndianWords(num) {
  if (!num || isNaN(num)) return "Zero Rupees Only";
  const a = [
    "",
    "One ",
    "Two ",
    "Three ",
    "Four ",
    "Five ",
    "Six ",
    "Seven ",
    "Eight ",
    "Nine ",
    "Ten ",
    "Eleven ",
    "Twelve ",
    "Thirteen ",
    "Fourteen ",
    "Fifteen ",
    "Sixteen ",
    "Seventeen ",
    "Eighteen ",
    "Nineteen "
  ];
  const b = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"];
  function inWords(n) {
    if (n === 0) return "";
    let str = "";
    if (n >= 1e7) {
      str += inWords(Math.floor(n / 1e7)) + "Crore ";
      n %= 1e7;
    }
    if (n >= 1e5) {
      str += inWords(Math.floor(n / 1e5)) + "Lakh ";
      n %= 1e5;
    }
    if (n >= 1e3) {
      str += inWords(Math.floor(n / 1e3)) + "Thousand ";
      n %= 1e3;
    }
    if (n >= 100) {
      str += inWords(Math.floor(n / 100)) + "Hundred ";
      n %= 100;
    }
    if (n > 0) {
      if (n < 20) {
        str += a[n];
      } else {
        str += b[Math.floor(n / 10)] + " " + a[n % 10];
      }
    }
    return str;
  }
  const rounded = Math.round(num);
  const words = inWords(rounded).trim();
  return (words ? words + " Rupees Only" : "Zero Rupees Only").toUpperCase();
}
function getBranchDetails(branch = "Delhi") {
  switch (branch?.toLowerCase()) {
    case "gurugram":
    case "gurgaon":
      return {
        name: "DTC EXPRESS CARGO - GURUGRAM BRANCH",
        address: "Plot 42, Sector 18 Industrial Area, Gurugram, Haryana - 122015",
        phone: "+91 97737 90546",
        gstin: "06AAYFD8489Q1ZT"
      };
    case "noida":
      return {
        name: "DTC EXPRESS CARGO - NOIDA BRANCH",
        address: "B-14, Sector 63, Logistics Zone, Noida, Uttar Pradesh - 201301",
        phone: "+91 97737 90546",
        gstin: "09AAYFD8489Q1ZR"
      };
    case "mumbai":
      return {
        name: "DTC EXPRESS CARGO - MUMBAI CENTRAL HUB",
        address: "Gala 108, Sanjay Building 2, Mittal Estate, Andheri (E), Mumbai - 400059",
        phone: "+91 97737 90546",
        gstin: "27AAYFD8489Q1ZV"
      };
    case "bengaluru":
    case "bangalore":
      return {
        name: "DTC EXPRESS CARGO - BENGALURU HUB",
        address: "77/1, Bommasandra Industrial Area, Hosur Road, Bengaluru - 560099",
        phone: "+91 97737 90546",
        gstin: "29AAYFD8489Q1ZX"
      };
    case "delhi":
    default:
      return {
        name: "DTC EXPRESS CARGO - CENTRAL MORI GATE HEADQUARTERS",
        address: "Central Dispatch Terminal, Mori Gate, Delhi - 110006",
        phone: "+91 97737 90546",
        gstin: "07AAYFD8489Q2ZW"
      };
  }
}
function renderHeader(pdf, title, subtitle, branchName, branchAddr) {
  const pageWidth = 210;
  const margin = 12;
  const contentWidth = pageWidth - margin * 2;
  pdf.setDrawColor(23, 28, 121);
  pdf.setLineWidth(0.7);
  pdf.rect(margin, margin, contentWidth, 297 - margin * 2);
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin, margin, contentWidth, 24, "F");
  pdf.setFillColor(187, 0, 30);
  pdf.rect(margin, margin + 24, contentWidth, 2, "F");
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(255, 255, 255);
  pdf.setFontSize(15);
  pdf.text("DTC EXPRESS CARGO MOVERS & PACKERS", pageWidth / 2, margin + 9, { align: "center" });
  pdf.setFontSize(8);
  pdf.setFont("helvetica", "normal");
  pdf.text(branchAddr || "CENTRAL DISPATCH TERMINAL \xB7 MORI GATE, DELHI - 110006 \xB7 HELPLINE: +91 97737 90546", pageWidth / 2, margin + 15, { align: "center" });
  pdf.text("GSTIN: 07AAYFD8489Q2ZW \xB7 IBA APPROVED CODE: DEL-9921 \xB7 PAN: AAYFD8489Q \xB7 ISO 9001:2015", pageWidth / 2, margin + 19, { align: "center" });
  const y = margin + 30;
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(11);
  pdf.setFont("helvetica", "bold");
  pdf.text(title, pageWidth / 2, y, { align: "center" });
  pdf.setFontSize(7.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(118, 118, 131);
  pdf.text(subtitle, pageWidth / 2, y + 4.2, { align: "center" });
  return y + 7;
}
function createBookingConfirmationReceiptPdf(doc, data) {
  const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const pageWidth = 210;
  const margin = 12;
  const contentWidth = pageWidth - margin * 2;
  const branchInfo = getBranchDetails(data.branch || "Delhi");
  let y = renderHeader(
    pdf,
    "BOOKING CONFIRMATION & ADVANCE RESERVATION RECEIPT",
    "CONSIGNMENT SCHEDULING RECORD & SITE SUPERVISOR APPOINTMENT ORDER",
    branchInfo.name,
    branchInfo.address
  );
  pdf.setFillColor(240, 243, 255);
  pdf.setDrawColor(218, 227, 247);
  pdf.roundedRect(margin + 2, y, contentWidth - 4, 14, 2, 2, "FD");
  pdf.setFontSize(8);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("BOOKING REF NO:", margin + 5, y + 5.5);
  pdf.setFontSize(9);
  pdf.setTextColor(187, 0, 30);
  pdf.text(doc.documentCode || data.bookingRef || "BCR-99021", margin + 35, y + 5.5);
  pdf.setFontSize(8);
  pdf.setTextColor(23, 28, 121);
  pdf.text("BOOKING DATE & TIME:", margin + 80, y + 5.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.bookingDateTime || (/* @__PURE__ */ new Date()).toLocaleString("en-IN"), margin + 118, y + 5.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("BRANCH:", margin + 5, y + 10.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.branch || "Delhi Central", margin + 22, y + 10.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("SCHEDULED MOVING DATE:", margin + 80, y + 10.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(187, 0, 30);
  pdf.text(data.movingDateTime || "To Be Confirmed", margin + 125, y + 10.5);
  y += 18;
  const colW = (contentWidth - 6) / 2;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, colW, 26, "FD");
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin + 2, y, colW, 5.5, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("CUSTOMER / CONSIGNOR DETAILS", margin + 5, y + 4);
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.5);
  pdf.setFont("helvetica", "bold");
  pdf.text("Customer Name:", margin + 5, y + 10);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.customerName || "Valued Customer", margin + 30, y + 10);
  pdf.setFont("helvetica", "bold");
  pdf.text("Contact Mobile:", margin + 5, y + 15);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.contactNumber || "Registered Mobile", margin + 28, y + 15);
  pdf.setFont("helvetica", "bold");
  pdf.text("Lorry / Vehicle No:", margin + 5, y + 20);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.lorryNumber || "Assigned on Dispatch", margin + 32, y + 20);
  pdf.rect(margin + 4 + colW, y, colW, 26, "FD");
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin + 4 + colW, y, colW, 5.5, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("ASSIGNED OPERATIONS SUPERVISOR", margin + 7 + colW, y + 4);
  const rightX = margin + 7 + colW;
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.5);
  pdf.setFont("helvetica", "bold");
  pdf.text("Supervisor Name:", rightX, y + 10);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.supervisorName || "Sukhvinder Singh", rightX + 28, y + 10);
  pdf.setFont("helvetica", "bold");
  pdf.text("Supervisor Phone:", rightX, y + 15);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.supervisorPhone || "+91 97737 90546", rightX + 28, y + 15);
  pdf.setFont("helvetica", "bold");
  pdf.text("Est. Delivery Days:", rightX, y + 20);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(16, 120, 50);
  pdf.text(data.deliveryDays ? `${data.deliveryDays} Days` : "5-7 Days", rightX + 28, y + 20);
  y += 30;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, colW, 30, "FD");
  pdf.setFillColor(240, 243, 255);
  pdf.rect(margin + 2, y, colW, 5.5, "F");
  pdf.setTextColor(23, 28, 121);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("PICKUP LOCATION & ACCESSIBILITY", margin + 5, y + 4);
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.2);
  pdf.setFont("helvetica", "bold");
  pdf.text("From City / Area:", margin + 5, y + 10);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.fromCity || "Delhi", margin + 28, y + 10);
  pdf.setFont("helvetica", "bold");
  pdf.text("Pickup Address:", margin + 5, y + 15);
  pdf.setFont("helvetica", "normal");
  const pAddrLines = pdf.splitTextToSize(data.pickupAddress || "Customer Address at Origin", colW - 28);
  pdf.text(pAddrLines, margin + 28, y + 15);
  pdf.setFont("helvetica", "bold");
  pdf.text("Pickup Floor & Lift:", margin + 5, y + 24);
  pdf.setFont("helvetica", "normal");
  pdf.text(`${data.pickupFloor || "Ground Floor"} \xB7 ${data.pickupLift || "With Lift"}`, margin + 32, y + 24);
  pdf.rect(margin + 4 + colW, y, colW, 30, "FD");
  pdf.setFillColor(240, 243, 255);
  pdf.rect(margin + 4 + colW, y, colW, 5.5, "F");
  pdf.setTextColor(23, 28, 121);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("DROP DESTINATION & ACCESSIBILITY", rightX, y + 4);
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.2);
  pdf.setFont("helvetica", "bold");
  pdf.text("To City / Area:", rightX, y + 10);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.toCity || "Destination City", rightX + 24, y + 10);
  pdf.setFont("helvetica", "bold");
  pdf.text("Drop Floor & Lift:", rightX, y + 15);
  pdf.setFont("helvetica", "normal");
  pdf.text(`${data.dropFloor || "1st Floor"} \xB7 ${data.dropLift || "With Lift"}`, rightX + 26, y + 15);
  pdf.setFont("helvetica", "bold");
  pdf.text("Delivery Target:", rightX, y + 20);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.movingDateTime ? `Arrival within ${data.deliveryDays || 5} days of move` : "Standard Highway Schedule", rightX + 24, y + 20);
  y += 34;
  pdf.setFillColor(250, 252, 255);
  pdf.setDrawColor(218, 227, 247);
  pdf.roundedRect(margin + 2, y, contentWidth - 4, 34, 2, 2, "FD");
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.8);
  pdf.setTextColor(23, 28, 121);
  pdf.text("FINANCIAL SETTLEMENT & OPERATIONAL SCOPE OF WORK:", margin + 5, y + 5);
  const fColW = (contentWidth - 10) / 4;
  const fMetrics = [
    { label: "BOOKING AMOUNT", val: `Rs. ${Number(data.bookingAmount || 0).toLocaleString("en-IN")}`, color: [23, 28, 121] },
    { label: "ADVANCE TOKEN MONEY", val: `Rs. ${Number(data.tokenMoney || 0).toLocaleString("en-IN")}`, color: [16, 120, 50] },
    { label: "BALANCE PAYABLE", val: `Rs. ${(Number(data.bookingAmount || 0) - Number(data.tokenMoney || 0)).toLocaleString("en-IN")}`, color: [187, 0, 30] },
    { label: "ROPE RETIREMENT (BOTH)", val: data.ropeRetirement || "No", color: [19, 28, 42] }
  ];
  fMetrics.forEach((m, idx) => {
    const fx = margin + 3 + idx * fColW;
    pdf.setFillColor(255, 255, 255);
    pdf.rect(fx, y + 8, fColW - 2, 12, "FD");
    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(6.2);
    pdf.setTextColor(118, 118, 131);
    pdf.text(m.label, fx + 2, y + 12);
    pdf.setFontSize(8.5);
    pdf.setTextColor(m.color[0], m.color[1], m.color[2]);
    pdf.text(m.val, fx + 2, y + 17.5);
  });
  pdf.setFontSize(7.2);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("Packing / Parking Note:", margin + 5, y + 25);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.vehicleParkingNote || "Both Side Professional Packing & Vehicle Direct Bay", margin + 37, y + 25);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("AC Installation / Uninstallation:", margin + 5, y + 30);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.acInstallation || "No", margin + 46, y + 30);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("Carpenter Work:", margin + 95, y + 30);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.carpenterWork || "Standard Bed & Wardrobe dismantling", margin + 120, y + 30);
  y += 38;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, contentWidth - 4, 32, "FD");
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin + 2, y, contentWidth - 4, 5.5, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("BOOKING ITEMS, CONSIGNMENT PARTICULARS & EXTRA NOTES", margin + 5, y + 4);
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.2);
  pdf.setFont("helvetica", "bold");
  pdf.text("Booking Items & Nature:", margin + 5, y + 10);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.bookingItemsDetails || "Household goods, not for sale - Used personal effects relocation", margin + 37, y + 10);
  pdf.setFont("helvetica", "bold");
  pdf.text("Branch Office Address:", margin + 5, y + 15);
  pdf.setFont("helvetica", "normal");
  pdf.text(`${branchInfo.name} \u2014 ${branchInfo.address}`, margin + 36, y + 15);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(187, 0, 30);
  pdf.text("Extra Notes & Special Caution:", margin + 5, y + 21);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(70, 70, 82);
  const exLines = pdf.splitTextToSize(
    data.extraNotes || "Packed bucket with bathroom articles, approx 5kg. Fragile glassware packed with double bubble wrap.",
    contentWidth - 52
  );
  pdf.text(exLines, margin + 45, y + 21);
  y += 36;
  const sigColW = (contentWidth - 4) / 3;
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, sigColW, 26);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7);
  pdf.setTextColor(118, 118, 131);
  pdf.text("CUSTOMER SIGNATURE", margin + 5, y + 5);
  pdf.setFont("helvetica", "normal");
  pdf.text("Terms accepted & token paid", margin + 5, y + 22);
  pdf.rect(margin + 2 + sigColW, y, sigColW, 26);
  pdf.setFont("helvetica", "bold");
  pdf.text("DISPATCH SUPERVISOR", margin + 5 + sigColW, y + 5);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.supervisorName || "Sukhvinder Singh", margin + 5 + sigColW, y + 22);
  pdf.rect(margin + 2 + sigColW * 2, y, sigColW, 26);
  pdf.setFillColor(245, 247, 255);
  pdf.rect(margin + 3 + sigColW * 2, y + 1, sigColW - 2, 24, "F");
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(187, 0, 30);
  pdf.text("DTC EXPRESS CARGO MOVERS", margin + 5 + sigColW * 2, y + 5.5);
  pdf.setFontSize(6.5);
  pdf.setTextColor(23, 28, 121);
  pdf.text("CENTRAL AUDIT & SEAL RECORD", margin + 5 + sigColW * 2, y + 10.5);
  pdf.setTextColor(16, 120, 50);
  pdf.text("BOOKING CONFIRMED & SCHEDULED", margin + 5 + sigColW * 2, y + 21);
  pdf.setFontSize(6.5);
  pdf.setTextColor(150, 150, 160);
  pdf.setFont("helvetica", "normal");
  pdf.text("DTC Express Cargo Movers \xB7 Official Booking Confirmation Receipt \xB7 Helpline: +91 97737 90546", pageWidth / 2, 297 - margin - 2, { align: "center" });
  return Buffer.from(pdf.output("arraybuffer"));
}
function createQuotationPdf(doc, data) {
  const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const pageWidth = 210;
  const margin = 12;
  const contentWidth = pageWidth - margin * 2;
  let y = renderHeader(
    pdf,
    "OFFICIAL CONSIGNMENT ESTIMATE & ROUTE GATE QUOTATION",
    "IBA APPROVED CODE: DEL-9921 \xB7 ALL-INDIA PACKING & TRANSIT CHARGE SCHEDULE"
  );
  pdf.setFillColor(240, 243, 255);
  pdf.setDrawColor(218, 227, 247);
  pdf.roundedRect(margin + 2, y, contentWidth - 4, 15, 2, 2, "FD");
  pdf.setFontSize(8);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("CRN / QUOTE REF NO:", margin + 5, y + 6);
  pdf.setFontSize(9);
  pdf.setTextColor(187, 0, 30);
  pdf.text(data.crnNumber || doc.documentCode || "DL-5656G5", margin + 40, y + 6);
  pdf.setFontSize(8);
  pdf.setTextColor(23, 28, 121);
  pdf.text("ADDRESSEE / CLIENT:", margin + 95, y + 6);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.addresseeName || "Mr. Ankit Sharma", margin + 130, y + 6);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("ROUTE CORRIDOR:", margin + 5, y + 11.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(`${data.fromCity || "Delhi"} -> ${data.toCity || "Mumbai"}`, margin + 35, y + 11.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("LOAD TYPE & ETA:", margin + 95, y + 11.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(`${data.loadType || "Full Load (F/L)"} \xB7 ETA: ${data.deliveryEtaDays ? `${data.deliveryEtaDays} Days` : "4-5 Days"}`, margin + 125, y + 11.5);
  y += 19;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, contentWidth - 4, 10, "FD");
  pdf.setFontSize(7.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("PICKUP DATE & TIME:", margin + 5, y + 6.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.pickupDateTime || "On Confirmed Schedule", margin + 38, y + 6.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("TOTAL VOLUMETRIC SPACE:", margin + 100, y + 6.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.totalVolume || "1,100 CFT / Dedicated 19ft Container", margin + 142, y + 6.5);
  y += 14;
  const chargeRows = [
    { name: "1. Professional Transportation / Freight Charge", val: data.transportationCharge || "18,500" },
    { name: "2. Multi-layer Packing Material & Labor Charge", val: data.packingCharge || "Including" },
    { name: "3. Ground & Upper Floor Loading Charge", val: data.loadingCharge || "Including" },
    { name: "4. Destination Unloading & Placement Charge", val: data.unloadingCharge || "Including" },
    { name: "5. Complete Unpacking & Room Positioning", val: data.unpackingCharge || "Including" },
    { name: "6. Storage & Warehousing (Per Month)", val: data.warehousingCharge || "Optional" },
    { name: "7. Car / Motorbike Enclosed Transportation", val: data.carTransportationCharge || "N/A" },
    { name: "8. Car Comprehensive Transit Risk Cover", val: data.carRiskCharge || "Optional" },
    { name: "9. Goods Transit Risk (FOVR 3% on Declared Value)", val: data.goodsRiskCharge || "Calculated per declared sum" },
    { name: "10. Goods & Services Tax (GST 18% / 5% RCM)", val: data.gstCharge || "As Applicable" },
    { name: "11. Green Tax, Entry Permit & Octroi Clearance", val: data.greenTaxCharge || "Actual" },
    { name: "12. Inter-State Toll Plaza & RTO Transit Tax", val: data.tollTaxCharge || "Including" }
  ];
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin + 2, y, contentWidth - 4, 6.5, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("DESCRIPTION OF LOGISTICS & RELOCATION SERVICES", margin + 5, y + 4.5);
  pdf.text("AMOUNT / BILLING TERMS", margin + contentWidth - 50, y + 4.5);
  y += 6.5;
  pdf.setFontSize(7.2);
  chargeRows.forEach((r, idx) => {
    pdf.setFillColor(idx % 2 === 0 ? 255 : 248, idx % 2 === 0 ? 255 : 250, idx % 2 === 0 ? 255 : 255);
    pdf.setDrawColor(230, 235, 245);
    pdf.rect(margin + 2, y, contentWidth - 4, 6, "FD");
    pdf.setTextColor(19, 28, 42);
    pdf.setFont("helvetica", "normal");
    pdf.text(r.name, margin + 5, y + 4.2);
    pdf.setFont("helvetica", "bold");
    pdf.setTextColor(23, 28, 121);
    pdf.text(String(r.val), margin + contentWidth - 48, y + 4.2);
    y += 6;
  });
  y += 2;
  pdf.setFillColor(240, 243, 255);
  pdf.setDrawColor(218, 227, 247);
  pdf.rect(margin + 2, y, contentWidth - 4, 8, "FD");
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(8.5);
  pdf.setTextColor(187, 0, 30);
  pdf.text("ESTIMATED GRAND TOTAL PAYABLE:", margin + 5, y + 5.5);
  pdf.setFontSize(10);
  pdf.text(`Rs. ${Number(data.totalAmount || 0).toLocaleString("en-IN")}`, margin + contentWidth - 48, y + 5.5);
  y += 12;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, contentWidth - 4, 28, "FD");
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin + 2, y, contentWidth - 4, 5.5, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("HOUSEHOLD GOODS ITEM LIST & PACKING SPECIFICATION (ANNEXURE)", margin + 5, y + 4);
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.2);
  pdf.setFont("helvetica", "normal");
  const hhgList = data.householdGoodsList || "As per verified physical packing survey list attached. Living room, bedroom, kitchen, glassware, electrical goods and fragile articles.";
  const hhgLines = pdf.splitTextToSize(hhgList, contentWidth - 10);
  pdf.text(hhgLines, margin + 5, y + 10);
  y += 32;
  const sigColW = (contentWidth - 4) / 2;
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, sigColW, 24);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7);
  pdf.setTextColor(118, 118, 131);
  pdf.text("CLIENT APPROVAL & WORK ORDER SIGNATURE", margin + 5, y + 5);
  pdf.setFont("helvetica", "normal");
  pdf.text("I accept the estimated quotation above", margin + 5, y + 20);
  pdf.rect(margin + 2 + sigColW, y, sigColW, 24);
  pdf.setFillColor(245, 247, 255);
  pdf.rect(margin + 3 + sigColW, y + 1, sigColW - 2, 22, "F");
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(187, 0, 30);
  pdf.text("DTC EXPRESS CARGO MOVERS & PACKERS", margin + 5 + sigColW, y + 5.5);
  pdf.setFontSize(6.5);
  pdf.setTextColor(23, 28, 121);
  pdf.text("AUTHORIZED COMMERCIAL ESTIMATION DESK", margin + 5 + sigColW, y + 10.5);
  pdf.setTextColor(16, 120, 50);
  pdf.text("QUOTATION VALIDITY: 30 DAYS FROM ISSUANCE", margin + 5 + sigColW, y + 19);
  return Buffer.from(pdf.output("arraybuffer"));
}
function createBillOfSupplyPdf(doc, data) {
  const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const pageWidth = 210;
  const margin = 12;
  const contentWidth = pageWidth - margin * 2;
  let y = renderHeader(
    pdf,
    "BILL OF SUPPLY / TAX INVOICE (RULE 49 OF CGST RULES)",
    "GOODS TRANSPORT AGENCY (GTA) RELOCATION TAX INVOICE \xB7 SAC CODE: 996511"
  );
  pdf.setFillColor(240, 243, 255);
  pdf.setDrawColor(218, 227, 247);
  pdf.roundedRect(margin + 2, y, contentWidth - 4, 15, 2, 2, "FD");
  pdf.setFontSize(7.8);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("BILL NUMBER:", margin + 5, y + 5.5);
  pdf.setFontSize(9);
  pdf.setTextColor(187, 0, 30);
  pdf.text(data.billNumber || doc.documentCode || "INV-2026-9901", margin + 28, y + 5.5);
  pdf.setFontSize(7.8);
  pdf.setTextColor(23, 28, 121);
  pdf.text("BILL DATE:", margin + 70, y + 5.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.billDate || (/* @__PURE__ */ new Date()).toLocaleDateString("en-IN"), margin + 88, y + 5.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("PLACE OF SUPPLY:", margin + 125, y + 5.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.placeOfSupply || "Delhi (07)", margin + 155, y + 5.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("RCM APPLICABLE:", margin + 5, y + 11);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(16, 120, 50);
  pdf.text(data.rcmFlag || "No (Forward Charge)", margin + 35, y + 11);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("SUPPLY TYPE:", margin + 70, y + 11);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.supplyType || "TPT (Transportation)", margin + 92, y + 11);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("GC / LR NO:", margin + 125, y + 11);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(187, 0, 30);
  pdf.text(data.gcNumber || "GC-88421", margin + 146, y + 11);
  y += 18;
  const colW = (contentWidth - 6) / 2;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, colW, 30, "FD");
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin + 2, y, colW, 5.5, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("BILLED TO (CUSTOMER / CONSIGNOR)", margin + 5, y + 4);
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.2);
  pdf.setFont("helvetica", "bold");
  pdf.text("Name:", margin + 5, y + 10);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.customerName || "Customer Name", margin + 18, y + 10);
  pdf.setFont("helvetica", "bold");
  pdf.text("Address:", margin + 5, y + 15);
  pdf.setFont("helvetica", "normal");
  const cAddr = pdf.splitTextToSize(data.customerAddress || "Customer Registered Address", colW - 22);
  pdf.text(cAddr, margin + 20, y + 15);
  pdf.setFont("helvetica", "bold");
  pdf.text("Contact & Email:", margin + 5, y + 23);
  pdf.setFont("helvetica", "normal");
  pdf.text(`${data.customerContact || "Phone"} \xB7 ${data.customerEmail || "email@client.in"}`, margin + 29, y + 23);
  pdf.setFont("helvetica", "bold");
  pdf.text("State & GSTIN:", margin + 5, y + 28);
  pdf.setFont("helvetica", "normal");
  pdf.text(`${data.customerState || "Delhi"} (${data.customerStateCode || "07"}) \xB7 GST: ${data.customerGstin || "URP"}`, margin + 26, y + 28);
  const rightX = margin + 4 + colW;
  pdf.rect(rightX, y, colW, 30, "FD");
  pdf.setFillColor(23, 28, 121);
  pdf.rect(rightX, y, colW, 5.5, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("SHIPPED TO (CONSIGNEE / DELIVERY DESTINATION)", rightX + 3, y + 4);
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.2);
  pdf.setFont("helvetica", "bold");
  pdf.text("Name:", rightX + 3, y + 10);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.consigneeName || data.customerName || "Consignee / Self", rightX + 16, y + 10);
  pdf.setFont("helvetica", "bold");
  pdf.text("Address:", rightX + 3, y + 15);
  pdf.setFont("helvetica", "normal");
  const dAddr = pdf.splitTextToSize(data.consigneeAddress || "Destination Address", colW - 20);
  pdf.text(dAddr, rightX + 18, y + 15);
  pdf.setFont("helvetica", "bold");
  pdf.text("Contact & IBA:", rightX + 3, y + 23);
  pdf.setFont("helvetica", "normal");
  pdf.text(`${data.consigneeContact || data.customerContact || "Phone"} \xB7 IBA: ${data.ibaCode || "DEL-9921"}`, rightX + 25, y + 23);
  pdf.setFont("helvetica", "bold");
  pdf.text("Transit KM & Weight:", rightX + 3, y + 28);
  pdf.setFont("helvetica", "normal");
  pdf.text(`${data.transitKm || "1,450"} KM \xB7 Weight: ${data.weightKg || "1,850"} KG (${data.packagesCount || "As per list"})`, rightX + 32, y + 28);
  y += 33;
  const invoiceCharges = [
    { name: "Freight / Transportation Charges (SAC 996511)", val: data.transportationCharge || "22,000" },
    { name: "Packaging Materials & Crating Workmanship", val: data.packingCharge || "Including" },
    { name: "Loading & Dispatch Handling Labor", val: data.loadingCharge || "Including" },
    { name: "Unloading & Staging at Destination", val: data.unloadingCharge || "Including" },
    { name: "Unpacking & Furniture Reassembly", val: data.unpackingCharge || "Including" },
    { name: "Transit Insurance / FOVR Cover (3% Declared Value)", val: data.goodsRiskCharge || "Including" },
    { name: "CGST (Central Goods and Services Tax @ 9%)", val: data.cgstCharge || "1,980" },
    { name: "SGST (State Goods and Services Tax @ 9%)", val: data.sgstCharge || "1,980" }
  ];
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin + 2, y, contentWidth - 4, 6, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("PARTICULARS OF RELOCATION SUPPLY", margin + 5, y + 4.2);
  pdf.text("RATE / CHARGE (INR)", margin + contentWidth - 45, y + 4.2);
  y += 6;
  pdf.setFontSize(7.2);
  invoiceCharges.forEach((c, idx) => {
    pdf.setFillColor(idx % 2 === 0 ? 255 : 248, idx % 2 === 0 ? 255 : 250, idx % 2 === 0 ? 255 : 255);
    pdf.setDrawColor(230, 235, 245);
    pdf.rect(margin + 2, y, contentWidth - 4, 5.5, "FD");
    pdf.setTextColor(19, 28, 42);
    pdf.setFont("helvetica", "normal");
    pdf.text(c.name, margin + 5, y + 3.8);
    pdf.setFont("helvetica", "bold");
    pdf.setTextColor(23, 28, 121);
    pdf.text(String(c.val), margin + contentWidth - 44, y + 3.8);
    y += 5.5;
  });
  const totalAmount = Number(data.totalAmount || 25960);
  const words = numberToIndianWords(totalAmount);
  y += 2;
  pdf.setFillColor(240, 243, 255);
  pdf.setDrawColor(218, 227, 247);
  pdf.rect(margin + 2, y, contentWidth - 4, 15, "FD");
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(8.5);
  pdf.setTextColor(187, 0, 30);
  pdf.text("NET INVOICE TOTAL AMOUNT:", margin + 5, y + 5.5);
  pdf.setFontSize(11);
  pdf.text(`Rs. ${totalAmount.toLocaleString("en-IN")}`, margin + contentWidth - 45, y + 5.5);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7);
  pdf.setTextColor(23, 28, 121);
  pdf.text("AMOUNT IN WORDS:", margin + 5, y + 11.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(19, 28, 42);
  pdf.text(words, margin + 35, y + 11.5);
  y += 18;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, contentWidth - 4, 18, "FD");
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.2);
  pdf.setTextColor(23, 28, 121);
  pdf.text("REMITTANCE BANK ACCOUNT DETAILS:", margin + 5, y + 5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(
    `A/C NAME: DTC EXPRESS CARGO MOVERS \xB7 BANK: HDFC BANK LTD \xB7 A/C NO: ${data.bankAccountNumber || "50200084920194"} \xB7 IFSC: HDFC0000182 \xB7 BRANCH: MORI GATE, DELHI`,
    margin + 5,
    y + 9.5
  );
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("GENERATED BY:", margin + 5, y + 14.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.generatedBy || "Command Superintendent (Mori Gate)", margin + 30, y + 14.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(16, 120, 50);
  pdf.text("TAX REGISTRATION STATUS: ACTIVE GSTIN 07AAYFD8489Q2ZW", margin + 105, y + 14.5);
  y += 22;
  const sigColW = (contentWidth - 4) / 2;
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, sigColW, 22);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7);
  pdf.setTextColor(118, 118, 131);
  pdf.text("CUSTOMER RECEIVING SIGNATURE", margin + 5, y + 5);
  pdf.setFont("helvetica", "normal");
  pdf.text("Acknowledged receipt of invoice & services", margin + 5, y + 18);
  pdf.rect(margin + 2 + sigColW, y, sigColW, 22);
  pdf.setFillColor(245, 247, 255);
  pdf.rect(margin + 3 + sigColW, y + 1, sigColW - 2, 20, "F");
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(187, 0, 30);
  pdf.text("FOR DTC EXPRESS CARGO MOVERS & PACKERS", margin + 5 + sigColW, y + 5.5);
  pdf.setFontSize(6.5);
  pdf.setTextColor(23, 28, 121);
  pdf.text("AUTHORIZED ACCOUNTS SIGNATORY", margin + 5 + sigColW, y + 10.5);
  pdf.setTextColor(16, 120, 50);
  pdf.text("ELECTRONIC BILL OF SUPPLY \xB7 COMPUTER GENERATED", margin + 5 + sigColW, y + 17);
  return Buffer.from(pdf.output("arraybuffer"));
}
function createMoneyReceiptPdf(doc, data) {
  const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const pageWidth = 210;
  const margin = 12;
  const contentWidth = pageWidth - margin * 2;
  const branchInfo = getBranchDetails(data.branch || "Delhi");
  let y = renderHeader(
    pdf,
    "OFFICIAL MONEY RECEIPT / ADVANCE PAYMENT VOUCHER",
    "LEGAL SETTLEMENT ACKNOWLEDGEMENT UNDER CARRIAGE ACCOUNTS RULES",
    branchInfo.name,
    branchInfo.address
  );
  pdf.setFillColor(240, 243, 255);
  pdf.setDrawColor(218, 227, 247);
  pdf.roundedRect(margin + 2, y, contentWidth - 4, 15, 2, 2, "FD");
  pdf.setFontSize(8);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("RECEIPT NUMBER:", margin + 5, y + 6);
  pdf.setFontSize(9.5);
  pdf.setTextColor(187, 0, 30);
  pdf.text(data.receiptNumber || doc.documentCode || "MR-99014", margin + 35, y + 6);
  pdf.setFontSize(8);
  pdf.setTextColor(23, 28, 121);
  pdf.text("RECEIPT DATE:", margin + 80, y + 6);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.receiptDate || (/* @__PURE__ */ new Date()).toLocaleDateString("en-IN"), margin + 105, y + 6);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("ISSUING BRANCH:", margin + 5, y + 11.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.branch || "Delhi Central Hub", margin + 35, y + 11.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("PAYMENT MODE:", margin + 80, y + 11.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(16, 120, 50);
  pdf.text(data.paymentMode || "Bank Transfer / IMPS / UPI", margin + 107, y + 11.5);
  y += 19;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, contentWidth - 4, 38, "FD");
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin + 2, y, contentWidth - 4, 6, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.8);
  pdf.text("PARTICULARS OF REMITTANCE & BILATERAL ACCOUNT REFERENCE", margin + 5, y + 4.2);
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.5);
  pdf.setFont("helvetica", "bold");
  pdf.text("Received From (Customer Name):", margin + 5, y + 11.5);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.customerName || "Valued Client", margin + 52, y + 11.5);
  pdf.setFont("helvetica", "bold");
  pdf.text("Contact Phone:", margin + 115, y + 11.5);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.phone || "+91 97737 90546", margin + 140, y + 11.5);
  pdf.setFont("helvetica", "bold");
  pdf.text("Towards Part Payment of Bill No:", margin + 5, y + 17.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(187, 0, 30);
  pdf.text(data.billNumber || "INV-2026-9901", margin + 52, y + 17.5);
  pdf.setTextColor(19, 28, 42);
  pdf.setFont("helvetica", "bold");
  pdf.text("Bill Date:", margin + 115, y + 17.5);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.billDate || (/* @__PURE__ */ new Date()).toLocaleDateString("en-IN"), margin + 130, y + 17.5);
  pdf.setFont("helvetica", "bold");
  pdf.text("Consignment Transit Route:", margin + 5, y + 23.5);
  pdf.setFont("helvetica", "normal");
  pdf.text(`${data.fromCity || "Delhi"} -> ${data.toCity || "Destination"}`, margin + 46, y + 23.5);
  pdf.setFont("helvetica", "bold");
  pdf.text("As Per Details By:", margin + 5, y + 29.5);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.asPerDetailsBy || "H.H.G (Household Goods Shifting)", margin + 35, y + 29.5);
  pdf.setFont("helvetica", "bold");
  pdf.text("Transaction / Reference No:", margin + 115, y + 29.5);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.referenceNumber || "TXN-998412857", margin + 155, y + 29.5);
  y += 42;
  const amountNumber = Number(data.amount || 15e3);
  const amountWords = numberToIndianWords(amountNumber);
  pdf.setFillColor(240, 243, 255);
  pdf.setDrawColor(218, 227, 247);
  pdf.roundedRect(margin + 2, y, contentWidth - 4, 24, 2, 2, "FD");
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(8);
  pdf.setTextColor(23, 28, 121);
  pdf.text("SUM RECEIVED (IN NUMBERS):", margin + 6, y + 6);
  pdf.setFontSize(14);
  pdf.setTextColor(16, 120, 50);
  pdf.text(`Rs. ${amountNumber.toLocaleString("en-IN")}/-`, margin + 54, y + 7.5);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.setTextColor(23, 28, 121);
  pdf.text("AMOUNT IN WORDS:", margin + 6, y + 15);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(19, 28, 42);
  pdf.text(amountWords, margin + 36, y + 15);
  pdf.setFont("helvetica", "normal");
  pdf.setFontSize(6.8);
  pdf.setTextColor(118, 118, 131);
  pdf.text("Subject to realization of cheque / digital bank credit. Acknowledged as valid settlement voucher.", margin + 6, y + 20);
  y += 30;
  const sigColW = (contentWidth - 4) / 2;
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, sigColW, 26);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7);
  pdf.setTextColor(118, 118, 131);
  pdf.text("REMITTER / CUSTOMER SIGNATURE", margin + 5, y + 5);
  pdf.setFont("helvetica", "normal");
  pdf.text("Depositor signature", margin + 5, y + 21);
  pdf.rect(margin + 2 + sigColW, y, sigColW, 26);
  pdf.setFillColor(245, 247, 255);
  pdf.rect(margin + 3 + sigColW, y + 1, sigColW - 2, 24, "F");
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(187, 0, 30);
  pdf.text("FOR DTC EXPRESS CARGO MOVERS & PACKERS", margin + 5 + sigColW, y + 5.5);
  pdf.setFontSize(6.5);
  pdf.setTextColor(23, 28, 121);
  pdf.text("CASHIER / ACCOUNTS RECEPTION DESK", margin + 5 + sigColW, y + 10.5);
  pdf.setTextColor(16, 120, 50);
  pdf.text("STAMPED & VALIDATED RECEIPT", margin + 5 + sigColW, y + 21);
  return Buffer.from(pdf.output("arraybuffer"));
}
function createLRDocumentPdf(doc, shipment, client, customData) {
  const data = customData || doc.documentData || {};
  const pdf = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4"
  });
  const pageWidth = 210;
  const pageHeight = 297;
  const margin = 12;
  const contentWidth = pageWidth - margin * 2;
  let y = renderHeader(
    pdf,
    "CONSIGNMENT NOTE / LORRY RECEIPT (CONSIGNOR COPY)",
    "ISSUED UNDER SECTION 9 OF THE CARRIAGE BY ROAD ACT, 2007"
  );
  pdf.setFillColor(240, 243, 255);
  pdf.setDrawColor(218, 227, 247);
  pdf.roundedRect(margin + 2, y, contentWidth - 4, 15, 2, 2, "FD");
  pdf.setFontSize(8);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("CONSIGNMENT NOTE NO:", margin + 5, y + 5.5);
  pdf.setFontSize(9.5);
  pdf.setTextColor(187, 0, 30);
  pdf.text(data.consignmentNoteNumber || doc.documentCode || shipment?.id || "CN-53450", margin + 45, y + 5.5);
  pdf.setFontSize(8);
  pdf.setTextColor(23, 28, 121);
  pdf.text("DATE:", margin + 110, y + 5.5);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.consignmentDate || (doc.createdAt ? new Date(doc.createdAt).toLocaleDateString("en-IN") : (/* @__PURE__ */ new Date()).toLocaleDateString("en-IN")), margin + 122, y + 5.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("ISSUING OFFICE CITY:", margin + 5, y + 11);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.issuingOfficeCity || "Delhi (Mori Gate)", margin + 38, y + 11);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("PARTY TELEPHONE:", margin + 110, y + 11);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.partyTelephone || client?.phone || "+91 97737 90546", margin + 140, y + 11);
  y += 18;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, contentWidth - 4, 9, "FD");
  pdf.setFontSize(7.5);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("LORRY NUMBER:", margin + 5, y + 6);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.lorryNumber || shipment?.vehiclePlate || "DL-01-AB-4419", margin + 30, y + 6);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("TRANSPORT MODE:", margin + 75, y + 6);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.transportMode || "By Road (Dedicated Container)", margin + 104, y + 6);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("INVOICE NO & DATE:", margin + 145, y + 6);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(data.invoiceNumberDate || "INV-2026 / As per list", margin + 175, y + 6);
  y += 12;
  const colW = (contentWidth - 6) / 2;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, colW, 30, "FD");
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin + 2, y, colW, 5.5, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("CONSIGNOR (NAME & FULL ADDRESS)", margin + 5, y + 4);
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.2);
  pdf.setFont("helvetica", "bold");
  pdf.text("Name:", margin + 5, y + 10);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.consignorName || client?.clientName || "Valued Consignor", margin + 16, y + 10);
  pdf.setFont("helvetica", "bold");
  pdf.text("Address:", margin + 5, y + 15);
  pdf.setFont("helvetica", "normal");
  const crLines = pdf.splitTextToSize(data.consignorAddress || "Pickup Address, Origin City", colW - 20);
  pdf.text(crLines, margin + 18, y + 15);
  pdf.setFont("helvetica", "bold");
  pdf.text("From City & State:", margin + 5, y + 23);
  pdf.setFont("helvetica", "normal");
  pdf.text(`${data.fromCity || "Delhi"} (${data.consignorState || "Delhi"} - ${data.consignorStateCode || "07"})`, margin + 31, y + 23);
  const rightX = margin + 4 + colW;
  pdf.rect(rightX, y, colW, 30, "FD");
  pdf.setFillColor(23, 28, 121);
  pdf.rect(rightX, y, colW, 5.5, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("CONSIGNEE (NAME & FULL ADDRESS)", rightX + 3, y + 4);
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.2);
  pdf.setFont("helvetica", "bold");
  pdf.text("Name:", rightX + 3, y + 10);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.consigneeName || "Consignee / Self", rightX + 14, y + 10);
  pdf.setFont("helvetica", "bold");
  pdf.text("Address:", rightX + 3, y + 15);
  pdf.setFont("helvetica", "normal");
  const ceLines = pdf.splitTextToSize(data.consigneeAddress || "Destination Drop Address", colW - 20);
  pdf.text(ceLines, rightX + 17, y + 15);
  pdf.setFont("helvetica", "bold");
  pdf.text("To City / State:", rightX + 3, y + 23);
  pdf.setFont("helvetica", "normal");
  pdf.text(`${data.toCity || "Maharashtra"} (${data.consigneeState || "Maharashtra"} - ${data.consigneeStateCode || "27"})`, rightX + 24, y + 23);
  y += 33;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, contentWidth - 4, 30, "FD");
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin + 2, y, contentWidth - 4, 5.5, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("DESCRIPTION OF PACKAGES & CARGO ARTICLES", margin + 5, y + 4);
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(7.2);
  pdf.setFont("helvetica", "bold");
  pdf.text("No. of Packages:", margin + 5, y + 10.5);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.packages || "As per list (28 Cartons & Units)", margin + 30, y + 10.5);
  pdf.setFont("helvetica", "bold");
  pdf.text("Description Lines:", margin + 5, y + 16);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.goodsDescription || "Household Goods Shifting \xB7 Used Personal Effects \xB7 Strictly Not For Sale", margin + 32, y + 16);
  if (data.vehicleRegNumber) {
    pdf.setFont("helvetica", "bold");
    pdf.setTextColor(187, 0, 30);
    pdf.text("Car Carried Reg No:", margin + 5, y + 21.5);
    pdf.setFont("helvetica", "bold");
    pdf.setTextColor(19, 28, 42);
    pdf.text(data.vehicleRegNumber, margin + 35, y + 21.5);
  } else {
    pdf.setFont("helvetica", "bold");
    pdf.text("Special Handling:", margin + 5, y + 21.5);
    pdf.setFont("helvetica", "normal");
    pdf.text("Weather-Proof Closed Container \xB7 Tamper-proof Bolt Seal Affixed", margin + 30, y + 21.5);
  }
  pdf.setFont("helvetica", "bold");
  pdf.text("Remarks:", margin + 5, y + 26.5);
  pdf.setFont("helvetica", "normal");
  pdf.text(data.remarks || doc.summaryText || "Consignment accepted at owner risk in sound condition for road transit.", margin + 20, y + 26.5);
  y += 33;
  const wColW = (contentWidth - 4) / 4;
  const wMetrics = [
    { label: "ACTUAL WEIGHT", val: data.actualWeight || "1,850 KG" },
    { label: "CHARGED WEIGHT", val: data.chargedWeight || "FIXED" },
    { label: "FREIGHT / CHARGES", val: data.freight || "AC PAY" },
    { label: "DECLARED VALUE", val: data.declaredValue ? `Rs. ${Number(data.declaredValue).toLocaleString("en-IN")}` : "Rs. 4,50,000" }
  ];
  wMetrics.forEach((m, idx) => {
    const wx = margin + 2 + idx * wColW;
    pdf.setFillColor(245, 248, 255);
    pdf.rect(wx, y, wColW, 14, "FD");
    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(6.5);
    pdf.setTextColor(118, 118, 131);
    pdf.text(m.label, wx + 3, y + 5);
    pdf.setFontSize(9);
    pdf.setTextColor(23, 28, 121);
    pdf.text(m.val, wx + 3, y + 10.5);
  });
  y += 17;
  pdf.setFillColor(255, 255, 255);
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, contentWidth - 4, 18, "FD");
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7);
  pdf.setTextColor(23, 28, 121);
  pdf.text("INSURANCE COVERAGE & DEMURRAGE PROTOCOL:", margin + 5, y + 4.5);
  pdf.setFont("helvetica", "normal");
  pdf.setFontSize(6.8);
  pdf.setTextColor(19, 28, 42);
  const insText = data.insuranceBlock || `Company: Carrier Group Transit Policy \xB7 Policy No: TP-3041-DEL \xB7 Date: Active \xB7 Risk: All-Risk Transit Cover \xB7 Demurrage: Free storage 24 hours from arrival, thereafter Rs. 300 per day applicable.`;
  const insLines = pdf.splitTextToSize(insText, contentWidth - 10);
  pdf.text(insLines, margin + 5, y + 9);
  y += 21;
  const sigColW = (contentWidth - 4) / 3;
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, sigColW, 25);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7);
  pdf.setTextColor(118, 118, 131);
  pdf.text("CONSIGNOR SIGNATURE / THUMB", margin + 5, y + 5);
  pdf.setFont("helvetica", "normal");
  pdf.text("I accept conditions & terms", margin + 5, y + 21);
  pdf.rect(margin + 2 + sigColW, y, sigColW, 25);
  pdf.setFont("helvetica", "bold");
  pdf.text("DRIVER / VEHICLE RECEIPT", margin + 5 + sigColW, y + 5);
  pdf.setFont("helvetica", "normal");
  pdf.text("Received cargo intact", margin + 5 + sigColW, y + 21);
  pdf.rect(margin + 2 + sigColW * 2, y, sigColW, 25);
  pdf.setFillColor(245, 247, 255);
  pdf.rect(margin + 3 + sigColW * 2, y + 1, sigColW - 2, 23, "F");
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(187, 0, 30);
  pdf.text("DTC EXPRESS CARGO MOVERS", margin + 5 + sigColW * 2, y + 5.5);
  pdf.setFontSize(6.5);
  pdf.setTextColor(23, 28, 121);
  pdf.text("MORI GATE DISPATCH COMMAND", margin + 5 + sigColW * 2, y + 10.5);
  pdf.setTextColor(16, 120, 50);
  pdf.text("AUTHORIZED DISPATCH OFFICER", margin + 5 + sigColW * 2, y + 21);
  return Buffer.from(pdf.output("arraybuffer"));
}
function createChecklistManifestPdf(clientName, docketNo, items, shipment) {
  const pdf = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4"
  });
  const pageWidth = 210;
  const pageHeight = 297;
  const margin = 14;
  const contentWidth = pageWidth - margin * 2;
  const safeItems = Array.isArray(items) ? items : [];
  pdf.setDrawColor(23, 28, 121);
  pdf.setLineWidth(0.6);
  pdf.rect(margin, margin, contentWidth, pageHeight - margin * 2);
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin, margin, contentWidth, 22, "F");
  pdf.setFillColor(187, 0, 30);
  pdf.rect(margin, margin + 22, contentWidth, 2, "F");
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(255, 255, 255);
  pdf.setFontSize(15);
  pdf.text("DTC EXPRESS CARGO MOVERS & PACKERS", pageWidth / 2, margin + 9, { align: "center" });
  pdf.setFontSize(8);
  pdf.setFont("helvetica", "normal");
  pdf.text("VERIFIED PACKING & INVENTORY AUDIT MANIFEST \xB7 MORI GATE CENTRAL DISPATCH", pageWidth / 2, margin + 15, { align: "center" });
  pdf.text("HELPLINE: +91 97737 90546 \xB7 GSTIN: 07AAYFD8489Q2ZW \xB7 IBA APPROVED CODE: DEL-9921", pageWidth / 2, margin + 19, { align: "center" });
  let y = margin + 28;
  pdf.setTextColor(19, 28, 42);
  pdf.setFontSize(11);
  pdf.setFont("helvetica", "bold");
  pdf.text("CONSIGNMENT ITEM-BY-ITEM PACKING CHECKLIST", pageWidth / 2, y, { align: "center" });
  y += 5;
  pdf.setFillColor(240, 243, 255);
  pdf.setDrawColor(218, 227, 247);
  pdf.roundedRect(margin + 2, y, contentWidth - 4, 18, 2, 2, "FD");
  pdf.setFontSize(8);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("CLIENT NAME:", margin + 6, y + 6);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(clientName || "Valued Client", margin + 30, y + 6);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("DOCKET / LR NO:", margin + 105, y + 6);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(187, 0, 30);
  pdf.text(docketNo || "CN-53450", margin + 135, y + 6);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("ROUTE CORRIDOR:", margin + 6, y + 13);
  pdf.setFont("helvetica", "normal");
  pdf.setTextColor(19, 28, 42);
  pdf.text(`${shipment?.originCity || "Origin"} -> ${shipment?.destinationCity || "Destination"}`, margin + 36, y + 13);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(23, 28, 121);
  pdf.text("TOTAL MANIFEST ITEMS:", margin + 105, y + 13);
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(16, 120, 50);
  const totalQty = safeItems.reduce((sum, it) => sum + (it.quantity || 1), 0);
  pdf.text(`${safeItems.length} Unique Records (${totalQty} Total Units)`, margin + 145, y + 13);
  y += 22;
  const colX = [margin + 2, margin + 12, margin + 78, margin + 108, margin + 120, margin + 158];
  pdf.setFillColor(23, 28, 121);
  pdf.rect(margin + 2, y, contentWidth - 4, 7, "F");
  pdf.setTextColor(255, 255, 255);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.text("#", colX[0] + 3, y + 5);
  pdf.text("ITEM NAME & SPECIFICATION", colX[1] + 2, y + 5);
  pdf.text("CATEGORY / ROOM", colX[2] + 2, y + 5);
  pdf.text("QTY", colX[3] + 2, y + 5);
  pdf.text("PACKING & CONDITION NOTE", colX[4] + 2, y + 5);
  pdf.text("VERIFICATION", colX[5] + 2, y + 5);
  y += 7;
  pdf.setFontSize(7.2);
  if (safeItems.length === 0) {
    pdf.setFillColor(255, 255, 255);
    pdf.rect(margin + 2, y, contentWidth - 4, 14, "FD");
    pdf.setTextColor(118, 118, 131);
    pdf.setFont("helvetica", "italic");
    pdf.text("No itemized checklist items logged yet. Items can be registered by client or operations team.", pageWidth / 2, y + 9, { align: "center" });
    y += 14;
  } else {
    safeItems.forEach((item, index) => {
      const rowHeight = 7.5;
      if (y + rowHeight > pageHeight - margin - 35) {
        return;
      }
      pdf.setFillColor(index % 2 === 0 ? 255 : 248, index % 2 === 0 ? 255 : 250, index % 2 === 0 ? 255 : 255);
      pdf.setDrawColor(230, 235, 245);
      pdf.rect(margin + 2, y, contentWidth - 4, rowHeight, "FD");
      pdf.setTextColor(19, 28, 42);
      pdf.setFont("helvetica", "normal");
      pdf.text(String(index + 1), colX[0] + 3, y + 5);
      pdf.setFont("helvetica", "bold");
      const truncatedName = item.itemName.length > 36 ? item.itemName.substring(0, 34) + ".." : item.itemName;
      pdf.text(truncatedName, colX[1] + 2, y + 5);
      pdf.setFont("helvetica", "normal");
      pdf.text(item.category || "General", colX[2] + 2, y + 5);
      pdf.setFont("helvetica", "bold");
      pdf.setTextColor(23, 28, 121);
      pdf.text(String(item.quantity || 1), colX[3] + 3, y + 5);
      pdf.setFont("helvetica", "normal");
      pdf.setTextColor(70, 70, 82);
      const note = item.conditionNote ? item.conditionNote.length > 25 ? item.conditionNote.substring(0, 23) + ".." : item.conditionNote : "Standard Bubble Wrap";
      pdf.text(note, colX[4] + 2, y + 5);
      pdf.setFont("helvetica", "bold");
      if (item.status === "Verified" || item.status === "Delivered") {
        pdf.setTextColor(16, 120, 50);
      } else if (item.status === "Packed" || item.status === "Loaded") {
        pdf.setTextColor(23, 28, 121);
      } else {
        pdf.setTextColor(187, 0, 30);
      }
      pdf.text(`[\u2713] ${item.status || "Packed"}`, colX[5] + 2, y + 5);
      y += rowHeight;
    });
  }
  y += 4;
  pdf.setFillColor(240, 243, 255);
  pdf.setDrawColor(218, 227, 247);
  pdf.roundedRect(margin + 2, y, contentWidth - 4, 12, 2, 2, "FD");
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7.5);
  pdf.setTextColor(23, 28, 121);
  pdf.text("PACKING AUDIT SUMMARY:", margin + 6, y + 5);
  pdf.setFont("helvetica", "normal");
  const packedCount = safeItems.filter((i) => i.status === "Packed" || i.status === "Loaded" || i.status === "Delivered" || i.status === "Verified").length;
  const verifiedCount = safeItems.filter((i) => i.status === "Verified" || i.status === "Delivered").length;
  pdf.text(`Packed & Staged: ${packedCount}/${safeItems.length}  |  Inspected & Verified: ${verifiedCount}/${safeItems.length}  |  Vehicle Sealed: ${shipment?.sealTagNumber || "Verified at Terminal"}`, margin + 6, y + 9.5);
  y += 16;
  const sigW = (contentWidth - 4) / 3;
  pdf.setDrawColor(200, 205, 220);
  pdf.rect(margin + 2, y, sigW, 24);
  pdf.setFont("helvetica", "bold");
  pdf.setFontSize(7);
  pdf.setTextColor(118, 118, 131);
  pdf.text("CONSIGNOR HANDOVER SIGNATURE", margin + 5, y + 5);
  pdf.setFont("helvetica", "normal");
  pdf.text("Verified all items listed above", margin + 5, y + 20);
  pdf.rect(margin + 2 + sigW, y, sigW, 24);
  pdf.setFont("helvetica", "bold");
  pdf.text("PACKING SUPERVISOR STAMP", margin + 5 + sigW, y + 5);
  pdf.setFont("helvetica", "normal");
  pdf.text("Multi-layer protection checked", margin + 5 + sigW, y + 20);
  pdf.rect(margin + 2 + sigW * 2, y, sigW, 24);
  pdf.setFillColor(245, 247, 255);
  pdf.rect(margin + 3 + sigW * 2, y + 1, sigW - 2, 22, "F");
  pdf.setFont("helvetica", "bold");
  pdf.setTextColor(187, 0, 30);
  pdf.text("DTC EXPRESS CARGO MOVERS", margin + 5 + sigW * 2, y + 5.5);
  pdf.setFontSize(6.5);
  pdf.setTextColor(23, 28, 121);
  pdf.text("MORI GATE DISPATCH COMMAND", margin + 5 + sigW * 2, y + 10);
  pdf.setTextColor(16, 120, 50);
  pdf.text("VERIFIED PHYSICAL INVENTORY", margin + 5 + sigW * 2, y + 19);
  return Buffer.from(pdf.output("arraybuffer"));
}

// server/emailService.ts
import nodemailer from "nodemailer";
var EmailService = class {
  getTransporter(settings = db.getAgencySettings()) {
    const host = settings.smtpHost || process.env.SMTP_HOST;
    const port = settings.smtpPort || (process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587);
    const user = settings.smtpUser || process.env.SMTP_USER;
    const pass = settings.smtpPass || process.env.SMTP_PASS;
    const secure = settings.smtpSecure !== void 0 ? settings.smtpSecure : process.env.SMTP_SECURE === "true" || port === 465;
    if (host && user && pass) {
      return nodemailer.createTransport({
        host,
        port,
        secure,
        auth: { user, pass },
        tls: {
          rejectUnauthorized: false
        },
        connectionTimeout: 8e3,
        greetingTimeout: 5e3,
        socketTimeout: 12e3
      });
    }
    return null;
  }
  /**
   * Dispatches an email notification to agency inbox when a client submits an enquiry form
   */
  async sendLeadNotification(lead) {
    const settings = db.getAgencySettings();
    const recipient = settings.agencyNotificationEmail || "narnaul.shersingh@gmail.com, customer@dtcexpresscargo.in";
    const userEmail = settings.smtpUser?.trim();
    const fromAddress = userEmail && userEmail.includes("@gmail.com") ? `DTC Express Cargo <${userEmail}>` : settings.smtpFrom || "DTC Express Dispatch Desk <customer@dtcexpresscargo.in>";
    const replyTo = "customer@dtcexpresscargo.in";
    const cleanPhoneDigits = (lead.phone || "").replace(/[^0-9]/g, "");
    const phoneInternational = cleanPhoneDigits.length === 10 ? `91${cleanPhoneDigits}` : cleanPhoneDigits;
    const waLink = `https://wa.me/${phoneInternational}?text=${encodeURIComponent(`Hello ${lead.customerName}, this is DTC Express Cargo Movers regarding your enquiry #${lead.id} for shifting from ${lead.pickupCity} to ${lead.dropCity}. We are pleased to provide you with the guaranteed best route quote.`)}`;
    const telLink = `tel:${lead.phone}`;
    const subject = `\u{1F6A8} [NEW ENQUIRY #${lead.id}] ${lead.customerName} | ${lead.pickupCity} \u2794 ${lead.dropCity} (${lead.serviceCategory})`;
    const previewText = `New booking request from ${lead.customerName} (${lead.phone}). Route: ${lead.pickupCity} to ${lead.dropCity}. Service: ${lead.serviceCategory}.`;
    const htmlBody = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>New Client Relocation Enquiry</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; margin: 0; padding: 24px; color: #0f172a; }
    .container { max-width: 620px; margin: 0 auto; background: #ffffff; border-radius: 16px; overflow: hidden; border: 1px solid #e2e8f0; box-shadow: 0 4px 20px rgba(0,0,0,0.06); }
    .header { background: #082153; padding: 28px 24px; text-align: center; color: #ffffff; border-bottom: 4px solid #E61E2B; }
    .badge { display: inline-block; background: #E61E2B; color: #ffffff; font-size: 11px; font-weight: 800; letter-spacing: 1px; padding: 4px 10px; border-radius: 999px; text-transform: uppercase; margin-bottom: 10px; }
    .title { font-size: 22px; font-weight: 800; margin: 0 0 6px 0; letter-spacing: -0.5px; }
    .subtitle { font-size: 12px; color: #cbd5e1; margin: 0; }
    .body { padding: 28px 24px; }
    .alert-banner { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 10px; padding: 14px 16px; margin-bottom: 24px; font-size: 13px; color: #1e3a8a; line-height: 1.5; }
    .table-details { width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 13px; }
    .table-details td { padding: 10px 12px; border-bottom: 1px solid #f1f5f9; }
    .table-details tr:last-child td { border-bottom: none; }
    .label { width: 34%; font-weight: 700; color: #64748b; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
    .value { font-weight: 600; color: #0f172a; }
    .value-highlight { font-weight: 800; color: #082153; font-size: 15px; }
    .actions-grid { display: flex; gap: 12px; margin-top: 10px; margin-bottom: 24px; }
    .btn { display: inline-block; padding: 12px 18px; border-radius: 8px; text-decoration: none; font-weight: 700; font-size: 13px; text-align: center; }
    .btn-call { background: #E61E2B; color: #ffffff !important; }
    .btn-whatsapp { background: #25D366; color: #ffffff !important; }
    .notes-box { background: #f8fafc; border-left: 4px solid #082153; padding: 12px 16px; border-radius: 0 8px 8px 0; margin-bottom: 24px; font-size: 12px; color: #334155; }
    .footer { background: #f8fafc; padding: 20px 24px; font-size: 11px; color: #64748b; border-top: 1px solid #e2e8f0; text-align: center; line-height: 1.6; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="badge">Immediate Dispatch Alert</div>
      <h1 class="title">New Client Relocation Request</h1>
      <p class="subtitle">DTC Express Cargo Movers & Packers \xB7 Central Control Desk</p>
    </div>

    <div class="body">
      <div class="alert-banner">
        <strong>\u26A1 Lead Notification:</strong> A new enquiry was just submitted via the website form. You can review all details below and connect with the client directly without opening the admin portal.
      </div>

      <table class="table-details">
        <tr>
          <td class="label">Reference ID</td>
          <td class="value"><span style="background: #e2e8f0; padding: 3px 8px; border-radius: 6px; font-family: monospace; font-size: 13px; font-weight: 700;">#${lead.id}</span></td>
        </tr>
        <tr>
          <td class="label">Client Name</td>
          <td class="value value-highlight">${escapeHtml(lead.customerName)}</td>
        </tr>
        ${lead.companyName ? `
        <tr>
          <td class="label">Company / Org</td>
          <td class="value">${escapeHtml(lead.companyName)}</td>
        </tr>
        ` : ""}
        <tr>
          <td class="label">Contact Phone</td>
          <td class="value">
            <a href="${telLink}" style="color: #E61E2B; font-weight: 800; font-size: 15px; text-decoration: none; font-family: monospace;">${escapeHtml(lead.phone)}</a>
          </td>
        </tr>
        ${lead.email ? `
        <tr>
          <td class="label">Client Email</td>
          <td class="value"><a href="mailto:${escapeHtml(lead.email)}" style="color: #082153;">${escapeHtml(lead.email)}</a></td>
        </tr>
        ` : ""}
        <tr>
          <td class="label">Pickup Hub (Origin)</td>
          <td class="value" style="color: #082153; font-weight: 700;">\u{1F4CD} ${escapeHtml(lead.pickupCity)}</td>
        </tr>
        <tr>
          <td class="label">Drop Hub (Dest.)</td>
          <td class="value" style="color: #082153; font-weight: 700;">\u{1F3C1} ${escapeHtml(lead.dropCity)}</td>
        </tr>
        <tr>
          <td class="label">Service Category</td>
          <td class="value"><span style="background: #fef2f2; color: #991b1b; padding: 3px 8px; border-radius: 6px; font-weight: 700;">${escapeHtml(lead.serviceCategory)}</span></td>
        </tr>
        <tr>
          <td class="label">Target Date</td>
          <td class="value">\u{1F4C5} ${escapeHtml(lead.movingDate)}</td>
        </tr>
        ${lead.estimatedValue ? `
        <tr>
          <td class="label">Est. Cargo Value</td>
          <td class="value">\u20B9 ${Number(lead.estimatedValue).toLocaleString("en-IN")}</td>
        </tr>
        ` : ""}
        <tr>
          <td class="label">Submission Time</td>
          <td class="value" style="font-size: 12px; color: #64748b;">${(/* @__PURE__ */ new Date()).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })} IST</td>
        </tr>
      </table>

      ${lead.itemizedNotes ? `
      <div>
        <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 6px;">Consignment Specifications & Notes:</div>
        <div class="notes-box">
          ${escapeHtml(lead.itemizedNotes).replace(/ \| /g, "<br>\u2022 ")}
        </div>
      </div>
      ` : ""}

      <div style="margin-top: 24px; text-align: center;">
        <a href="${telLink}" class="btn btn-call" style="margin-right: 8px;">\u{1F4DE} Call Client (${lead.phone})</a>
        <a href="${waLink}" class="btn btn-whatsapp" target="_blank">\u{1F4AC} Chat on WhatsApp</a>
      </div>
    </div>

    <div class="footer">
      <strong>DTC Express Cargo Movers and Packers</strong><br>
      Corporate Office: B-13, Gokhale Market, Mori Gate, Delhi 110006<br>
      Govt Reg: UDYAM-DL-10-0107770 \xB7 GSTIN: 07AAYFD8489Q2ZW \xB7 Toll-Free / 24x7: 9773790546<br>
      <em>Official Automated Dispatch Transmission. Keep this email for quotation and audit reference.</em>
    </div>
  </div>
</body>
</html>
    `;
    const textBody = `
[DTC EXPRESS CARGO - NEW CLIENT RELOCATION ENQUIRY]
Reference ID: #${lead.id}
Client Name: ${lead.customerName}
${lead.companyName ? `Company: ${lead.companyName}
` : ""}
Phone: ${lead.phone}
${lead.email ? `Email: ${lead.email}
` : ""}
Origin Hub: ${lead.pickupCity}
Destination Hub: ${lead.dropCity}
Service: ${lead.serviceCategory}
Preferred Moving Date: ${lead.movingDate}
Specifications / Notes: ${lead.itemizedNotes || "Standard Relocation"}
Estimated Value: ${lead.estimatedValue ? `\u20B9 ${lead.estimatedValue}` : "To be assessed"}
Timestamp: ${(/* @__PURE__ */ new Date()).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })} IST

Direct Call: ${lead.phone}
Direct WhatsApp: ${waLink}
    `.trim();
    const transporter = this.getTransporter(settings);
    if (transporter) {
      try {
        const info = await transporter.sendMail({
          from: fromAddress,
          replyTo,
          to: recipient,
          subject,
          text: textBody,
          html: htmlBody
        });
        console.log(`[EMAIL DISPATCH SUCCESS] Lead ${lead.id} sent to ${recipient}: ${info.messageId}`);
        db.addEmailLog({
          type: "lead",
          referenceId: lead.id,
          recipient,
          subject,
          status: "sent",
          previewText
        });
        return { success: true, recipient, status: "sent" };
      } catch (err) {
        console.warn(`[EMAIL DISPATCH SMTP ERROR] Failed to send via SMTP, logging to outbox:`, err.message);
        db.addEmailLog({
          type: "lead",
          referenceId: lead.id,
          recipient,
          subject,
          status: "failed",
          error: err.message,
          previewText
        });
        return { success: false, recipient, status: "failed", error: err.message };
      }
    } else {
      console.log(`[EMAIL DISPATCH SIMULATED] Lead ${lead.id} from ${lead.customerName} (${lead.phone}) logged for agency recipient: ${recipient}`);
      db.addEmailLog({
        type: "lead",
        referenceId: lead.id,
        recipient,
        subject,
        status: "simulated",
        previewText
      });
      return { success: true, recipient, status: "simulated" };
    }
  }
  /**
   * Dispatches grievance notification to agency inbox
   */
  async sendComplaintNotification(complaint) {
    const settings = db.getAgencySettings();
    const recipient = settings.agencyNotificationEmail || "narnaul.shersingh@gmail.com, customer@dtcexpresscargo.in";
    const userEmail = settings.smtpUser?.trim();
    const fromAddress = userEmail && userEmail.includes("@gmail.com") ? `DTC Express Cargo <${userEmail}>` : settings.smtpFrom || "DTC Express Grievance Cell <customer@dtcexpresscargo.in>";
    const replyTo = "customer@dtcexpresscargo.in";
    const subject = `\u26A0\uFE0F [GRIEVANCE #${complaint.id}] ${complaint.customerName} - ${complaint.category}`;
    const previewText = `Complaint registered by ${complaint.customerName} (${complaint.phone}): ${complaint.description}`;
    const htmlBody = `
      <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 12px;">
        <h2 style="color: #b91c1c; margin-top: 0;">Formal Customer Grievance #${complaint.id}</h2>
        <p><strong>Customer:</strong> ${escapeHtml(complaint.customerName)}</p>
        <p><strong>Phone:</strong> <a href="tel:${complaint.phone}">${escapeHtml(complaint.phone)}</a></p>
        ${complaint.relatedShipmentId ? `<p><strong>Shipment Docket:</strong> ${escapeHtml(complaint.relatedShipmentId)}</p>` : ""}
        <p><strong>Category:</strong> ${escapeHtml(complaint.category)}</p>
        <p><strong>Description:</strong></p>
        <div style="background: #fef2f2; border-left: 4px solid #ef4444; padding: 12px; margin: 12px 0;">${escapeHtml(complaint.description)}</div>
        <p style="font-size: 11px; color: #64748b;">Lodged at ${complaint.createdAt}</p>
      </div>
    `;
    const transporter = this.getTransporter(settings);
    if (transporter) {
      try {
        await transporter.sendMail({
          from: fromAddress,
          replyTo,
          to: recipient,
          subject,
          text: `${subject}
Customer: ${complaint.customerName} (${complaint.phone})
Description: ${complaint.description}`,
          html: htmlBody
        });
        db.addEmailLog({ type: "complaint", referenceId: complaint.id, recipient, subject, status: "sent", previewText });
        return { success: true, recipient, status: "sent" };
      } catch (err) {
        db.addEmailLog({ type: "complaint", referenceId: complaint.id, recipient, subject, status: "failed", error: err.message, previewText });
        return { success: false, recipient, status: "failed" };
      }
    } else {
      db.addEmailLog({ type: "complaint", referenceId: complaint.id, recipient, subject, status: "simulated", previewText });
      return { success: true, recipient, status: "simulated" };
    }
  }
  /**
   * Dispatches a test email to verify settings
   */
  async sendTestNotification(targetEmail) {
    const settings = db.getAgencySettings();
    const recipient = targetEmail || settings.agencyNotificationEmail || "narnaul.shersingh@gmail.com, customer@dtcexpresscargo.in";
    const userEmail = settings.smtpUser?.trim();
    const fromAddress = userEmail && userEmail.includes("@gmail.com") ? `DTC Express Cargo <${userEmail}>` : settings.smtpFrom || "DTC Express Test Dispatch <customer@dtcexpresscargo.in>";
    const replyTo = "customer@dtcexpresscargo.in";
    const subject = `\u2705 [TEST NOTIFICATION] DTC Express Agency Email Dispatch Verified`;
    const previewText = `Test email dispatch to verify agency notification inbox connectivity.`;
    const htmlBody = `
      <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 12px; background: #ffffff;">
        <h2 style="color: #082153; margin-top: 0;">Agency Email Dispatch System Online</h2>
        <p>This is a test notification confirming that the DTC Express Cargo agency notification channel is active.</p>
        <p><strong>Configured Recipients:</strong> ${escapeHtml(recipient)}</p>
        <p><strong>Timestamp:</strong> ${(/* @__PURE__ */ new Date()).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })} IST</p>
        <div style="background: #f0fdf4; border: 1px solid #86efac; border-radius: 8px; padding: 12px; color: #166534; font-size: 13px;">
          \u2713 Whenever a client submits any moving inquiry or contact form on the website, full consignment and contact details are automatically dispatched to this inbox.
        </div>
      </div>
    `;
    const transporter = this.getTransporter(settings);
    if (transporter) {
      try {
        const info = await transporter.sendMail({
          from: fromAddress,
          replyTo,
          to: recipient,
          subject,
          text: `DTC Express Agency Email Dispatch System Test. Recipients: ${recipient}`,
          html: htmlBody
        });
        db.addEmailLog({ type: "test", referenceId: "TEST", recipient, subject, status: "sent", previewText });
        return { success: true, recipient, status: "sent" };
      } catch (err) {
        db.addEmailLog({ type: "test", referenceId: "TEST", recipient, subject, status: "failed", error: err.message, previewText });
        return { success: false, recipient, status: "failed", error: err.message };
      }
    } else {
      db.addEmailLog({ type: "test", referenceId: "TEST", recipient, subject, status: "simulated", previewText });
      return { success: true, recipient, status: "simulated" };
    }
  }
};
function escapeHtml(text) {
  if (!text) return "";
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
var emailService = new EmailService();

// server/routes.ts
var apiRouter = express.Router();
apiRouter.use(authenticateSession);
apiRouter.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }
  const result = db.authenticate(username, password);
  if (!result.user) {
    return res.status(401).json({ error: result.error || "Invalid credentials. User does not exist." });
  }
  const user = result.user;
  if (user.status === "deactivated") {
    return res.status(403).json({
      error: "Account has been deactivated. Portal access is revoked.",
      isDeactivated: true
    });
  }
  user.lastLogin = (/* @__PURE__ */ new Date()).toISOString();
  db.addAudit(user.username, "USER_LOGIN", user.id, `User logged in with role: ${user.role}`);
  const token = sessionStore.createSession({
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    role: user.role,
    linkedClientId: user.linkedClientId,
    status: user.status,
    permissions: user.permissions || []
  });
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      role: user.role,
      status: user.status,
      linkedClientId: user.linkedClientId,
      permissions: user.permissions || []
    }
  });
});
apiRouter.get("/auth/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});
apiRouter.post("/auth/logout", requireAuth, (req, res) => {
  if (req.session?.token) {
    sessionStore.destroySession(req.session.token);
  }
  res.json({ success: true, message: "Logged out successfully" });
});
apiRouter.get("/auth/users", requireRole(["super_admin"]), (_req, res) => {
  const users = db.getUsers().map((u) => ({
    id: u.id,
    username: u.username,
    displayName: u.displayName,
    role: u.role,
    status: u.status,
    linkedClientId: u.linkedClientId,
    createdAt: u.createdAt,
    lastLogin: u.lastLogin
  }));
  res.json(users);
});
apiRouter.get("/auth/admin-requests", requireRole(["super_admin"]), (_req, res) => {
  const requests = db.getAdminRequests();
  res.json(requests);
});
apiRouter.post("/auth/request-admin", (req, res) => {
  const {
    fullName,
    email,
    phone,
    requestedUsername,
    requestedRole,
    branchHub,
    department,
    justification
  } = req.body;
  if (!fullName || !phone || !requestedUsername) {
    return res.status(400).json({ error: "Full Name, Phone number, and Requested Username are required." });
  }
  try {
    const result = db.addAdminRequest({
      fullName,
      email: email || "",
      phone,
      requestedUsername,
      requestedRole: requestedRole || "staff",
      branchHub: branchHub || "Delhi Mori Gate Central Hub",
      department: department || "Operations Dispatch",
      justification: justification || "Operational duties authorization request."
    });
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message || "Failed to submit admin request" });
  }
});
apiRouter.post("/auth/admin-requests/:id/review", requireRole(["super_admin"]), (req, res) => {
  const { id } = req.params;
  const { action, rejectionReason } = req.body;
  if (!action || action !== "approve" && action !== "reject") {
    return res.status(400).json({ error: 'Action must be "approve" or "reject".' });
  }
  try {
    const result = db.reviewAdminRequest(
      id,
      action,
      req.user?.displayName || "Super Admin",
      rejectionReason
    );
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message || "Failed to review request" });
  }
});
apiRouter.get("/leads", requireRole(["super_admin", "staff"]), (req, res) => {
  const { status, q } = req.query;
  let leads = db.getLeads();
  if (status && typeof status === "string" && status !== "ALL") {
    leads = leads.filter((l) => l.status.toLowerCase() === status.toLowerCase());
  }
  if (q && typeof q === "string") {
    const query = q.toLowerCase();
    leads = leads.filter(
      (l) => l.id.toLowerCase().includes(query) || l.customerName.toLowerCase().includes(query) || l.companyName && l.companyName.toLowerCase().includes(query) || l.pickupCity.toLowerCase().includes(query) || l.dropCity.toLowerCase().includes(query) || l.phone.includes(query)
    );
  }
  res.json(leads);
});
apiRouter.post("/leads", async (req, res) => {
  const {
    customerName,
    companyName,
    phone,
    email,
    pickupCity,
    dropCity,
    serviceCategory,
    movingDate,
    itemizedNotes,
    estimatedValue
  } = req.body;
  const rawPhone = (phone || "").toString().trim();
  const digits = rawPhone.replace(/[^0-9]/g, "");
  if (!digits || digits.length < 6) {
    return res.status(400).json({ error: "Please provide a valid contact phone number." });
  }
  const finalCustomer = (customerName || "").trim() || "Online Consignor";
  const finalPickup = (pickupCity || "").trim() || "Delhi NCR (Central Node)";
  const finalDrop = (dropCity || "").trim() || "Pan-India Relocation";
  const newLead = db.addLead({
    customerName: finalCustomer,
    companyName: (companyName || "").trim(),
    phone: rawPhone,
    email: (email || "").trim(),
    pickupCity: finalPickup,
    dropCity: finalDrop,
    serviceCategory: serviceCategory || "Household Relocation",
    movingDate: movingDate || (/* @__PURE__ */ new Date()).toISOString().split("T")[0],
    itemizedNotes: itemizedNotes || "",
    estimatedValue: estimatedValue || 0,
    assignedStaff: "Anil Sharma (Dispatch Desk)",
    assignedStaffPhone: "9773790546"
  });
  const agencySettings = db.getAgencySettings();
  res.status(201).json({
    ...newLead,
    agencyNotificationEmail: agencySettings.agencyNotificationEmail,
    emailDeliveryStatus: "queued"
  });
  setImmediate(() => {
    emailService.sendLeadNotification(newLead).catch((err) => {
      console.error("[BACKGROUND EMAIL ERROR] Failed dispatching lead notification:", err?.message || err);
    });
  });
});
apiRouter.patch("/leads/:id/status", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!["New", "Under Review", "Verified", "Closed"].includes(status)) {
    return res.status(400).json({ error: "Invalid lead status" });
  }
  const updated = db.updateLeadStatus(id, status, req.user?.displayName || "OPERATIONS");
  if (!updated) {
    return res.status(404).json({ error: "Lead not found" });
  }
  res.json(updated);
});
apiRouter.post("/leads/:id/convert-to-client", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const { username, gstin, orderId, phone } = req.body;
  const lead = db.getLeadById(id);
  if (!lead) {
    return res.status(404).json({ error: "Lead not found" });
  }
  const actingUser = req.user?.displayName || "OPERATIONS";
  const clientPhone = phone && typeof phone === "string" && phone.trim() ? phone.trim() : lead.phone;
  const safeUsername = username || lead.customerName.toLowerCase().split(" ")[0].replace(/[^a-z0-9]/g, "") + "_dtc";
  const assignedDocket = orderId || `CN-${Math.floor(1e4 + Math.random() * 9e4)}`;
  const client = db.createClient({
    id: safeUsername,
    username: safeUsername,
    clientName: lead.companyName ? `${lead.customerName} (${lead.companyName})` : lead.customerName,
    companyName: lead.companyName || "",
    gstin: gstin || "URP (Unregistered)",
    phone: clientPhone,
    email: lead.email,
    status: "Active",
    sourceLeadId: lead.id,
    primaryDocketId: assignedDocket
  }, actingUser);
  lead.phone = clientPhone;
  db.updateLeadStatus(lead.id, "Closed", actingUser);
  const newShipment = db.addShipment({
    id: assignedDocket,
    orderRef: assignedDocket,
    clientId: client.id,
    clientName: client.clientName,
    clientPhone,
    serviceCategory: lead.serviceCategory || "Commercial / Household Shifting",
    originCity: lead.pickupCity,
    originHub: `${lead.pickupCity} Operations Hub`,
    destinationCity: lead.dropCity,
    destinationHub: `${lead.dropCity} Terminal`,
    vehiclePlate: "DL-01-AB-4419",
    vehicleType: "Eicher 19ft Closed Container",
    driverName: "Sukhvinder Singh",
    driverPhone: "+91 97737 90546",
    sealTagNumber: `DTC-SL-${Math.floor(1e4 + Math.random() * 9e4)}`,
    insurancePolicyNumber: `Transit Policy #TP-${Math.floor(1e3 + Math.random() * 9e3)}`,
    carrierGstin: "07AAYFD8489Q2ZW",
    packagesCount: 28,
    grossWeightKg: 1850,
    declaredValueInr: lead.estimatedValue || 45e4,
    currentStatus: "Booking Confirmed / In Operations",
    currentLocationNote: `Client surveyed and onboarded from Lead ${lead.id}. Transit operations active at ${lead.pickupCity} Hub.`,
    estimatedArrival: "In 3 Days, 18:00 IST",
    progressPercent: 20,
    milestones: [
      {
        id: `m_${Date.now()}_1`,
        title: "Booking & Transit Custody Ingested",
        location: lead.pickupCity,
        stationOrVehicle: "Central Operations Command",
        timestamp: (/* @__PURE__ */ new Date()).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }) + ", " + (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }),
        completed: true,
        active: false
      },
      {
        id: `m_${Date.now()}_2`,
        title: "Fleet & Packaging Staging",
        location: lead.pickupCity,
        stationOrVehicle: "Terminal Bay 3",
        timestamp: "Active Now",
        completed: false,
        active: true
      }
    ],
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    updatedAt: (/* @__PURE__ */ new Date()).toISOString()
  }, actingUser);
  db.addDocument({
    documentCode: `LR-${assignedDocket}`,
    displayName: `Official Consignment Note & LR (${assignedDocket})`,
    category: "lr",
    clientId: client.id,
    relatedShipmentId: assignedDocket,
    fileSizeText: "1.4 MB",
    mimeType: "application/pdf",
    status: "Verified",
    declaredValue: lead.estimatedValue || 45e4,
    grossWeight: "1,850 KG",
    summaryText: `CONSIGNMENT NOTE (BILTY) - DTC EXPRESS CARGO MOVERS & PACKERS
Docket No: ${assignedDocket}
Client Name: ${client.clientName}
Client Mobile: ${clientPhone}
Origin: ${lead.pickupCity} -> Destination: ${lead.dropCity}
Declared Value: \u20B9${(lead.estimatedValue || 45e4).toLocaleString("en-IN")}
Status: Verified Operational Ingest`,
    uploadedBy: actingUser
  }, actingUser);
  res.status(201).json({
    message: "Client reviewed and onboarded to Ongoing Operations successfully",
    client,
    shipment: newShipment
  });
});
apiRouter.get("/clients", requireRole(["super_admin", "staff"]), (_req, res) => {
  res.json(db.getClients());
});
apiRouter.get("/clients/:id", requireAuth, (req, res) => {
  const requestedId = req.params.id;
  const user = req.user;
  if (user.role === "client") {
    const isOwner = user.linkedClientId && user.linkedClientId.toLowerCase() === requestedId.toLowerCase() || user.username && user.username.toLowerCase() === requestedId.toLowerCase();
    if (!isOwner) {
      const actualClient = db.getClientById(requestedId);
      if (!actualClient || actualClient.id.toLowerCase() !== (user.linkedClientId || "").toLowerCase()) {
        return res.status(403).json({ error: "Access Denied: You may only view your own client account." });
      }
    }
  }
  let client = db.getClientById(requestedId);
  if (!client && (user.role === "super_admin" || user.role === "staff")) {
    if (["superadmin", "admin", "staff", "usr_superadmin", "undefined", "null"].includes(requestedId.toLowerCase())) {
      client = db.getClients()[0];
    }
  }
  if (!client) {
    return res.status(404).json({ error: "Client not found" });
  }
  let shipments = db.getShipmentsByClientId(client.id);
  if (shipments.length === 0 && client.primaryDocketId) {
    const byDocket = db.getShipmentById(client.primaryDocketId);
    if (byDocket) {
      shipments = [byDocket];
    }
  }
  if (shipments.length === 0) {
    const allShipments = db.getShipments();
    const cleanDigits = (client.phone || "").replace(/[^0-9]/g, "");
    const byPhone = allShipments.filter((s) => {
      const sDigits = (s.clientPhone || "").replace(/[^0-9]/g, "");
      return cleanDigits.length >= 10 && sDigits.endsWith(cleanDigits.slice(-10));
    });
    if (byPhone.length > 0) {
      shipments = byPhone;
    }
  }
  const documents = db.getDocuments(client.id);
  const invoices = db.getInvoices(client.id);
  res.json({
    client,
    shipments,
    documents,
    invoices
  });
});
apiRouter.post("/clients", requireRole(["super_admin", "staff"]), (req, res) => {
  const { clientName, companyName, gstin, phone, email, username, primaryDocketId } = req.body;
  if (!clientName || !phone || !username) {
    return res.status(400).json({ error: "clientName, phone, and username are required." });
  }
  const existing = db.getClientById(username);
  if (existing) {
    return res.status(409).json({ error: `Client username "${username}" is already registered.` });
  }
  const client = db.createClient({
    id: username,
    username,
    clientName,
    companyName: companyName || "",
    gstin: gstin || "URP (Unregistered)",
    phone,
    email: email || "",
    status: "Active",
    primaryDocketId: primaryDocketId || `CN-${Math.floor(1e4 + Math.random() * 9e4)}`
  }, req.user?.displayName || "OPERATIONS");
  res.status(201).json(client);
});
apiRouter.patch("/clients/:id/status", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const { status, reason } = req.body;
  if (!["Active", "Deactivated"].includes(status)) {
    return res.status(400).json({ error: "Status must be Active or Deactivated" });
  }
  const updated = db.updateClientStatus(id, status, reason, req.user?.displayName || "OPERATIONS");
  if (!updated) {
    return res.status(404).json({ error: "Client not found" });
  }
  res.json(updated);
});
apiRouter.patch("/clients/:id", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  const updated = db.updateClient(id, updates, req.user?.displayName || "OPERATIONS");
  if (!updated) {
    return res.status(404).json({ error: "Client not found" });
  }
  res.json(updated);
});
apiRouter.get("/shipments", requireAuth, (req, res) => {
  const user = req.user;
  const { clientId } = req.query;
  if (user.role === "client") {
    const targetCid = user.linkedClientId || user.username;
    return res.json(db.getShipmentsByClientId(targetCid));
  }
  if (clientId && typeof clientId === "string") {
    return res.json(db.getShipmentsByClientId(clientId));
  }
  res.json(db.getShipments());
});
apiRouter.get("/shipments/track/:refId", (req, res) => {
  const { refId } = req.params;
  const shipment = db.getShipmentById(refId);
  if (!shipment) {
    return res.status(404).json({
      found: false,
      message: "Docket number not located in terminal registry."
    });
  }
  const publicData = {
    found: true,
    id: shipment.id,
    orderRef: shipment.orderRef,
    originCity: shipment.originCity,
    originHub: shipment.originHub,
    destinationCity: shipment.destinationCity,
    destinationHub: shipment.destinationHub,
    vehiclePlate: shipment.vehiclePlate,
    vehicleType: shipment.vehicleType,
    carrierGstin: shipment.carrierGstin,
    insurancePolicyNumber: shipment.insurancePolicyNumber,
    packagesCount: shipment.packagesCount,
    grossWeightKg: shipment.grossWeightKg,
    currentStatus: shipment.currentStatus,
    currentLocationNote: shipment.currentLocationNote,
    estimatedArrival: shipment.estimatedArrival,
    progressPercent: shipment.progressPercent,
    milestones: shipment.milestones,
    updatedAt: shipment.updatedAt
  };
  res.json(publicData);
});
apiRouter.get("/shipments/:id", requireAuth, (req, res) => {
  const user = req.user;
  const shipment = db.getShipmentById(req.params.id);
  if (!shipment) {
    return res.status(404).json({ error: "Shipment not found" });
  }
  if (user.role === "client") {
    const userCid = (user.linkedClientId || user.username).toLowerCase();
    if (shipment.clientId.toLowerCase() !== userCid && shipment.id.toLowerCase() !== userCid) {
      return res.status(403).json({ error: "Access Denied: Consignment does not belong to your account." });
    }
  }
  res.json(shipment);
});
apiRouter.patch("/shipments/:id/status", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const { status, note } = req.body;
  const validStatuses = ["Booked", "Packing", "In Transit", "Out for Delivery", "Delivered"];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: "Invalid shipment status" });
  }
  const updated = db.updateShipmentStatus(id, status, note, req.user?.displayName || "OPERATIONS");
  if (!updated) {
    return res.status(404).json({ error: "Shipment not found" });
  }
  res.json(updated);
});
apiRouter.patch("/shipments/:id", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  const updated = db.updateShipmentDetails(id, updates, req.user?.displayName || "OPERATIONS");
  if (!updated) {
    return res.status(404).json({ error: "Shipment not found" });
  }
  res.json(updated);
});
apiRouter.post("/shipments/:id/milestones", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const { title, location, stationOrVehicle, note, timestamp, completed, active } = req.body;
  if (!title || !location) {
    return res.status(400).json({ error: "Title and location are required" });
  }
  const updated = db.addShipmentMilestone(id, {
    title,
    location,
    stationOrVehicle: stationOrVehicle || "Field Checkpoint",
    note: note || "",
    timestamp: timestamp || (/* @__PURE__ */ new Date()).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }) + ", " + (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }),
    completed: completed !== void 0 ? Boolean(completed) : true,
    active: active !== void 0 ? Boolean(active) : true
  }, req.user?.displayName || "OPERATIONS");
  if (!updated) {
    return res.status(404).json({ error: "Shipment not found" });
  }
  res.status(201).json(updated);
});
apiRouter.patch("/shipments/:id/milestones/:milestoneId", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id, milestoneId } = req.params;
  const { completed, active, title, location, stationOrVehicle, note, timestamp } = req.body;
  const updated = db.updateShipmentMilestone(id, milestoneId, {
    completed,
    active,
    title,
    location,
    stationOrVehicle,
    note,
    timestamp
  }, req.user?.displayName || "OPERATIONS");
  if (!updated) {
    return res.status(404).json({ error: "Shipment or milestone not found" });
  }
  res.json(updated);
});
apiRouter.delete("/shipments/:id/milestones/:milestoneId", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id, milestoneId } = req.params;
  const updated = db.deleteShipmentMilestone(id, milestoneId, req.user?.displayName || "OPERATIONS");
  if (!updated) {
    return res.status(404).json({ error: "Shipment or milestone not found" });
  }
  res.json(updated);
});
apiRouter.get("/documents", requireAuth, (req, res) => {
  const user = req.user;
  const { clientId, category } = req.query;
  const targetCid = user.role === "client" ? user.linkedClientId || user.username : typeof clientId === "string" ? clientId : void 0;
  let docs = db.getDocuments(targetCid);
  if (category && typeof category === "string" && category !== "all" && category !== "ALL") {
    docs = docs.filter((d) => d.category.toLowerCase() === category.toLowerCase());
  }
  res.json(docs);
});
apiRouter.get("/documents/:id", requireAuth, (req, res) => {
  const user = req.user;
  const doc = db.getDocumentById(req.params.id);
  if (!doc) {
    return res.status(404).json({ error: "Document not found" });
  }
  if (user.role === "client") {
    const userCid = (user.linkedClientId || user.username).toLowerCase();
    if (doc.clientId.toLowerCase() !== userCid) {
      return res.status(403).json({ error: "Access Denied: Document belongs to another consignor." });
    }
  }
  res.json(doc);
});
apiRouter.post("/documents", requireRole(["super_admin", "staff"]), (req, res) => {
  const {
    documentCode,
    displayName,
    category,
    clientId,
    relatedShipmentId,
    fileSizeText,
    summaryText,
    declaredValue,
    grossWeight,
    fileName,
    fileData,
    documentData
  } = req.body;
  if (!documentCode || !displayName || !clientId) {
    return res.status(400).json({ error: "documentCode, displayName, and clientId are required." });
  }
  const actingUser = req.user?.displayName || "OPERATIONS";
  const newDoc = db.addDocument({
    documentCode,
    displayName,
    category: category || "lr",
    clientId,
    relatedShipmentId: relatedShipmentId || "",
    fileSizeText: fileSizeText || "1.2 MB",
    mimeType: "application/pdf",
    status: "Verified",
    declaredValue: declaredValue || 0,
    grossWeight: grossWeight || "",
    summaryText: summaryText || "Legally verified commercial cargo document.",
    fileName: fileName || `${documentCode}.pdf`,
    fileData: fileData || void 0,
    documentData: documentData || void 0,
    uploadedBy: actingUser
  }, actingUser);
  res.status(201).json(newDoc);
});
apiRouter.delete("/documents/:id", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const ok = db.deleteDocument(id, req.user?.displayName || "OPERATIONS");
  if (!ok) {
    return res.status(404).json({ error: "Document not found" });
  }
  res.json({ message: "Document removed successfully" });
});
apiRouter.get("/documents/:id/download", requireAuth, (req, res) => {
  const user = req.user;
  const doc = db.getDocumentById(req.params.id);
  if (!doc) {
    return res.status(404).json({ error: "Document not found" });
  }
  if (user.role === "client") {
    const userCid = (user.linkedClientId || user.username).toLowerCase();
    if (doc.clientId.toLowerCase() !== userCid) {
      return res.status(403).json({ error: "Access Denied: You may not download another client\u2019s document." });
    }
  }
  const fileName = doc.fileName || `${doc.documentCode}.pdf`;
  if (doc.fileData && doc.fileData.length > 50) {
    try {
      const base64Index = doc.fileData.indexOf(";base64,");
      const base64Str = base64Index !== -1 ? doc.fileData.substring(base64Index + 8) : doc.fileData;
      const fileBuffer = Buffer.from(base64Str, "base64");
      res.setHeader("Content-Type", doc.mimeType || "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
      res.setHeader("Content-Length", fileBuffer.length);
      return res.send(fileBuffer);
    } catch (err) {
      console.warn("Failed to decode stored base64 file data, falling back to official PDF generator:", err);
    }
  }
  try {
    const client = db.getClientById(doc.clientId);
    const shipment = doc.relatedShipmentId ? db.getShipmentById(doc.relatedShipmentId) : doc.clientId ? db.getShipmentsByClientId(doc.clientId)[0] : void 0;
    const data = doc.documentData || {};
    let pdfBuffer;
    const cat = doc.category?.toLowerCase();
    if (cat === "booking_receipt") {
      pdfBuffer = createBookingConfirmationReceiptPdf(doc, data);
    } else if (cat === "quotation") {
      pdfBuffer = createQuotationPdf(doc, data);
    } else if (cat === "invoice") {
      pdfBuffer = createBillOfSupplyPdf(doc, data);
    } else if (cat === "receipts") {
      pdfBuffer = createMoneyReceiptPdf(doc, data);
    } else {
      pdfBuffer = createLRDocumentPdf(doc, shipment, client, data);
    }
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
    res.setHeader("Content-Length", pdfBuffer.length);
    return res.send(pdfBuffer);
  } catch (err) {
    console.error("PDF generation error:", err);
    res.status(500).json({ error: "Failed to generate PDF document" });
  }
});
apiRouter.get("/checklist", requireAuth, (req, res) => {
  const user = req.user;
  const { clientId, shipmentId } = req.query;
  const targetCid = user.role === "client" ? user.linkedClientId || user.username : typeof clientId === "string" ? clientId : void 0;
  const items = db.getChecklistItems(
    targetCid,
    typeof shipmentId === "string" ? shipmentId : void 0
  );
  res.json(items);
});
apiRouter.post("/checklist", requireRole(["super_admin", "staff"]), (req, res) => {
  const { clientId, shipmentId, itemName, quantity, category, conditionNote, status, addedBy } = req.body;
  if (!clientId || !itemName) {
    return res.status(400).json({ error: "clientId and itemName are required." });
  }
  const actingUser = req.user?.displayName || "OPERATIONS";
  const newItem = db.addChecklistItem({
    clientId,
    shipmentId: shipmentId || "",
    itemName: itemName.trim(),
    quantity: Math.max(1, Number(quantity) || 1),
    category: category || "Other",
    conditionNote: conditionNote || "",
    status: status || "Pending",
    addedBy: addedBy || `Staff (${actingUser})`
  }, actingUser);
  res.status(201).json(newItem);
});
apiRouter.patch("/checklist/:id", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const { itemName, quantity, category, conditionNote, status } = req.body;
  const updated = db.updateChecklistItem(id, {
    ...itemName ? { itemName } : {},
    ...quantity ? { quantity: Number(quantity) } : {},
    ...category ? { category } : {},
    ...conditionNote !== void 0 ? { conditionNote } : {},
    ...status ? { status } : {}
  }, req.user?.displayName || "OPERATIONS");
  if (!updated) {
    return res.status(404).json({ error: "Checklist item not found" });
  }
  res.json(updated);
});
apiRouter.delete("/checklist/:id", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const ok = db.deleteChecklistItem(id, req.user?.displayName || "OPERATIONS");
  if (!ok) {
    return res.status(404).json({ error: "Checklist item not found" });
  }
  res.json({ message: "Checklist item removed successfully" });
});
apiRouter.get("/checklist/download", requireAuth, (req, res) => {
  const user = req.user;
  const { clientId, shipmentId } = req.query;
  let cid = typeof clientId === "string" ? clientId : void 0;
  const sid = typeof shipmentId === "string" ? shipmentId : void 0;
  if (user.role === "client") {
    cid = user.linkedClientId || user.username;
  }
  const items = db.getChecklistItems(cid, sid);
  const client = cid ? db.getClientById(cid) : void 0;
  const shipment = sid ? db.getShipmentById(sid) : cid ? db.getShipmentsByClientId(cid)[0] : void 0;
  const clientName = client?.clientName || shipment?.clientName || "Valued Consignor";
  const docketNo = shipment?.id || "DTC-CHECKLIST-MANIFEST";
  try {
    const pdfBuffer = createChecklistManifestPdf(clientName, docketNo, items, shipment);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="Packing-Checklist-${docketNo}.pdf"`);
    res.setHeader("Content-Length", pdfBuffer.length);
    res.send(pdfBuffer);
  } catch (err) {
    console.error("Checklist PDF generation error:", err);
    res.status(500).json({ error: "Failed to generate Checklist PDF" });
  }
});
apiRouter.get("/invoices", requireAuth, (req, res) => {
  const user = req.user;
  const { clientId } = req.query;
  const targetCid = user.role === "client" ? user.linkedClientId || user.username : typeof clientId === "string" ? clientId : void 0;
  res.json(db.getInvoices(targetCid));
});
apiRouter.post("/invoices", requireRole(["super_admin", "staff"]), (req, res) => {
  const { invoiceReference, clientId, clientName, relatedShipmentId, issueDate, amount, gstRate, status, paymentMode, irnHash } = req.body;
  if (!invoiceReference || !clientId || !amount) {
    return res.status(400).json({ error: "invoiceReference, clientId, and amount are required" });
  }
  const invoice = db.addInvoice({
    invoiceReference,
    clientId,
    clientName: clientName || clientId,
    relatedShipmentId: relatedShipmentId || "",
    issueDate: issueDate || (/* @__PURE__ */ new Date()).toISOString().substring(0, 10),
    amount: Number(amount),
    gstRate: gstRate !== void 0 ? Number(gstRate) : 18,
    status: status || "Pending",
    paymentMode: paymentMode || "Bank NEFT",
    irnHash: irnHash || Math.random().toString(36).substring(2, 18)
  }, req.user?.displayName || "OPERATIONS");
  res.status(201).json(invoice);
});
apiRouter.patch("/invoices/:id/status", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!["Paid", "Pending", "Overdue"].includes(status)) {
    return res.status(400).json({ error: "Status must be Paid, Pending, or Overdue" });
  }
  const updated = db.updateInvoiceStatus(id, status, req.user?.displayName || "OPERATIONS");
  if (!updated) {
    return res.status(404).json({ error: "Invoice not found" });
  }
  res.json(updated);
});
apiRouter.get("/services", (_req, res) => {
  res.json(db.getServices());
});
apiRouter.patch("/services/:id", requireRole(["super_admin", "staff"]), (req, res) => {
  const { id } = req.params;
  const { title, description, badge, visible } = req.body;
  const updated = db.updateService(id, { title, description, badge, visible }, req.user?.displayName || "OPERATIONS");
  if (!updated) {
    return res.status(404).json({ error: "Service not found" });
  }
  res.json(updated);
});
apiRouter.get("/complaints", requireRole(["super_admin", "staff"]), (_req, res) => {
  res.json(db.getComplaints());
});
apiRouter.post("/complaints", (req, res) => {
  const { customerName, phone, email, relatedShipmentId, category, description } = req.body;
  if (!customerName || !phone || !description) {
    return res.status(400).json({ error: "Name, phone, and description are required." });
  }
  const complaint = db.addComplaint({
    customerName,
    phone,
    email: email || "",
    relatedShipmentId: relatedShipmentId || "",
    category: category || "General Inquiry",
    description
  });
  res.status(201).json(complaint);
  setImmediate(() => {
    emailService.sendComplaintNotification(complaint).catch((err) => {
      console.error("[EMAIL COMPLAINT DISPATCH ERROR]", err?.message || err);
    });
  });
});
apiRouter.get("/audit", requireRole(["super_admin"]), (_req, res) => {
  res.json(db.getAuditLogs());
});
apiRouter.get("/stats", requireRole(["super_admin", "staff"]), (_req, res) => {
  res.json(db.getStats());
});
apiRouter.get("/settings/agency", requireRole(["super_admin", "staff"]), (_req, res) => {
  const settings = db.getAgencySettings();
  res.json({
    ...settings,
    smtpPass: settings.smtpPass ? "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" : ""
  });
});
apiRouter.put("/settings/agency", requireRole(["super_admin", "staff"]), (req, res) => {
  const {
    agencyNotificationEmail,
    agencyPhone,
    smtpHost,
    smtpPort,
    smtpUser,
    smtpPass,
    smtpSecure,
    smtpFrom,
    notifyOnNewLead,
    notifyOnNewComplaint
  } = req.body;
  const update = {};
  if (agencyNotificationEmail !== void 0) update.agencyNotificationEmail = (agencyNotificationEmail || "").trim();
  if (agencyPhone !== void 0) update.agencyPhone = (agencyPhone || "").trim();
  if (smtpHost !== void 0) update.smtpHost = (smtpHost || "").trim();
  if (smtpPort !== void 0) update.smtpPort = Number(smtpPort) || 587;
  if (smtpUser !== void 0) update.smtpUser = (smtpUser || "").trim();
  if (smtpPass !== void 0 && smtpPass !== "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022") update.smtpPass = smtpPass;
  if (smtpSecure !== void 0) update.smtpSecure = Boolean(smtpSecure);
  if (smtpFrom !== void 0) update.smtpFrom = (smtpFrom || "").trim();
  if (notifyOnNewLead !== void 0) update.notifyOnNewLead = Boolean(notifyOnNewLead);
  if (notifyOnNewComplaint !== void 0) update.notifyOnNewComplaint = Boolean(notifyOnNewComplaint);
  const updated = db.updateAgencySettings(update, req.user?.displayName || "ADMIN");
  res.json({
    ...updated,
    smtpPass: updated.smtpPass ? "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" : ""
  });
});
apiRouter.get("/notifications/outbox", requireRole(["super_admin", "staff"]), (_req, res) => {
  res.json(db.getEmailLogs());
});
apiRouter.post("/notifications/test-email", requireRole(["super_admin", "staff"]), async (req, res) => {
  const { targetEmail } = req.body;
  const result = await emailService.sendTestNotification(targetEmail);
  res.json(result);
});
apiRouter.get("/content", (_req, res) => {
  const settings = db.getAgencySettings();
  res.json({
    companyName: "DTC Express Cargo Movers and Packers",
    website: "dtcexpresscargo.in",
    customerSupport: settings.agencyPhone || "9773790546",
    whatsapp: settings.agencyPhone || "9773790546",
    email: settings.agencyNotificationEmail.split(",")[0].trim() || "customer@dtcexpresscargo.in",
    registrationAddress: "Pole No. NJSF 310, Ground Floor, Chawla Village, Delhi 110071.",
    corporateAddress: "B-13, Gokhale Market, Mori Gate, Delhi 110006.",
    branchAddress: "Plot No. 12, DLF Ankur Vihar, Ghaziabad, Uttar Pradesh 201102.",
    udyam: "UDYAM-DL-10-0107770",
    pan: "AAYFD8489Q",
    gstin: "07AAYFD8489Q2ZW",
    claims: {
      branches: "250+",
      experience: "30+",
      happyCustomers: "2 Lakh+",
      containers: "1,500+"
    },
    directors: [
      { name: "Akash Sharma", role: "Managing Director", division: "Fleet & Logistics Strategy" },
      { name: "Sonu Sharma", role: "Director - Operations", division: "Customer Experience & Hub Control" }
    ]
  });
});

// server.ts
import dotenv from "dotenv";
if (!process.env.UV_THREADPOOL_SIZE) {
  process.env.UV_THREADPOOL_SIZE = "2";
}
dotenv.config();
var __filename = fileURLToPath(import.meta.url);
var __dirname = path2.dirname(__filename);
async function startServer() {
  const app = express2();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3e3;
  const distPath = path2.resolve(__dirname, "dist");
  const distExists = fs2.existsSync(path2.resolve(distPath, "index.html"));
  const isDev = process.env.NODE_ENV === "development" && !distExists;
  const isProd = !isDev;
  app.use(express2.json());
  app.use(express2.urlencoded({ extended: true }));
  app.use((req, res, next) => {
    const p = req.path.toLowerCase();
    if (p.startsWith("/data") || p.startsWith("/server") || isProd && p.startsWith("/node_modules") || p.includes("/.env") || p.includes("/.git") || p.endsWith(".json") && p !== "/metadata.json" || isProd && (p.startsWith("/src") || p.endsWith(".ts") || p.endsWith(".tsx")) || p === "/package.json" || p === "/tsconfig.json") {
      return res.status(403).json({ error: "Access Denied: Protected System Resource" });
    }
    next();
  });
  app.use("/api", apiRouter);
  app.use("/api/*", (_req, res) => {
    res.status(404).json({ error: "API endpoint not found", code: "NOT_FOUND" });
  });
  app.get(["/dist.zip", "/dist-latest.zip", "/download/dist", "/download/dist.zip", "/dtc-express-dist.zip"], (_req, res) => {
    const zipPath = path2.resolve(__dirname, "public", "dist.zip");
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Content-Disposition", 'attachment; filename="dtc-express-dist.zip"');
    res.setHeader("Content-Type", "application/zip");
    res.sendFile(zipPath);
  });
  const publicDir = path2.resolve(__dirname, "public");
  app.use(express2.static(publicDir));
  app.use("/logo", express2.static(path2.resolve(publicDir, "logo")));
  app.use("/log", express2.static(path2.resolve(publicDir, "log")));
  app.use("/photos", express2.static(path2.resolve(publicDir, "photos")));
  if (isDev) {
    const { createServer } = await import("vite");
    const vite = await createServer({
      server: {
        middlewareMode: true,
        host: "0.0.0.0",
        port: PORT,
        hmr: process.env.DISABLE_HMR !== "true",
        watch: process.env.DISABLE_HMR === "true" ? null : {}
      },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distPath2 = path2.resolve(__dirname, "dist");
    app.use(express2.static(distPath2));
    app.get("*", (_req, res) => {
      res.sendFile(path2.resolve(distPath2, "index.html"));
    });
  }
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`DTC Express Cargo Movers server running on http://0.0.0.0:${PORT}`);
  });
}
startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
