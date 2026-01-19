// ============================================================
// OneKamer - Serveur Stripe + Supabase (OK COINS + Abonnements)
// ============================================================

// ============================================================
// OneKamer - Serveur Stripe + Supabase (OK COINS + Abonnements)
// ============================================================

import * as dotenv from "dotenv";
dotenv.config(); // <-- chargera automatiquement le .env à la racine

// Vérification visuelle (envPath supprimé pour éviter ReferenceError)
console.log("📂 .env chargé");
console.log("🔗 SUPABASE_URL =", process.env.SUPABASE_URL);

import express from "express";
import Stripe from "stripe";
import crypto from "crypto";
import bodyParser from "body-parser";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import { AccessToken } from "livekit-server-sdk";
import nodemailer from "nodemailer";
import webpush from "web-push";
import uploadRoute from "./api/upload.js";
import partenaireDefaultsRoute from "./api/fix-partenaire-images.js";
import fixAnnoncesImagesRoute from "./api/fix-annonces-images.js";
import fixEvenementsImagesRoute from "./api/fix-evenements-images.js";
import pushRouter from "./api/push.js";
import qrcodeRouter from "./api/qrcode.js";
import { createFxService } from "./utils/fx.js";

// ✅ Correction : utiliser le fetch natif de Node 18+ (pas besoin d'import)
const fetch = globalThis.fetch;
// =======================================================
// ✅ CONFIGURATION CORS — OneKamer Render + Horizon
// =======================================================
const app = express();
const NOTIF_PROVIDER = process.env.NOTIFICATIONS_PROVIDER || "supabase_light";
// 🔹 Récupération et gestion de plusieurs origines depuis l'environnement
const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map(origin => origin.trim())
  : [
      "https://onekamer.co",                        // Horizon (production)
      "https://onekamer-front-render.onrender.com", // Render (ancien test/labo)
      "https://onekamer-front-lab.onrender.com",    // Render (front lab actuel)
    ];

// 🔧 Autorisations locales pour le développement/tests (sans ouvrir la prod)
function isDevOrigin(origin) {
  try {
    const url = new URL(origin);
    const host = url.hostname;
    const protoOk = url.protocol === "http:" || url.protocol === "https:";
    if (!protoOk) return false;
    return (
      host === "localhost" ||
      host === "127.0.0.1" ||
      host.startsWith("192.168.") ||
      host.startsWith("10.")
    );
  } catch (_e) {
    return false;
  }
}

// ============================================================
// 🔔 supabase_light — Web Push (LAB)
// ============================================================

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || "mailto:contact@onekamer.co";

try {
  if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
    webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
  }
} catch {}

async function sendSupabaseLightPush({ title, message, targetUserIds = [], data = {}, url = "/" }) {
  if (NOTIF_PROVIDER !== "supabase_light") return { success: false, reason: "provider_disabled", sent: 0 };
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) return { success: false, reason: "vapid_not_configured", sent: 0 };

  const uniqueUserIds = Array.isArray(targetUserIds) ? Array.from(new Set(targetUserIds.filter(Boolean))) : [];
  if (uniqueUserIds.length === 0) return { success: false, reason: "no_targets", sent: 0 };

  const { data: subs } = await supabase
    .from("push_subscriptions")
    .select("user_id, endpoint, p256dh, auth")
    .in("user_id", uniqueUserIds);

  const icon = "https://onekamer-media-cdn.b-cdn.net/logo/IMG_0885%202.PNG";
  const payload = JSON.stringify({ title, body: message, icon, url, data });

  let sent = 0;
  if (Array.isArray(subs)) {
    for (const s of subs) {
      try {
        await webpush.sendNotification(
          { endpoint: s.endpoint, expirationTime: null, keys: { p256dh: s.p256dh, auth: s.auth } },
          payload
        );
        sent += 1;
      } catch (err) {
        console.error("webpush_send_error", {
          status: err?.statusCode,
          code: err?.code,
          message: err?.message,
        });
      }
    }
  }

  // Historique notifications in-app (RPC)
  try {
    const notifType = (data && (data.type || data.notificationType)) || "systeme";
    const contentId = data && (data.contentId || data.content_id) ? data.contentId || data.content_id : null;
    const senderId = data && (data.senderId || data.sender_id) ? data.senderId || data.sender_id : null;

    for (const userId of uniqueUserIds) {
      try {
        await supabase.rpc("create_notification", {
          p_user_id: userId,
          p_sender_id: senderId,
          p_type: notifType,
          p_content_id: contentId,
          p_title: title,
          p_message: message,
          p_link: url || "/",
        });
      } catch (err) {
        console.error("notification_persist_error", { user_id: userId, message: err?.message });
      }
    }
  } catch (err) {
    console.error("notification_persist_wrapper_error", { message: err?.message });
  }

  return { success: true, sent };
}

// ============================================================
// 🔔 Helper générique @tous (LOG ONLY pour LAB)
// ============================================================

async function handleAtTousIfAllowed({
  req,
  supabase,
  NOTIF_PROVIDER,
  authorId,
  contextType,
  contextId,
  rawText,
}) {
  try {
    if (NOTIF_PROVIDER !== "supabase_light") return;
    if (!rawText || typeof rawText !== "string") return;
    if (!rawText.includes("@tous")) return;

    // Vérifier que l'auteur est admin global
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("id, is_admin, role")
      .eq("id", authorId)
      .maybeSingle();

    if (profileError || !profile) {
      await logEvent({
        category: "attous",
        action: "guard.check_admin",
        status: "error",
        userId: authorId,
        context: { reason: "profile_not_found", error: profileError?.message },
      });
      return;
    }

    const isAdmin = Boolean(profile.is_admin) || profile.role === "admin";
    if (!isAdmin) {
      await logEvent({
        category: "attous",
        action: "guard.not_admin",
        status: "info",
        userId: authorId,
        context: { contextType, contextId },
      });
      return;
    }

    let targetUserIds = [];

    if (contextType === "groupe") {
      const { data: members, error: membersError } = await supabase
        .from("groupes_membres")
        .select("user_id")
        .eq("groupe_id", contextId);

      if (membersError) {
        await logEvent({
          category: "attous",
          action: "fetch_members.error",
          status: "error",
          userId: authorId,
          context: { contextType, contextId, error: membersError.message },
        });
        return;
      }

      targetUserIds = (members || [])
        .map((m) => m.user_id)
        .filter((id) => !!id && id !== authorId);
    }

    if (!Array.isArray(targetUserIds) || targetUserIds.length === 0) {
      await logEvent({
        category: "attous",
        action: "target.empty",
        status: "info",
        userId: authorId,
        context: { contextType, contextId },
      });
      return;
    }

    // Phase 1 LAB : on loggue uniquement ce qui serait envoyé (dry-run)
    await logEvent({
      category: "attous",
      action: "push.dryrun",
      status: "success",
      userId: authorId,
      context: {
        contextType,
        contextId,
        target_count: targetUserIds.length,
      },
    });
  } catch (e) {
    console.warn("⚠️ handleAtTousIfAllowed error:", e?.message || e);
    await logEvent({
      category: "attous",
      action: "exception",
      status: "error",
      userId: authorId,
      context: { contextType, contextId, error: e?.message || String(e) },
    });
  }
}

app.use(
  cors({
    origin: function (origin, callback) {
      // Autorise les appels sans origin (ex: Postman, tests internes)
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin) || isDevOrigin(origin)) {
        callback(null, true);
      } else {
        console.warn(`🚫 CORS refusé pour l'origine : ${origin}`);
        callback(new Error("Non autorisé par CORS"));
      }
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "Accept",
      "x-admin-token",
    ],
    credentials: true,
  })
);

console.log("✅ CORS actif pour :", allowedOrigins.join(", "));

app.use("/api", uploadRoute);
app.use("/api", partenaireDefaultsRoute);
app.use("/api", fixAnnoncesImagesRoute);
app.use("/api", fixEvenementsImagesRoute);
app.use("/api", pushRouter);
app.use("/api", qrcodeRouter);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: "2024-06-20",
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const fxService = createFxService({ supabase, fetchImpl: fetch });

// Configuration Stripe (clé publique) pour Elements (LAB)
app.get("/api/stripe/config", async (req, res) => {
  try {
    const publishableKey = process.env.STRIPE_PUBLISHABLE_KEY;
    if (!publishableKey) return res.status(500).json({ error: "publishable_key_missing" });
    return res.json({ publishableKey });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/market/fx-rate", async (req, res) => {
  try {
    const from = String(req.query.from || "").trim().toUpperCase();
    const to = String(req.query.to || "").trim().toUpperCase();
    if (!from || !to) return res.status(400).json({ error: "from et to requis" });

    const rate = await fxService.getRate(from, to);
    return res.json({ from, to, rate });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "fx_error" });
  }
});

function countryToCurrency(countryCode) {
  const cc = String(countryCode || "").trim().toUpperCase();
  if (!cc) return "EUR";
  if (cc === "CA") return "CAD";
  if (cc === "GB") return "GBP";
  if (cc === "CH") return "CHF";
  if (cc === "MA") return "MAD";
  const euroCountries = new Set([
    "AT",
    "BE",
    "CY",
    "DE",
    "EE",
    "ES",
    "FI",
    "FR",
    "GR",
    "HR",
    "IE",
    "IT",
    "LT",
    "LU",
    "LV",
    "MT",
    "NL",
    "PT",
    "SI",
    "SK",
  ]);
  if (euroCountries.has(cc)) return "EUR";
  if (cc === "US") return "USD";
  return "USD";
}

async function requireUserJWT(req) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return { ok: false, status: 401, error: "unauthorized" };

  const supabaseAuth = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
  const { data: userData, error: userErr } = await supabaseAuth.auth.getUser(token);
  if (userErr || !userData?.user) return { ok: false, status: 401, error: "invalid_token" };

  return { ok: true, userId: userData.user.id, token };
}

function getRequestIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim()) return xff.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || "";
}

function hashIp(ip) {
  const v = String(ip || "").trim();
  if (!v) return null;
  return crypto.createHash("sha256").update(v).digest("hex");
}

function generateInviteCode() {
  return `OK-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
}

app.post("/api/invites/my-code", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { data: existing, error: readErr } = await supabase
      .from("invites")
      .select("code, created_at, revoked_at")
      .eq("inviter_user_id", guard.userId)
      .is("revoked_at", null)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (readErr) return res.status(500).json({ error: readErr.message || "invite_read_failed" });
    if (existing?.code) return res.json({ code: existing.code, created_at: existing.created_at });

    let code = generateInviteCode();
    for (let i = 0; i < 5; i += 1) {
      const { error: insErr } = await supabase
        .from("invites")
        .insert({ code, inviter_user_id: guard.userId });
      if (!insErr) return res.json({ code });
      code = generateInviteCode();
    }

    return res.status(500).json({ error: "invite_create_failed" });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/api/invites/track", bodyParser.json(), async (req, res) => {
  try {
    const { code, event, meta, user_email, user_username } = req.body || {};
    const cleanCode = String(code || "").trim();
    const cleanEvent = String(event || "").trim();
    if (!cleanCode) return res.status(400).json({ error: "missing_code" });
    if (!cleanEvent) return res.status(400).json({ error: "missing_event" });

    const allowed = new Set(["click", "signup", "first_login", "install"]);
    if (!allowed.has(cleanEvent)) return res.status(400).json({ error: "invalid_event" });

    const { data: invite, error: invErr } = await supabase
      .from("invites")
      .select("code, inviter_user_id, revoked_at")
      .eq("code", cleanCode)
      .maybeSingle();
    if (invErr) return res.status(500).json({ error: invErr.message || "invite_read_failed" });
    if (!invite || invite.revoked_at) return res.status(404).json({ error: "invite_not_found" });

    let trackedUserId = null;
    let trackedEmail = null;
    let trackedUsername = null;

    const authHeader = req.headers["authorization"] || "";
    if (authHeader.startsWith("Bearer ")) {
      const guard = await requireUserJWT(req);
      if (guard.ok) {
        trackedUserId = guard.userId;
        const supabaseAuth = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
        const { data: userData } = await supabaseAuth.auth.getUser(guard.token);
        trackedEmail = userData?.user?.email || null;

        const { data: prof } = await supabase
          .from("profiles")
          .select("username")
          .eq("id", guard.userId)
          .maybeSingle();
        trackedUsername = prof?.username || null;
      }
    }

    if (!trackedEmail && user_email) trackedEmail = String(user_email).trim() || null;
    if (!trackedUsername && user_username) trackedUsername = String(user_username).trim() || null;

    const ip = getRequestIp(req);
    const ipHash = hashIp(ip);
    const ua = String(req.headers["user-agent"] || "").slice(0, 500) || null;

    if (cleanEvent === "click" && ipHash) {
      const since = new Date(Date.now() - 10 * 60 * 1000).toISOString();
      const { data: lastClick } = await supabase
        .from("invite_events")
        .select("id")
        .eq("code", cleanCode)
        .eq("event", "click")
        .eq("ip_hash", ipHash)
        .gte("created_at", since)
        .order("created_at", { ascending: false })
        .limit(1);
      if (Array.isArray(lastClick) && lastClick.length > 0) {
        return res.json({ ok: true, deduped: true });
      }
    }

    const { error: insErr } = await supabase
      .from("invite_events")
      .insert({
        code: cleanCode,
        event: cleanEvent,
        user_id: trackedUserId,
        user_username: trackedUsername,
        user_email: trackedEmail,
        ip_hash: ipHash,
        user_agent: ua,
        meta: meta && typeof meta === "object" ? meta : null,
      });
    if (insErr) return res.status(500).json({ error: insErr.message || "invite_event_insert_failed" });

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/invites/my-stats", async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const period = String(req.query?.period || "30d").toLowerCase();
    let sinceIso = null;
    if (period === "7d") sinceIso = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    else if (period === "30d") sinceIso = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

    const { data: invite, error: invErr } = await supabase
      .from("invites")
      .select("code, created_at")
      .eq("inviter_user_id", guard.userId)
      .is("revoked_at", null)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (invErr) return res.status(500).json({ error: invErr.message || "invite_read_failed" });
    if (!invite?.code) return res.json({ code: null, stats: {}, recent: [] });

    const events = ["click", "signup", "first_login", "install"];
    const stats = {};
    for (const ev of events) {
      let q = supabase
        .from("invite_events")
        .select("id", { count: "exact", head: true })
        .eq("code", invite.code)
        .eq("event", ev);
      if (sinceIso) q = q.gte("created_at", sinceIso);
      const { count, error } = await q;
      if (error) return res.status(500).json({ error: error.message || "stats_read_failed" });
      stats[ev] = count || 0;
    }

    let recentQuery = supabase
      .from("invite_events")
      .select("id, event, created_at, user_id, user_username, user_email, meta")
      .eq("code", invite.code)
      .order("created_at", { ascending: false })
      .limit(10);
    if (sinceIso) recentQuery = recentQuery.gte("created_at", sinceIso);
    const { data: recent, error: recErr } = await recentQuery;
    if (recErr) return res.status(500).json({ error: recErr.message || "events_read_failed" });

    return res.json({ code: invite.code, stats, recent: recent || [] });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/api/presence/heartbeat", async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { data: prof, error: pErr } = await supabase
      .from("profiles")
      .select("id, show_online_status")
      .eq("id", guard.userId)
      .maybeSingle();
    if (pErr) return res.status(500).json({ error: pErr.message || "profile_read_failed" });
    if (!prof) return res.status(404).json({ error: "profile_not_found" });

    if (prof.show_online_status !== true) {
      return res.json({ ok: true, updated: false });
    }

    const now = new Date().toISOString();
    const { error: upErr } = await supabase
      .from("profiles")
      .update({ last_seen_at: now, updated_at: now })
      .eq("id", guard.userId);
    if (upErr) return res.status(500).json({ error: upErr.message || "profile_update_failed" });
    return res.json({ ok: true, updated: true, last_seen_at: now });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

async function getActiveFeeSettings(currency) {
  const cur = String(currency || "").trim().toUpperCase();
  const { data, error } = await supabase
    .from("marketplace_fee_settings")
    .select("currency, percent_bps, fixed_fee_amount")
    .eq("currency", cur)
    .eq("is_active", true)
    .maybeSingle();
  if (error || !data) return null;
  return data;
}

async function requirePartnerOwner({ req, partnerId }) {
  const guard = await requireUserJWT(req);
  if (!guard.ok) return guard;

  const { data: partner, error: pErr } = await supabase
    .from("partners_market")
    .select("id, owner_user_id, stripe_connect_account_id, payout_status")
    .eq("id", partnerId)
    .maybeSingle();

  if (pErr) return { ok: false, status: 500, error: pErr.message || "partner_read_failed" };
  if (!partner) return { ok: false, status: 404, error: "partner_not_found" };
  if (partner.owner_user_id !== guard.userId) return { ok: false, status: 403, error: "forbidden" };
  return { ok: true, userId: guard.userId, partner };
}

async function requireVipOrAdminUser({ req }) {
  const guard = await requireUserJWT(req);
  if (!guard.ok) return guard;

  const { data: profile, error } = await supabase
    .from("profiles")
    .select("id, plan, role, is_admin, country_code")
    .eq("id", guard.userId)
    .maybeSingle();

  if (error) return { ok: false, status: 500, error: error.message || "profile_read_failed" };
  if (!profile) return { ok: false, status: 404, error: "profile_not_found" };

  const plan = String(profile.plan || "free").toLowerCase();
  const isAdmin = Boolean(profile.is_admin) || String(profile.role || "").toLowerCase() === "admin";
  const isVip = plan === "vip";
  if (!isAdmin && !isVip) return { ok: false, status: 403, error: "vip_required" };

  return { ok: true, userId: guard.userId, token: guard.token, profile };
}

app.get("/api/market/partners", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("partners_market")
      .select(
        "id, display_name, description, category, country_code, base_currency, status, payout_status, is_open, logo_url, phone, whatsapp, address, hours, created_at"
      )
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message || "Erreur lecture partenaires" });

    const partners = (data || []).map((p) => {
      const isApproved = String(p.status || "").toLowerCase() === "approved";
      const payoutComplete = String(p.payout_status || "").toLowerCase() === "complete";
      const isOpen = p.is_open === true;
      const commandable = isApproved && payoutComplete && isOpen;
      return { ...p, commandable };
    });

    return res.json({ partners });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/market/partners/me", async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { data: partner, error } = await supabase
      .from("partners_market")
      .select(
        "id, owner_user_id, display_name, description, category, status, payout_status, stripe_connect_account_id, is_open, logo_url, phone, whatsapp, address, hours, created_at, updated_at"
      )
      .eq("owner_user_id", guard.userId)
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message || "Erreur lecture boutique" });
    return res.json({ partner: partner || null });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// Signaler une boutique (report)
app.post("/api/market/partners/:partnerId/report", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });
    const { partnerId } = req.params;
    const { reason, details } = req.body || {};
    const normalizedReason = typeof reason === "string" ? reason.trim() : "";
    if (!partnerId || !normalizedReason) return res.status(400).json({ error: "partnerId et reason requis" });

    const { data: existing, error: exErr } = await supabase
      .from("marketplace_shop_reports")
      .select("id, status")
      .eq("shop_id", partnerId)
      .eq("reporter_id", guard.userId)
      .eq("status", "open")
      .maybeSingle();
    if (exErr) return res.status(500).json({ error: exErr.message || "report_read_failed" });
    if (existing) return res.json({ id: existing.id, status: existing.status || "open", dedup: true });

    const payload = {
      shop_id: partnerId,
      reporter_id: guard.userId,
      reason: normalizedReason,
      details: typeof details === "string" ? details.slice(0, 2000) : null,
      status: "open",
      created_at: new Date().toISOString(),
    };

    const { data: inserted, error: insErr } = await supabase
      .from("marketplace_shop_reports")
      .insert(payload)
      .select("id")
      .maybeSingle();
    if (insErr) return res.status(500).json({ error: insErr.message || "report_insert_failed" });

    try {
      await logEvent({
        category: "marketplace",
        action: "shop.report.create",
        status: "success",
        userId: guard.userId,
        context: { partner_id: partnerId, reason: normalizedReason },
      });
    } catch {}

    try {
      const { data: admins, error } = await supabase
        .from("profiles")
        .select("id")
        .eq("is_admin", true);
      if (!error && Array.isArray(admins) && admins.length > 0) {
        const targetUserIds = admins.map((a) => a.id).filter(Boolean);
        await sendSupabaseLightPush({
          title: "Nouveau signalement boutique",
          message: `Un utilisateur a signalé la boutique ${partnerId}`,
          targetUserIds,
          data: { type: "market_shop_report", partnerId },
          url: "/admin/reports",
        });
      }
    } catch {}

    return res.json({ id: inserted?.id || null, status: "open" });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/market/partners/:partnerId/orders", async (req, res) => {
  try {
    const { partnerId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const auth = await requirePartnerOwner({ req, partnerId });
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const statusFilter = String(req.query.status || "all").trim().toLowerCase();
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    let query = supabase
      .from("partner_orders")
      .select(
        "id, partner_id, customer_user_id, status, delivery_mode, customer_note, customer_country_code, base_currency, base_amount_total, charge_currency, charge_amount_total, platform_fee_amount, partner_amount, created_at, updated_at"
      )
      .eq("partner_id", partnerId)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (statusFilter && statusFilter !== "all") {
      if (statusFilter === "pending") {
        query = query.in("status", ["created", "payment_pending"]);
      } else if (statusFilter === "paid") {
        query = query.eq("status", "paid");
      } else if (statusFilter === "canceled" || statusFilter === "cancelled") {
        query = query.in("status", ["canceled", "cancelled"]);
      } else {
        query = query.eq("status", statusFilter);
      }
    }

    const { data: orders, error: oErr } = await query;
    if (oErr) return res.status(500).json({ error: oErr.message || "Erreur lecture commandes" });

    const safeOrders = Array.isArray(orders) ? orders : [];
    const orderIds = safeOrders.map((o) => o.id).filter(Boolean);

    let itemsByOrderId = {};
    if (orderIds.length > 0) {
      const { data: items, error: iErr } = await supabase
        .from("partner_order_items")
        .select("id, order_id, item_id, title_snapshot, unit_base_price_amount, quantity, total_base_amount")
        .in("order_id", orderIds)
        .order("created_at", { ascending: true });

      if (iErr) return res.status(500).json({ error: iErr.message || "Erreur lecture lignes commande" });

      itemsByOrderId = (items || []).reduce((acc, it) => {
        const oid = it?.order_id ? String(it.order_id) : null;
        if (!oid) return acc;
        if (!acc[oid]) acc[oid] = [];
        acc[oid].push(it);
        return acc;
      }, {});
    }

    const uniqueCustomerIds = Array.from(
      new Set(safeOrders.map((o) => (o?.customer_user_id ? String(o.customer_user_id) : null)).filter(Boolean))
    );

    const emailByUserId = {};
    if (uniqueCustomerIds.length > 0 && supabase?.auth?.admin?.getUserById) {
      await Promise.all(
        uniqueCustomerIds.map(async (uid) => {
          try {
            const { data: uData, error: uErr } = await supabase.auth.admin.getUserById(uid);
            if (uErr) return;
            const email = String(uData?.user?.email || "").trim();
            if (email) emailByUserId[uid] = email;
          } catch {
            // ignore
          }
        })
      );
    }

    const enriched = safeOrders.map((o) => {
      const oid = o?.id ? String(o.id) : null;
      const uid = o?.customer_user_id ? String(o.customer_user_id) : null;
      return {
        ...o,
        customer_email: uid ? emailByUserId[uid] || null : null,
        items: oid ? itemsByOrderId[oid] || [] : [],
      };
    });

    return res.json({ orders: enriched, limit, offset });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.put("/api/market/cart", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { partnerId, items } = req.body || {};
    const pid = partnerId ? String(partnerId).trim() : null;
    if (!pid) return res.status(400).json({ error: "partnerId requis" });
    if (!Array.isArray(items)) return res.status(400).json({ error: "items requis" });

    const normalizedItems = items
      .map((it) => ({
        itemId: it?.itemId ? String(it.itemId).trim() : null,
        quantity: Math.max(parseInt(it?.quantity, 10) || 1, 1),
      }))
      .filter((it) => it.itemId);

    const now = new Date().toISOString();

    const { data: existingCart, error: cReadErr } = await supabase
      .from("market_carts")
      .select("id")
      .eq("user_id", guard.userId)
      .eq("partner_id", pid)
      .eq("status", "active")
      .order("updated_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (cReadErr) return res.status(500).json({ error: cReadErr.message || "Erreur lecture panier" });

    let cartId = existingCart?.id ? String(existingCart.id) : null;
    if (!cartId) {
      const { data: inserted, error: cInsErr } = await supabase
        .from("market_carts")
        .insert({ user_id: guard.userId, partner_id: pid, status: "active", created_at: now, updated_at: now })
        .select("id")
        .maybeSingle();
      if (cInsErr) return res.status(500).json({ error: cInsErr.message || "Erreur création panier" });
      cartId = inserted?.id ? String(inserted.id) : null;
    } else {
      const { error: cUpErr } = await supabase
        .from("market_carts")
        .update({ updated_at: now })
        .eq("id", cartId);
      if (cUpErr) return res.status(500).json({ error: cUpErr.message || "Erreur mise à jour panier" });
    }

    if (!cartId) return res.status(500).json({ error: "cart_create_failed" });

    const { error: delErr } = await supabase.from("market_cart_items").delete().eq("cart_id", cartId);
    if (delErr) return res.status(500).json({ error: delErr.message || "Erreur reset items panier" });

    if (normalizedItems.length === 0) {
      return res.json({ success: true, cartId, items: [] });
    }

    const itemIds = normalizedItems.map((x) => x.itemId);
    const { data: dbItems, error: iErr } = await supabase
      .from("partner_items")
      .select("id, partner_id, title, base_price_amount")
      .eq("partner_id", pid)
      .in("id", itemIds);
    if (iErr) return res.status(500).json({ error: iErr.message || "Erreur lecture produits" });

    const byId = new Map((dbItems || []).map((x) => [String(x.id), x]));
    const rows = [];

    for (const it of normalizedItems) {
      const row = byId.get(String(it.itemId));
      if (!row) continue;
      const priceMinor = Number(row.base_price_amount || 0);
      rows.push({
        cart_id: cartId,
        item_id: row.id,
        title_snapshot: row.title || null,
        unit_price_minor: Number.isFinite(priceMinor) ? Math.round(priceMinor) : 0,
        quantity: it.quantity,
      });
    }

    if (rows.length === 0) {
      return res.json({ success: true, cartId, items: [] });
    }

    const { error: insErr } = await supabase.from("market_cart_items").insert(rows);
    if (insErr) return res.status(500).json({ error: insErr.message || "Erreur ajout items panier" });

    return res.json({ success: true, cartId, itemsCount: rows.length });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/market/partners/:partnerId/abandoned-carts", async (req, res) => {
  try {
    const { partnerId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const auth = await requirePartnerOwner({ req, partnerId });
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const minutes = Math.min(Math.max(parseInt(req.query.minutes, 10) || 60, 5), 4320);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    const cutoff = new Date(Date.now() - minutes * 60 * 1000).toISOString();

    const { data: carts, error: cErr } = await supabase
      .from("market_carts")
      .select("id, user_id, partner_id, status, created_at, updated_at")
      .eq("partner_id", partnerId)
      .eq("status", "active")
      .lt("updated_at", cutoff)
      .order("updated_at", { ascending: false })
      .range(offset, offset + limit - 1);
    if (cErr) return res.status(500).json({ error: cErr.message || "Erreur lecture paniers" });

    const safeCarts = Array.isArray(carts) ? carts : [];
    const cartIds = safeCarts.map((c) => c.id).filter(Boolean);

    let itemsByCartId = {};
    if (cartIds.length > 0) {
      const { data: items, error: iErr } = await supabase
        .from("market_cart_items")
        .select("id, cart_id, item_id, title_snapshot, unit_price_minor, quantity")
        .in("cart_id", cartIds)
        .order("created_at", { ascending: true });
      if (iErr) return res.status(500).json({ error: iErr.message || "Erreur lecture items panier" });

      itemsByCartId = (items || []).reduce((acc, it) => {
        const cid = it?.cart_id ? String(it.cart_id) : null;
        if (!cid) return acc;
        if (!acc[cid]) acc[cid] = [];
        acc[cid].push(it);
        return acc;
      }, {});
    }

    const uniqueUserIds = Array.from(new Set(safeCarts.map((c) => (c?.user_id ? String(c.user_id) : null)).filter(Boolean)));
    const emailByUserId = {};
    if (uniqueUserIds.length > 0 && supabase?.auth?.admin?.getUserById) {
      await Promise.all(
        uniqueUserIds.map(async (uid) => {
          try {
            const { data: uData, error: uErr } = await supabase.auth.admin.getUserById(uid);
            if (uErr) return;
            const email = String(uData?.user?.email || "").trim();
            if (email) emailByUserId[uid] = email;
          } catch {
            // ignore
          }
        })
      );
    }

    const enriched = safeCarts.map((c) => {
      const cid = c?.id ? String(c.id) : null;
      const uid = c?.user_id ? String(c.user_id) : null;
      const its = cid ? itemsByCartId[cid] || [] : [];
      const totalMinor = its.reduce(
        (sum, it) => sum + Number(it?.unit_price_minor || 0) * Math.max(parseInt(it?.quantity, 10) || 1, 1),
        0
      );
      return {
        ...c,
        customer_email: uid ? emailByUserId[uid] || null : null,
        items: its,
        total_minor: totalMinor,
        currency: "EUR",
      };
    });

    return res.json({ carts: enriched, cutoff, minutes, limit, offset });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/api/market/partners", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireVipOrAdminUser({ req });
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const {
      display_name,
      description,
      category,
      logo_url,
      phone,
      whatsapp,
      address,
      hours,
    } = req.body || {};

    const name = String(display_name || "").trim();
    const desc = String(description || "").trim();
    const cat = String(category || "").trim();
    const logo = String(logo_url || "").trim();

    if (!name) return res.status(400).json({ error: "display_name requis" });
    if (!desc) return res.status(400).json({ error: "description requise" });
    if (!cat) return res.status(400).json({ error: "category requise" });
    if (!logo) return res.status(400).json({ error: "logo_url requis" });

    const { data: existing, error: exErr } = await supabase
      .from("partners_market")
      .select("id")
      .eq("owner_user_id", guard.userId)
      .maybeSingle();
    if (exErr) return res.status(500).json({ error: exErr.message || "Erreur lecture boutique" });
    if (existing?.id) return res.status(409).json({ error: "partner_already_exists" });

    const profileCountryCode = String(guard.profile?.country_code || "").trim().toUpperCase() || "FR";
    const baseCurrency = countryToCurrency(profileCountryCode);

    const now = new Date().toISOString();
    const { data: inserted, error } = await supabase
      .from("partners_market")
      .insert({
        owner_user_id: guard.userId,
        display_name: name,
        description: desc,
        category: cat,
        country_code: profileCountryCode,
        base_currency: baseCurrency,
        status: "pending",
        payout_status: "incomplete",
        is_open: false,
        logo_url: logo,
        phone: phone ? String(phone).trim() : null,
        whatsapp: whatsapp ? String(whatsapp).trim() : null,
        address: address ? String(address).trim() : null,
        hours: hours ? String(hours).trim() : null,
        created_at: now,
        updated_at: now,
      })
      .select("id")
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message || "Erreur création boutique" });
    if (!inserted?.id) return res.status(500).json({ error: "partner_create_failed" });
    return res.json({ success: true, partnerId: inserted.id });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.patch("/api/market/partners/:partnerId", bodyParser.json(), async (req, res) => {
  try {
    const { partnerId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const auth = await requirePartnerOwner({ req, partnerId });
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const patch = req.body || {};
    const update = {
      updated_at: new Date().toISOString(),
    };

    if (patch.display_name !== undefined) update.display_name = String(patch.display_name || "").trim();
    if (patch.description !== undefined) update.description = String(patch.description || "").trim();
    if (patch.category !== undefined) update.category = String(patch.category || "").trim();
    if (patch.logo_url !== undefined) update.logo_url = String(patch.logo_url || "").trim();
    if (patch.phone !== undefined) update.phone = patch.phone ? String(patch.phone).trim() : null;
    if (patch.whatsapp !== undefined) update.whatsapp = patch.whatsapp ? String(patch.whatsapp).trim() : null;
    if (patch.address !== undefined) update.address = patch.address ? String(patch.address).trim() : null;
    if (patch.hours !== undefined) update.hours = patch.hours ? String(patch.hours).trim() : null;

    if ("display_name" in update && !update.display_name) {
      return res.status(400).json({ error: "display_name requis" });
    }
    if ("description" in update && !update.description) {
      return res.status(400).json({ error: "description requise" });
    }
    if ("category" in update && !update.category) {
      return res.status(400).json({ error: "category requise" });
    }
    if ("logo_url" in update && !update.logo_url) {
      return res.status(400).json({ error: "logo_url requis" });
    }

    const { error } = await supabase.from("partners_market").update(update).eq("id", partnerId);
    if (error) return res.status(500).json({ error: error.message || "Erreur mise à jour boutique" });
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.patch("/api/admin/partenaires/:partnerId", bodyParser.json(), async (req, res) => {
  try {
    const { partnerId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const patch = req.body || {};
    const update = {
      updated_at: new Date().toISOString(),
    };

    const allowed = [
      "name",
      "category_id",
      "address",
      "phone",
      "website",
      "email",
      "description",
      "recommandation",
      "latitude",
      "longitude",
      "media_url",
      "media_type",
    ];

    allowed.forEach((k) => {
      if (patch[k] !== undefined) update[k] = patch[k];
    });

    if (Object.keys(update).length === 1) {
      return res.status(400).json({ error: "nothing_to_update" });
    }

    const { error } = await supabase.from("partenaires").update(update).eq("id", partnerId);
    if (error) return res.status(500).json({ error: error.message || "Erreur mise à jour partenaire" });
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.delete("/api/admin/partenaires/:partnerId", async (req, res) => {
  try {
    const { partnerId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    await supabase.from("favoris").delete().eq("type_contenu", "partenaire").eq("content_id", partnerId);

    const { error } = await supabase.from("partenaires").delete().eq("id", partnerId);
    if (error) return res.status(500).json({ error: error.message || "Erreur suppression partenaire" });
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.patch("/api/admin/faits-divers/:articleId", bodyParser.json(), async (req, res) => {
  try {
    const { articleId } = req.params;
    if (!articleId) return res.status(400).json({ error: "articleId requis" });

    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const patch = req.body || {};
    const update = {
      updated_at: new Date().toISOString(),
    };

    const allowed = ["title", "category_id", "excerpt", "full_content", "image_url"];
    allowed.forEach((k) => {
      if (patch[k] !== undefined) update[k] = patch[k];
    });

    if (Object.keys(update).length === 1) {
      return res.status(400).json({ error: "nothing_to_update" });
    }

    const { error } = await supabase.from("faits_divers").update(update).eq("id", articleId);
    if (error) return res.status(500).json({ error: error.message || "Erreur mise à jour fait divers" });
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.delete("/api/admin/faits-divers/:articleId", async (req, res) => {
  try {
    const { articleId } = req.params;
    if (!articleId) return res.status(400).json({ error: "articleId requis" });

    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    await supabase.from("faits_divers_comments").delete().eq("fait_divers_id", articleId);
    await supabase.from("faits_divers_likes").delete().eq("fait_divers_id", articleId);
    await supabase.from("favoris").delete().eq("type_contenu", "fait_divers").eq("content_id", articleId);

    const { error } = await supabase.from("faits_divers").delete().eq("id", articleId);
    if (error) return res.status(500).json({ error: error.message || "Erreur suppression fait divers" });
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/market/partners/:partnerId/items", async (req, res) => {
  try {
    const { partnerId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const { data: items, error } = await supabase
      .from("partner_items")
      .select("id, partner_id, type, title, description, base_price_amount, is_available, is_published, media")
      .eq("partner_id", partnerId)
      .eq("is_published", true)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message || "Erreur lecture items" });
    return res.json({ items: items || [] });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/market/partners/:partnerId/items/manage", async (req, res) => {
  try {
    const { partnerId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const auth = await requirePartnerOwner({ req, partnerId });
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const { data: items, error } = await supabase
      .from("partner_items")
      .select("id, partner_id, type, title, description, base_price_amount, is_available, is_published, media, created_at, updated_at")
      .eq("partner_id", partnerId)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message || "Erreur lecture items" });
    return res.json({ items: items || [] });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/api/market/partners/:partnerId/items", bodyParser.json(), async (req, res) => {
  try {
    const { partnerId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const auth = await requirePartnerOwner({ req, partnerId });
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const payload = req.body || {};
    const title = String(payload.title || "").trim();
    const description = payload.description ? String(payload.description).trim() : null;
    const type = payload.type ? String(payload.type).trim() : "product";

    const basePriceAmount = Number(payload.base_price_amount);
    if (!title) return res.status(400).json({ error: "title requis" });
    if (!Number.isFinite(basePriceAmount) || basePriceAmount < 0) {
      return res.status(400).json({ error: "base_price_amount invalide" });
    }

    const isAvailable = payload.is_available === false ? false : true;
    const isPublished = payload.is_published === true;
    const media = payload.media && typeof payload.media === "object" ? payload.media : null;

    const now = new Date().toISOString();
    const { data, error } = await supabase
      .from("partner_items")
      .insert({
        partner_id: partnerId,
        type,
        title,
        description,
        base_price_amount: Math.round(basePriceAmount),
        is_available: isAvailable,
        is_published: isPublished,
        media,
        created_at: now,
        updated_at: now,
      })
      .select("id")
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message || "Erreur création item" });
    if (!data?.id) return res.status(500).json({ error: "item_create_failed" });
    return res.json({ success: true, itemId: data.id });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.patch("/api/market/partners/:partnerId/items/:itemId", bodyParser.json(), async (req, res) => {
  try {
    const { partnerId, itemId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });
    if (!itemId) return res.status(400).json({ error: "itemId requis" });

    const auth = await requirePartnerOwner({ req, partnerId });
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const patch = req.body || {};
    const update = { updated_at: new Date().toISOString() };

    if (patch.title !== undefined) update.title = String(patch.title || "").trim();
    if (patch.description !== undefined) update.description = patch.description ? String(patch.description).trim() : null;
    if (patch.type !== undefined) update.type = patch.type ? String(patch.type).trim() : "product";
    if (patch.base_price_amount !== undefined) {
      const v = Number(patch.base_price_amount);
      if (!Number.isFinite(v) || v < 0) return res.status(400).json({ error: "base_price_amount invalide" });
      update.base_price_amount = Math.round(v);
    }
    if (patch.is_available !== undefined) update.is_available = patch.is_available === true;
    if (patch.is_published !== undefined) update.is_published = patch.is_published === true;
    if (patch.media !== undefined) update.media = patch.media && typeof patch.media === "object" ? patch.media : null;

    if ("title" in update && !update.title) return res.status(400).json({ error: "title requis" });

    const { data: existing, error: readErr } = await supabase
      .from("partner_items")
      .select("id, partner_id")
      .eq("id", itemId)
      .maybeSingle();
    if (readErr) return res.status(500).json({ error: readErr.message || "Erreur lecture item" });
    if (!existing) return res.status(404).json({ error: "item_not_found" });
    if (String(existing.partner_id) !== String(partnerId)) return res.status(403).json({ error: "forbidden" });

    const { error } = await supabase.from("partner_items").update(update).eq("id", itemId);
    if (error) return res.status(500).json({ error: error.message || "Erreur mise à jour item" });
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.delete("/api/market/partners/:partnerId/items/:itemId", async (req, res) => {
  try {
    const { partnerId, itemId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });
    if (!itemId) return res.status(400).json({ error: "itemId requis" });

    const auth = await requirePartnerOwner({ req, partnerId });
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const { data: existing, error: readErr } = await supabase
      .from("partner_items")
      .select("id, partner_id")
      .eq("id", itemId)
      .maybeSingle();
    if (readErr) return res.status(500).json({ error: readErr.message || "Erreur lecture item" });
    if (!existing) return res.status(404).json({ error: "item_not_found" });
    if (String(existing.partner_id) !== String(partnerId)) return res.status(403).json({ error: "forbidden" });

    const { error } = await supabase.from("partner_items").delete().eq("id", itemId);
    if (error) return res.status(500).json({ error: error.message || "Erreur suppression item" });
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/api/market/orders", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { partnerId, items, delivery_mode, customer_note } = req.body || {};
    if (!partnerId || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "partnerId et items requis" });
    }

    const { data: partner, error: pErr } = await supabase
      .from("partners_market")
      .select("id, status, payout_status, is_open, base_currency")
      .eq("id", partnerId)
      .maybeSingle();
    if (pErr) return res.status(500).json({ error: pErr.message || "Erreur lecture partenaire" });
    if (!partner) return res.status(404).json({ error: "partner_not_found" });

    const baseCurrency = String(partner.base_currency || "").trim().toUpperCase();
    if (!baseCurrency) return res.status(400).json({ error: "partner_base_currency_missing" });

    const { data: prof, error: profErr } = await supabase
      .from("profiles")
      .select("country_code")
      .eq("id", guard.userId)
      .maybeSingle();
    if (profErr) return res.status(500).json({ error: profErr.message || "Erreur lecture profil" });

    const customerCountryCode = String(prof?.country_code || "").trim().toUpperCase() || null;
    const chargeCurrency = countryToCurrency(customerCountryCode);

    const itemIds = items
      .map((it) => String(it?.itemId || "").trim())
      .filter(Boolean);
    if (itemIds.length === 0) return res.status(400).json({ error: "items_invalid" });

    const { data: dbItems, error: iErr } = await supabase
      .from("partner_items")
      .select("id, partner_id, title, base_price_amount, is_available, is_published")
      .eq("partner_id", partnerId)
      .in("id", itemIds);
    if (iErr) return res.status(500).json({ error: iErr.message || "Erreur lecture items" });

    const byId = new Map((dbItems || []).map((x) => [x.id, x]));
    const orderLines = [];
    let baseTotal = 0;

    for (const it of items) {
      const id = String(it?.itemId || "").trim();
      const qty = Math.max(parseInt(it?.quantity, 10) || 1, 1);
      const row = byId.get(id);
      if (!row) return res.status(400).json({ error: `item_not_found:${id}` });
      if (!row.is_published) return res.status(400).json({ error: `item_not_published:${id}` });
      if (!row.is_available) return res.status(400).json({ error: `item_unavailable:${id}` });
      const unit = Number(row.base_price_amount);
      if (!Number.isFinite(unit) || unit < 0) return res.status(400).json({ error: `item_price_invalid:${id}` });
      const lineTotal = unit * qty;
      baseTotal += lineTotal;
      orderLines.push({
        item_id: row.id,
        title_snapshot: row.title,
        unit_base_price_amount: unit,
        quantity: qty,
        total_base_amount: lineTotal,
      });
    }

    const { amount: chargeTotal, rate } = await fxService.convertMinorAmount({
      amount: baseTotal,
      fromCurrency: baseCurrency,
      toCurrency: chargeCurrency,
    });

    const fee = await getActiveFeeSettings(chargeCurrency);
    if (!fee) return res.status(400).json({ error: "fee_settings_missing" });

    const percentFee = Math.round((chargeTotal * Number(fee.percent_bps || 0)) / 10000);
    const fixedFee = Number(fee.fixed_fee_amount || 0);
    const platformFee = Math.max(percentFee + fixedFee, 0);
    const partnerAmount = Math.max(chargeTotal - platformFee, 0);

    const { data: inserted, error: oErr } = await supabase
      .from("partner_orders")
      .insert({
        partner_id: partnerId,
        customer_user_id: guard.userId,
        status: "created",
        delivery_mode: delivery_mode === "partner_delivery" ? "partner_delivery" : "pickup",
        customer_note: customer_note ? String(customer_note) : null,
        customer_country_code: customerCountryCode,
        base_currency: baseCurrency,
        base_amount_total: baseTotal,
        charge_currency: chargeCurrency,
        charge_amount_total: chargeTotal,
        fx_rate_used: rate,
        fx_provider: "frankfurter",
        fx_timestamp: new Date().toISOString(),
        platform_fee_amount: platformFee,
        partner_amount: partnerAmount,
      })
      .select("id")
      .maybeSingle();
    if (oErr) return res.status(500).json({ error: oErr.message || "Erreur création commande" });

    const orderId = inserted?.id;
    if (!orderId) return res.status(500).json({ error: "order_create_failed" });

    const linesPayload = orderLines.map((l) => ({ ...l, order_id: orderId }));
    const { error: liErr } = await supabase.from("partner_order_items").insert(linesPayload);
    if (liErr) return res.status(500).json({ error: liErr.message || "Erreur création lignes" });

    return res.json({ success: true, orderId });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/api/market/orders/:orderId/checkout", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { orderId } = req.params;
    if (!orderId) return res.status(400).json({ error: "orderId requis" });

    const { data: order, error: oErr } = await supabase
      .from("partner_orders")
      .select("id, partner_id, customer_user_id, status, charge_currency, charge_amount_total, platform_fee_amount")
      .eq("id", orderId)
      .maybeSingle();
    if (oErr) return res.status(500).json({ error: oErr.message || "Erreur lecture commande" });
    if (!order) return res.status(404).json({ error: "order_not_found" });
    if (order.customer_user_id !== guard.userId) return res.status(403).json({ error: "forbidden" });
    if (!['created', 'payment_pending'].includes(String(order.status || ''))) {
      return res.status(400).json({ error: "order_status_invalid" });
    }

    const { data: partner, error: pErr } = await supabase
      .from("partners_market")
      .select("id, status, payout_status, is_open, stripe_connect_account_id")
      .eq("id", order.partner_id)
      .maybeSingle();
    if (pErr) return res.status(500).json({ error: pErr.message || "Erreur lecture partenaire" });
    if (!partner) return res.status(404).json({ error: "partner_not_found" });

    const isApproved = String(partner.status || "").toLowerCase() === "approved";
    const payoutComplete = String(partner.payout_status || "").toLowerCase() === "complete";
    const isOpen = partner.is_open === true;
    if (!(isApproved && payoutComplete && isOpen)) {
      return res.status(400).json({ error: "partner_not_commandable" });
    }

    const currency = String(order.charge_currency || "").toLowerCase();
    const unitAmount = Number(order.charge_amount_total);
    if (!currency || !Number.isFinite(unitAmount) || unitAmount <= 0) {
      return res.status(400).json({ error: "order_amount_invalid" });
    }

    const destinationAccount = partner?.stripe_connect_account_id
      ? String(partner.stripe_connect_account_id)
      : null;
    if (!destinationAccount) {
      return res.status(400).json({ error: "partner_connect_account_missing" });
    }

    const applicationFeeAmount = Number(order.platform_fee_amount);
    if (!Number.isFinite(applicationFeeAmount) || applicationFeeAmount < 0) {
      return res.status(400).json({ error: "order_fee_invalid" });
    }
    if (applicationFeeAmount > unitAmount) {
      return res.status(400).json({ error: "order_fee_too_high" });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      payment_intent_data: {
        application_fee_amount: applicationFeeAmount,
        transfer_data: { destination: destinationAccount },
      },
      line_items: [
        {
          price_data: {
            currency,
            product_data: { name: "Commande Partenaire — OneKamer" },
            unit_amount: unitAmount,
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: `https://onekamer-front-lab.onrender.com/paiement-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `https://onekamer-front-lab.onrender.com/paiement-annule`,
      metadata: { market_order_id: orderId, partner_id: order.partner_id, customer_user_id: guard.userId },
    });

    await supabase.from("partner_order_payments").insert({
      order_id: orderId,
      provider: "stripe",
      stripe_checkout_session_id: session.id,
      status: "created",
    });

    await supabase
      .from("partner_orders")
      .update({ status: "payment_pending" })
      .eq("id", orderId);

    return res.json({ url: session.url });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/api/market/orders/sync-payment", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { sessionId } = req.body || {};
    const sid = sessionId ? String(sessionId).trim() : "";
    if (!sid) return res.status(400).json({ error: "sessionId requis" });

    const { data: paymentRow, error: payErr } = await supabase
      .from("partner_order_payments")
      .select("order_id, stripe_checkout_session_id, status")
      .eq("stripe_checkout_session_id", sid)
      .maybeSingle();
    if (payErr) return res.status(500).json({ error: payErr.message || "Erreur lecture payment" });
    if (!paymentRow?.order_id) return res.status(404).json({ error: "payment_not_found" });

    const orderId = String(paymentRow.order_id);

    const { data: order, error: oErr } = await supabase
      .from("partner_orders")
      .select("id, customer_user_id, status")
      .eq("id", orderId)
      .maybeSingle();
    if (oErr) return res.status(500).json({ error: oErr.message || "Erreur lecture commande" });
    if (!order) return res.status(404).json({ error: "order_not_found" });
    if (order.customer_user_id !== guard.userId) return res.status(403).json({ error: "forbidden" });

    const session = await stripe.checkout.sessions.retrieve(sid, {
      expand: ["payment_intent"],
    });

    const marketOrderId = session?.metadata?.market_order_id ? String(session.metadata.market_order_id) : null;
    if (marketOrderId && marketOrderId !== orderId) {
      return res.status(400).json({ error: "order_session_mismatch" });
    }

    const paymentStatus = String(session?.payment_status || "").toLowerCase();
    const isPaid = paymentStatus === "paid";
    if (!isPaid) {
      return res.status(400).json({
        error: "payment_not_paid",
        payment_status: session?.payment_status || null,
      });
    }

    const paymentIntentId = session?.payment_intent
      ? typeof session.payment_intent === "string"
        ? session.payment_intent
        : session.payment_intent?.id || null
      : null;

    await supabase
      .from("partner_orders")
      .update({
        status: "paid",
        updated_at: new Date().toISOString(),
      })
      .eq("id", orderId);

    await supabase
      .from("partner_order_payments")
      .update({
        status: "succeeded",
        stripe_payment_intent_id: paymentIntentId,
        updated_at: new Date().toISOString(),
      })
      .eq("stripe_checkout_session_id", sid);

    try {
      const { data: conv } = await supabase
        .from("marketplace_order_conversations")
        .select("id")
        .eq("order_id", orderId)
        .maybeSingle();
      if (!conv) {
        const { data: ordRow } = await supabase
          .from("partner_orders")
          .select("id, partner_id, customer_user_id")
          .eq("id", orderId)
          .maybeSingle();
        const { data: partnerRow } = await supabase
          .from("partners_market")
          .select("id, owner_user_id")
          .eq("id", ordRow?.partner_id)
          .maybeSingle();
        if (ordRow?.id && partnerRow?.owner_user_id) {
          await supabase.from("marketplace_order_conversations").insert({
            order_id: orderId,
            buyer_id: ordRow.customer_user_id,
            seller_id: partnerRow.owner_user_id,
            created_at: new Date().toISOString(),
          });
        }
      }
    } catch {}

    await logEvent({
      category: "marketplace",
      action: "checkout.sync",
      status: "success",
      userId: guard.userId,
      context: {
        market_order_id: orderId,
        stripe_checkout_session_id: sid,
        stripe_payment_intent_id: paymentIntentId,
      },
    });

    return res.json({
      ok: true,
      orderId,
      payment_status: session?.payment_status || null,
      stripe_payment_intent_id: paymentIntentId,
    });
  } catch (e) {
    await logEvent({
      category: "marketplace",
      action: "checkout.sync",
      status: "error",
      context: { error: e?.message || String(e) },
    });
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/market/orders", async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const statusFilter = String(req.query.status || "all").trim().toLowerCase();
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    let query = supabase
      .from("partner_orders")
      .select(
        "id, partner_id, customer_user_id, status, delivery_mode, base_currency, base_amount_total, charge_currency, charge_amount_total, created_at, updated_at"
      )
      .eq("customer_user_id", guard.userId)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (statusFilter && statusFilter !== "all") {
      if (statusFilter === "pending") {
        query = query.in("status", ["created", "payment_pending"]);
      } else if (statusFilter === "paid") {
        query = query.eq("status", "paid");
      } else if (statusFilter === "canceled" || statusFilter === "cancelled") {
        query = query.in("status", ["canceled", "cancelled"]);
      } else {
        query = query.eq("status", statusFilter);
      }
    }

    const { data: orders, error: oErr } = await query;
    if (oErr) return res.status(500).json({ error: oErr.message || "Erreur lecture commandes" });

    const safeOrders = Array.isArray(orders) ? orders : [];
    const orderIds = safeOrders.map((o) => o.id).filter(Boolean);

    let itemsByOrderId = {};
    if (orderIds.length > 0) {
      const { data: items, error: iErr } = await supabase
        .from("partner_order_items")
        .select("id, order_id, item_id, title_snapshot, unit_base_price_amount, quantity, total_base_amount")
        .in("order_id", orderIds)
        .order("created_at", { ascending: true });

      if (iErr) return res.status(500).json({ error: iErr.message || "Erreur lecture lignes commande" });

      itemsByOrderId = (items || []).reduce((acc, it) => {
        const oid = it?.order_id ? String(it.order_id) : null;
        if (!oid) return acc;
        if (!acc[oid]) acc[oid] = [];
        acc[oid].push(it);
        return acc;
      }, {});
    }

    const enriched = safeOrders.map((o) => {
      const oid = o?.id ? String(o.id) : null;
      return {
        ...o,
        items: oid ? itemsByOrderId[oid] || [] : [],
      };
    });

    return res.json({ orders: enriched, limit, offset });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/market/orders/:orderId", async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { orderId } = req.params;
    if (!orderId) return res.status(400).json({ error: "orderId requis" });

    const { data: order, error: oErr } = await supabase
      .from("partner_orders")
      .select(
        "id, partner_id, customer_user_id, status, delivery_mode, customer_note, fulfillment_status, fulfillment_updated_at, buyer_received_at, base_currency, base_amount_total, charge_currency, charge_amount_total, platform_fee_amount, partner_amount, created_at, updated_at"
      )
      .eq("id", orderId)
      .maybeSingle();
    if (oErr) return res.status(500).json({ error: oErr.message || "Erreur lecture commande" });
    if (!order) return res.status(404).json({ error: "order_not_found" });

    const { data: partner, error: pErr } = await supabase
      .from("partners_market")
      .select("id, owner_user_id, display_name")
      .eq("id", order.partner_id)
      .maybeSingle();
    if (pErr) return res.status(500).json({ error: pErr.message || "Erreur lecture partenaire" });

    const sellerId = partner?.owner_user_id ? String(partner.owner_user_id) : null;
    const isBuyer = String(order.customer_user_id) === String(guard.userId);
    const isSeller = sellerId && sellerId === String(guard.userId);
    if (!(isBuyer || isSeller)) return res.status(403).json({ error: "forbidden" });

    let customerEmail = null;
    if (isSeller && order?.customer_user_id && supabase?.auth?.admin?.getUserById) {
      try {
        const { data: uData, error: uErr } = await supabase.auth.admin.getUserById(String(order.customer_user_id));
        if (!uErr) customerEmail = (uData?.user?.email || "").trim() || null;
      } catch {}
    }

    const { data: items, error: iErr } = await supabase
      .from("partner_order_items")
      .select("id, order_id, item_id, title_snapshot, unit_base_price_amount, quantity, total_base_amount")
      .eq("order_id", orderId)
      .order("created_at", { ascending: true });
    if (iErr) return res.status(500).json({ error: iErr.message || "Erreur lecture lignes commande" });

    const { data: conv } = await supabase
      .from("marketplace_order_conversations")
      .select("id")
      .eq("order_id", orderId)
      .maybeSingle();

    return res.json({
      order: { ...order, partner_display_name: partner?.display_name || null },
      items: Array.isArray(items) ? items : [],
      conversationId: conv?.id || null,
      role: isBuyer ? "buyer" : "seller",
      customer_email: customerEmail,
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// Mettre à jour le statut d'exécution (vendeur)
app.patch("/api/market/orders/:orderId/fulfillment", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { orderId } = req.params;
    const { status } = req.body || {};
    if (!orderId) return res.status(400).json({ error: "orderId requis" });

    const next = String(status || "").toLowerCase();
    const allowed = ["preparing", "shipping", "delivered"];
    if (!allowed.includes(next)) return res.status(400).json({ error: "invalid_status" });

    const { data: order, error: oErr } = await supabase
      .from("partner_orders")
      .select("id, partner_id, customer_user_id, fulfillment_status, fulfillment_updated_at")
      .eq("id", orderId)
      .maybeSingle();
    if (oErr) return res.status(500).json({ error: oErr.message || "Erreur lecture commande" });
    if (!order) return res.status(404).json({ error: "order_not_found" });

    const { data: partner, error: pErr } = await supabase
      .from("partners_market")
      .select("id, owner_user_id")
      .eq("id", order.partner_id)
      .maybeSingle();
    if (pErr) return res.status(500).json({ error: pErr.message || "Erreur lecture partenaire" });
    if (!partner || String(partner.owner_user_id) !== String(guard.userId)) return res.status(403).json({ error: "forbidden" });

    const { data: upd, error: uErr } = await supabase
      .from("partner_orders")
      .update({ fulfillment_status: next, updated_at: new Date().toISOString() })
      .eq("id", orderId)
      .select("id, fulfillment_status, fulfillment_updated_at")
      .maybeSingle();
    if (uErr) return res.status(500).json({ error: uErr.message || "Erreur mise à jour" });

    try {
      await sendSupabaseLightPush({
        title: "Mise à jour commande",
        message: `Statut: ${next}`,
        targetUserIds: [String(order.customer_user_id)],
        data: { type: "market_order_fulfillment_update", orderId },
        url: `/market/orders/${orderId}`,
      });
    } catch {}

    return res.json({ order: upd });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// Confirmation de réception (acheteur)
app.post("/api/market/orders/:orderId/confirm-received", async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { orderId } = req.params;
    if (!orderId) return res.status(400).json({ error: "orderId requis" });

    const { data: order, error: oErr } = await supabase
      .from("partner_orders")
      .select("id, partner_id, customer_user_id, fulfillment_status, buyer_received_at")
      .eq("id", orderId)
      .maybeSingle();
    if (oErr) return res.status(500).json({ error: oErr.message || "Erreur lecture commande" });
    if (!order) return res.status(404).json({ error: "order_not_found" });
    if (String(order.customer_user_id) !== String(guard.userId)) return res.status(403).json({ error: "forbidden" });

    const f = String(order.fulfillment_status || "").toLowerCase();
    if (f !== "delivered") return res.status(400).json({ error: "not_delivered" });

    if (!order.buyer_received_at) {
      const { error: uErr } = await supabase
        .from("partner_orders")
        .update({ buyer_received_at: new Date().toISOString(), updated_at: new Date().toISOString() })
        .eq("id", orderId);
      if (uErr) return res.status(500).json({ error: uErr.message || "Erreur mise à jour" });
    }

    let sellerId = null;
    try {
      const { data: partner } = await supabase
        .from("partners_market")
        .select("id, owner_user_id")
        .eq("id", order.partner_id)
        .maybeSingle();
      sellerId = partner?.owner_user_id ? String(partner.owner_user_id) : null;
    } catch {}

    if (sellerId) {
      try {
        await sendSupabaseLightPush({
          title: "Commande reçue",
          message: "L'acheteur a confirmé la réception.",
          targetUserIds: [sellerId],
          data: { type: "market_order_received_confirmed", orderId },
          url: `/market/orders/${orderId}`,
        });
      } catch {}
    }

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/market/orders/:orderId/messages", async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { orderId } = req.params;
    if (!orderId) return res.status(400).json({ error: "orderId requis" });

    const { data: order, error: oErr } = await supabase
      .from("partner_orders")
      .select("id, partner_id, customer_user_id, status")
      .eq("id", orderId)
      .maybeSingle();
    if (oErr) return res.status(500).json({ error: oErr.message || "Erreur lecture commande" });
    if (!order) return res.status(404).json({ error: "order_not_found" });

    const { data: partner, error: pErr } = await supabase
      .from("partners_market")
      .select("id, owner_user_id")
      .eq("id", order.partner_id)
      .maybeSingle();
    if (pErr) return res.status(500).json({ error: pErr.message || "Erreur lecture partenaire" });

    const sellerId = partner?.owner_user_id ? String(partner.owner_user_id) : null;
    const isBuyer = String(order.customer_user_id) === String(guard.userId);
    const isSeller = sellerId && sellerId === String(guard.userId);
    if (!(isBuyer || isSeller)) return res.status(403).json({ error: "forbidden" });

    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    const { data: conv } = await supabase
      .from("marketplace_order_conversations")
      .select("id")
      .eq("order_id", orderId)
      .maybeSingle();

    if (!conv?.id) {
      return res.json({ messages: [], limit, offset, conversationId: null });
    }

    const { data: messages, error: mErr } = await supabase
      .from("marketplace_order_messages")
      .select("id, conversation_id, sender_id:author_id, content:body, created_at")
      .eq("conversation_id", conv.id)
      .order("created_at", { ascending: true })
      .range(offset, offset + limit - 1);
    if (mErr) return res.status(500).json({ error: mErr.message || "Erreur lecture messages" });

    return res.json({ messages: Array.isArray(messages) ? messages : [], limit, offset, conversationId: conv.id });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/api/market/orders/:orderId/messages", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { orderId } = req.params;
    const { content } = req.body || {};
    if (!orderId) return res.status(400).json({ error: "orderId requis" });
    const text = typeof content === "string" ? content.trim() : "";
    if (!text) return res.status(400).json({ error: "content requis" });

    const { data: order, error: oErr } = await supabase
      .from("partner_orders")
      .select("id, partner_id, customer_user_id, status")
      .eq("id", orderId)
      .maybeSingle();
    if (oErr) return res.status(500).json({ error: oErr.message || "Erreur lecture commande" });
    if (!order) return res.status(404).json({ error: "order_not_found" });

    const statusNorm = String(order.status || "").toLowerCase();
    if (["created", "payment_pending", "canceled", "cancelled"].includes(statusNorm)) {
      return res.status(400).json({ error: "order_not_paid" });
    }

    const { data: partner, error: pErr } = await supabase
      .from("partners_market")
      .select("id, owner_user_id")
      .eq("id", order.partner_id)
      .maybeSingle();
    if (pErr) return res.status(500).json({ error: pErr.message || "Erreur lecture partenaire" });

    const sellerId = partner?.owner_user_id ? String(partner.owner_user_id) : null;
    const isBuyer = String(order.customer_user_id) === String(guard.userId);
    const isSeller = sellerId && sellerId === String(guard.userId);
    if (!(isBuyer || isSeller)) return res.status(403).json({ error: "forbidden" });

    let convId = null;
    try {
      const { data: conv } = await supabase
        .from("marketplace_order_conversations")
        .select("id")
        .eq("order_id", orderId)
        .maybeSingle();
      if (conv?.id) {
        convId = conv.id;
      } else {
        const { data: inserted, error: insConvErr } = await supabase
          .from("marketplace_order_conversations")
          .insert({
            order_id: orderId,
            buyer_id: order.customer_user_id,
            seller_id: partner.owner_user_id,
            created_at: new Date().toISOString(),
          })
          .select("id")
          .maybeSingle();
        if (insConvErr) return res.status(500).json({ error: insConvErr.message || "Erreur création conversation" });
        convId = inserted?.id || null;
      }
    } catch (e) {
      return res.status(500).json({ error: e?.message || "Erreur conversation" });
    }

    if (!convId) return res.status(500).json({ error: "conversation_unavailable" });

    const safeText = text.slice(0, 2000);
    const { data: msg, error: mErr } = await supabase
      .from("marketplace_order_messages")
      .insert({
        conversation_id: convId,
        author_id: guard.userId,
        body: safeText,
        created_at: new Date().toISOString(),
      })
      .select("id")
      .maybeSingle();
    if (mErr) return res.status(500).json({ error: mErr.message || "Erreur envoi message" });

    try {
      const recipientId = isBuyer ? sellerId : String(order.customer_user_id);
      if (recipientId) {
        await sendSupabaseLightPush({
          title: "Nouveau message commande",
          message: safeText,
          targetUserIds: [recipientId],
          data: { type: "market_order_message", orderId },
          url: `/market/orders/${orderId}`,
        });
      }
    } catch {}

    return res.json({ success: true, messageId: msg?.id || null, conversationId: convId });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/api/partner/connect/onboarding-link", bodyParser.json(), async (req, res) => {
  try {
    const { partnerId } = req.body || {};
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const auth = await requirePartnerOwner({ req, partnerId });
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    let accountId = auth.partner?.stripe_connect_account_id || null;
    if (!accountId) {
      const account = await stripe.accounts.create({
        type: "express",
        capabilities: {
          card_payments: { requested: true },
          transfers: { requested: true },
        },
      });

      accountId = account.id;
      await supabase
        .from("partners_market")
        .update({
          stripe_connect_account_id: accountId,
          payout_status: "incomplete",
          updated_at: new Date().toISOString(),
        })
        .eq("id", partnerId);
    }

    const frontendBase = String(process.env.FRONTEND_URL || "https://onekamer-front-lab.onrender.com").replace(/\/$/, "");
    const returnUrl = `${frontendBase}/compte`;
    const refreshUrl = `${frontendBase}/compte`;

    const link = await stripe.accountLinks.create({
      account: accountId,
      refresh_url: refreshUrl,
      return_url: returnUrl,
      type: "account_onboarding",
    });

    return res.json({ url: link.url, accountId });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/api/partner/connect/sync-status", bodyParser.json(), async (req, res) => {
  try {
    const { partnerId } = req.body || {};
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const auth = await requirePartnerOwner({ req, partnerId });
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const accountId = auth.partner?.stripe_connect_account_id ? String(auth.partner.stripe_connect_account_id) : null;
    if (!accountId) return res.status(400).json({ error: "stripe_connect_account_id manquant" });

    const account = await stripe.accounts.retrieve(accountId);

    const detailsSubmitted = account?.details_submitted === true;
    const chargesEnabled = account?.charges_enabled === true;
    const payoutsEnabled = account?.payouts_enabled === true;
    const payoutStatus = detailsSubmitted && chargesEnabled && payoutsEnabled ? "complete" : "incomplete";

    await supabase
      .from("partners_market")
      .update({
        payout_status: payoutStatus,
        updated_at: new Date().toISOString(),
      })
      .eq("id", partnerId);

    await logEvent({
      category: "marketplace",
      action: "connect.status.sync",
      status: "success",
      userId: auth.userId,
      context: {
        partner_id: partnerId,
        stripe_connect_account_id: accountId,
        payout_status: payoutStatus,
        details_submitted: detailsSubmitted,
        charges_enabled: chargesEnabled,
        payouts_enabled: payoutsEnabled,
      },
    });

    return res.json({
      ok: true,
      payout_status: payoutStatus,
      details_submitted: detailsSubmitted,
      charges_enabled: chargesEnabled,
      payouts_enabled: payoutsEnabled,
    });
  } catch (e) {
    await logEvent({
      category: "marketplace",
      action: "connect.status.sync",
      status: "error",
      context: { error: e?.message || String(e) },
    });
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const fromEmail = process.env.FROM_EMAIL || "no-reply@onekamer.co";

// Clé API Brevo HTTP (recommandé sur Render)
const brevoApiKey = process.env.BREVO_API_KEY;
const brevoApiUrl = process.env.BREVO_API_URL || "https://api.brevo.com/v3/smtp/email";

let mailTransport = null;

function getMailTransport() {
  if (!mailTransport) {
    if (!smtpHost || !smtpUser || !smtpPass) {
      console.warn("⚠️ SMTP non configuré (HOST/USER/PASS manquants)");
      throw new Error("SMTP non configuré côté serveur LAB");
    }
    console.log("📧 Initialisation transport SMTP Nodemailer", {
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
    });
    mailTransport = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: {
        user: smtpUser,
        pass: smtpPass,
      },
      connectionTimeout: 15000,
      socketTimeout: 15000,
    });
  }
  return mailTransport;
}

async function sendEmailViaBrevo({ to, subject, text }) {
  if (!brevoApiKey) {
    console.warn("⚠️ BREVO_API_KEY manquant, tentative via transport SMTP Nodemailer");
    const transport = getMailTransport();
    await transport.sendMail({ from: fromEmail, to, subject, text });
    return;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);

  try {
    const response = await fetch(brevoApiUrl, {
      method: "POST",
      headers: {
        "api-key": brevoApiKey,
        "Content-Type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        // ⚠️ L'adresse doit être validée côté Brevo pour être vraiment utilisée
        sender: { email: fromEmail, name: "OneKamer" },
        to: [{ email: to }],
        subject,
        textContent: text,
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Brevo API error ${response.status}: ${errorText}`);
    }

    console.log("📧 Brevo HTTP API → email envoyé à", to);
  } catch (err) {
    console.error("❌ Erreur Brevo HTTP API:", err.message || err);
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

// ============================================================
// 🎥 LiveKit - Config de base (LAB)
// ============================================================
const LIVEKIT_API_KEY = process.env.LIVEKIT_API_KEY;
const LIVEKIT_API_SECRET = process.env.LIVEKIT_API_SECRET;
const LIVEKIT_URL = process.env.LIVEKIT_URL;

function createGroupRoomName(groupId) {
  return `group_${groupId}`;
}

async function ensureUserIsGroupMember(groupId, userId) {
  const { data, error } = await supabase
    .from("groupes_membres")
    .select("id")
    .eq("groupe_id", groupId)
    .eq("user_id", userId)
    .limit(1)
    .maybeSingle();

  if (error) {
    console.error("❌ Erreur vérification membre groupe:", error.message);
    throw new Error("Erreur vérification du groupe");
  }
  if (!data) {
    const err = new Error("Accès refusé au groupe");
    err.statusCode = 403;
    throw err;
  }
}

async function getOrCreateGroupLiveSession(groupId, hostUserId) {
  const { data: existing, error: existingErr } = await supabase
    .from("group_live_sessions")
    .select("id, room_name")
    .eq("group_id", groupId)
    .eq("is_live", true)
    .limit(1)
    .maybeSingle();

  if (existingErr) {
    console.error("❌ Erreur lecture group_live_sessions:", existingErr.message);
    throw new Error("Erreur serveur (group_live_sessions)");
  }

  if (existing) {
    return existing.room_name;
  }

  const roomName = createGroupRoomName(groupId);
  const { error: insertErr } = await supabase.from("group_live_sessions").insert({
    group_id: groupId,
    host_user_id: hostUserId,
    room_name: roomName,
    is_live: true,
  });

  if (insertErr) {
    console.error("❌ Erreur création group_live_sessions:", insertErr.message);
    throw new Error("Impossible de créer la session live");
  }

  return roomName;
}

function createLivekitToken({ roomName, userId }) {
  if (!LIVEKIT_API_KEY || !LIVEKIT_API_SECRET) {
    throw new Error("LiveKit non configuré côté serveur");
  }

  const at = new AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET, {
    identity: userId,
  });

  at.addGrant({
    roomJoin: true,
    room: roomName,
    canPublish: true,
    canPublishData: true,
    canSubscribe: true,
  });

  return at.toJwt();
}

// ============================================================
// 🔎 Journalisation auto (évènements sensibles) -> public.server_logs
//   Colonnes attendues (recommandées) :
//     id uuid default gen_random_uuid() PK
//     created_at timestamptz default now()
//     category text            -- ex: 'stripe', 'subscription', 'okcoins', 'withdrawal', 'profile'
//     action text              -- ex: 'webhook.received', 'checkout.created', ...
//     status text              -- 'success' | 'error' | 'info'
//     user_id uuid null
//     context jsonb null
//   ⚠️ Le code fonctionne même si des colonnes supplémentaires existent.
// ============================================================

function safeJson(obj) {
  try {
    return JSON.parse(
      JSON.stringify(obj, (_key, val) => {
        if (typeof val === "bigint") return val.toString();
        return val;
      })
    );
  } catch (_e) {
    return { note: "context serialization failed" };
  }
}

async function logEvent({ category, action, status, userId = null, context = {} }) {
  try {
    const payload = {
      category,
      action,
      status,
      user_id: userId || null,
      context: safeJson(context),
    };
    const { error } = await supabase.from("server_logs").insert(payload);
    if (error) {
      console.warn("⚠️ Log insert failed:", error.message);
    }
  } catch (e) {
    console.warn("⚠️ Log error:", e?.message || e);
  }
}

// ============================================================
// 🔔 Notification push admin (retraits) via système natif (LAB)
//    - Utilise NOTIFICATIONS_PROVIDER = 'supabase_light'
//    - Envoie vers /api/push/send pour tous les profils admin
// ============================================================

async function sendAdminWithdrawalPush(req, { username, amount }) {
  if (NOTIF_PROVIDER !== "supabase_light") return;

  try {
    const { data: admins, error } = await supabase
      .from("profiles")
      .select("id")
      .or("role.eq.admin,is_admin.is.true");

    if (error) {
      console.warn("⚠️ Erreur lecture profils admin pour push retrait (LAB):", error.message);
      await logEvent({
        category: "withdrawal",
        action: "push.notify",
        status: "error",
        context: { env: "lab", stage: "fetch_admins", error: error.message },
      });
      return;
    }

    if (!admins || admins.length === 0) {
      await logEvent({
        category: "withdrawal",
        action: "push.notify",
        status: "info",
        context: { env: "lab", note: "no_admins_found" },
      });
      return;
    }

    const targetUserIds = admins.map((a) => a.id).filter(Boolean);
    if (targetUserIds.length === 0) return;

    const baseUrl = `${req.protocol}://${req.get("host")}`;

    const safeName = username || "Un membre";
    const title = "Nouvelle demande de retrait OK COINS";
    const message = `${safeName} a demandé un retrait de ${amount.toLocaleString("fr-FR")} pièces.`;

    const response = await fetch(`${baseUrl}/api/push/send`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        title,
        message,
        targetUserIds,
        url: process.env.FRONTEND_URL ? `${process.env.FRONTEND_URL}/okcoins` : "https://onekamer.co/okcoins",
        data: { type: "okcoins_withdrawal" },
      }),
    });

    const data = await response.json().catch(() => null);

    if (!response.ok) {
      await logEvent({
        category: "withdrawal",
        action: "push.notify",
        status: "error",
        context: { env: "lab", stage: "push_send", status: response.status, body: data },
      });
      return;
    }

    await logEvent({
      category: "withdrawal",
      action: "push.notify",
      status: "success",
      context: { env: "lab", sent: data?.sent ?? null, target_count: targetUserIds.length },
    });
  } catch (e) {
    console.warn("⚠️ Erreur sendAdminWithdrawalPush (LAB):", e?.message || e);
    await logEvent({
      category: "withdrawal",
      action: "push.notify",
      status: "error",
      context: { env: "lab", stage: "exception", error: e?.message || String(e) },
    });
  }
}

// ============================================================
// 🔔 API Notifications (LAB) — lecture + marquage lu
//      Utilise la table public.notifications (commune LAB/PROD)
// ============================================================

// Liste paginée des notifications pour un utilisateur
// Query: userId (requis), limit (def 20), cursor (ISO date: created_at < cursor)
app.get("/notifications", async (req, res) => {
  try {
    const userId = req.query.userId;
    const limit = Math.min(parseInt(req.query.limit || "20", 10), 50);
    const cursor = req.query.cursor; // ISO date string

    if (!userId) return res.status(400).json({ error: "userId requis" });

    let query = supabase
      .from("notifications")
      .select("id, created_at, title, message, type, link, is_read, content_id")
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(limit + 1);

    if (cursor) {
      query = query.lt("created_at", cursor);
    }

    const { data, error } = await query;
    if (error) throw new Error(error.message);

    const hasMore = data && data.length > limit;
    const items = hasMore ? data.slice(0, limit) : data || [];
    const nextCursor = hasMore ? items[items.length - 1]?.created_at : null;

    const { count: unreadCount, error: cntErr } = await supabase
      .from("notifications")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .eq("is_read", false);
    if (cntErr) console.warn("⚠️ unreadCount error:", cntErr.message);

    res.json({
      items:
        items?.map((n) => ({
          id: n.id,
          created_at: n.created_at,
          title: n.title,
          body: n.message,
          type: n.type,
          deeplink: n.link || "/",
          contentId: n.content_id || null,
          is_read: !!n.is_read,
        })) || [],
      nextCursor,
      hasMore,
      unreadCount: typeof unreadCount === "number" ? unreadCount : 0,
    });
  } catch (e) {
    console.error("❌ GET /notifications:", e);
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// Marquer une notification comme lue
app.post("/notifications/mark-read", async (req, res) => {
  try {
    const { userId, id } = req.body || {};

    if (!userId || !id) return res.status(400).json({ error: "userId et id requis" });

    const { error } = await supabase
      .from("notifications")
      .update({ is_read: true })
      .eq("id", id)
      .eq("user_id", userId);
    if (error) throw new Error(error.message);

    res.json({ ok: true });
  } catch (e) {
    console.error("❌ POST /notifications/mark-read:", e);
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// Marquer toutes les notifications comme lues
app.post("/notifications/mark-all-read", async (req, res) => {
  try {
    const { userId } = req.body || {};

    if (!userId) return res.status(400).json({ error: "userId requis" });

    const { error } = await supabase
      .from("notifications")
      .update({ is_read: true })
      .eq("user_id", userId)
      .eq("is_read", false);
    if (error) throw new Error(error.message);

    res.json({ ok: true });
  } catch (e) {
    console.error("❌ POST /notifications/mark-all-read:", e);
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// Aliases /api pour compat FRONT
app.get("/api/notifications", (req, res, next) => {
  console.log("🔁 Alias LAB : /api/notifications → /notifications");
  req.url = "/notifications";
  app._router.handle(req, res, next);
});

app.post("/api/notifications/mark-read", (req, res, next) => {
  console.log("🔁 Alias LAB : /api/notifications/mark-read → /notifications/mark-read");
  req.url = "/notifications/mark-read";
  app._router.handle(req, res, next);
});

app.post("/api/notifications/mark-all-read", (req, res, next) => {
  console.log("🔁 Alias LAB : /api/notifications/mark-all-read → /notifications/mark-all-read");
  req.url = "/notifications/mark-all-read";
  app._router.handle(req, res, next);
});

// ============================================================
// 1️⃣ Webhook Stripe (OK COINS + Abonnements)
// ============================================================

app.post("/webhook", bodyParser.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error("❌ Webhook verification failed:", err.message);
    await logEvent({
      category: "stripe",
      action: "webhook.verify",
      status: "error",
      context: { error: err.message },
    });
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log("📦 Événement Stripe reçu :", event.type);
  await logEvent({
    category: "stripe",
    action: "webhook.received",
    status: "info",
    context: { event_type: event.type, event_id: event.id },
  });

  try {
    if (event.type === "payment_intent.succeeded") {
      const pi = event.data.object;
      const md = (pi && pi.metadata) ? pi.metadata : {};
      const userId = md.userId ? String(md.userId) : null;
      const packId = md.packId ? parseInt(md.packId, 10) : null;

      try {
        const { error: evtErr } = await supabase
          .from("stripe_events")
          .insert({ event_id: event.id });
        if (evtErr && evtErr.code === "23505") {
          await logEvent({
            category: "okcoins",
            action: "pi.succeeded.duplicate",
            status: "info",
            userId: userId || null,
            context: { event_id: event.id, packId },
          });
          return res.json({ received: true });
        }
      } catch {}

      if (userId && Number.isFinite(packId)) {
        try {
          await supabase.rpc("okc_grant_pack_after_payment", {
            p_user: userId,
            p_pack_id: packId,
            p_status: "paid",
          });
          await logEvent({
            category: "okcoins",
            action: "pi.succeeded.credit",
            status: "success",
            userId,
            context: { packId },
          });
        } catch (e) {
          await logEvent({
            category: "okcoins",
            action: "pi.succeeded.credit",
            status: "error",
            userId: userId || null,
            context: { packId, error: e?.message || String(e) },
          });
        }
      }
      return res.json({ received: true });
    }
    if (event.type === "account.updated" || event.type === "v2.core.account.updated") {
      const account = event.data.object;
      const accountId = account?.id ? String(account.id) : null;
      if (accountId) {
        const detailsSubmitted = account?.details_submitted === true;
        const chargesEnabled = account?.charges_enabled === true;
        const payoutsEnabled = account?.payouts_enabled === true;
        const payoutStatus = detailsSubmitted && chargesEnabled && payoutsEnabled ? "complete" : "incomplete";

        try {
          await supabase
            .from("partners_market")
            .update({
              payout_status: payoutStatus,
              updated_at: new Date().toISOString(),
            })
            .eq("stripe_connect_account_id", accountId);

          await logEvent({
            category: "marketplace",
            action: "connect.account.updated",
            status: "success",
            context: {
              stripe_connect_account_id: accountId,
              payout_status: payoutStatus,
              details_submitted: detailsSubmitted,
              charges_enabled: chargesEnabled,
              payouts_enabled: payoutsEnabled,
            },
          });
        } catch (e) {
          await logEvent({
            category: "marketplace",
            action: "connect.account.updated",
            status: "error",
            context: {
              stripe_connect_account_id: accountId,
              error: e?.message || String(e),
            },
          });
        }
      }

      return res.json({ received: true });
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const { userId, packId, planKey, promoCode, eventId, paymentMode } = session.metadata || {};

      // Cas marketplace (Partenaires)
      const marketOrderId = session?.metadata?.market_order_id;
      if (marketOrderId) {
        try {
          await supabase
            .from("partner_orders")
            .update({
              status: "paid",
              updated_at: new Date().toISOString(),
            })
            .eq("id", marketOrderId);

          await supabase
            .from("partner_order_payments")
            .update({
              status: "succeeded",
              stripe_payment_intent_id: session.payment_intent || null,
              updated_at: new Date().toISOString(),
            })
            .eq("stripe_checkout_session_id", session.id);

          try {
            const { data: conv } = await supabase
              .from("marketplace_order_conversations")
              .select("id")
              .eq("order_id", marketOrderId)
              .maybeSingle();
            if (!conv) {
              const { data: ordRow } = await supabase
                .from("partner_orders")
                .select("id, partner_id, customer_user_id")
                .eq("id", marketOrderId)
                .maybeSingle();
              const { data: partnerRow } = await supabase
                .from("partners_market")
                .select("id, owner_user_id")
                .eq("id", ordRow?.partner_id)
                .maybeSingle();
              if (ordRow?.id && partnerRow?.owner_user_id) {
                await supabase.from("marketplace_order_conversations").insert({
                  order_id: marketOrderId,
                  buyer_id: ordRow.customer_user_id,
                  seller_id: partnerRow.owner_user_id,
                  created_at: new Date().toISOString(),
                });
              }
            }
          } catch {}

          await logEvent({
            category: "marketplace",
            action: "checkout.completed",
            status: "success",
            userId: session?.metadata?.customer_user_id || null,
            context: {
              market_order_id: marketOrderId,
              stripe_checkout_session_id: session.id,
              stripe_payment_intent_id: session.payment_intent || null,
            },
          });

          return res.json({ received: true });
        } catch (e) {
          await logEvent({
            category: "marketplace",
            action: "checkout.completed",
            status: "error",
            userId: session?.metadata?.customer_user_id || null,
            context: {
              market_order_id: marketOrderId,
              stripe_checkout_session_id: session.id,
              error: e?.message || String(e),
            },
          });
          return res.json({ received: true });
        }
      }

      // Cas 0 : Paiement événement (Checkout mode payment)
      if (eventId && userId && session.mode === "payment") {
        try {
          const paidAmount = typeof session.amount_total === "number" ? session.amount_total : 0;

          const { data: ev, error: evErr } = await supabase
            .from("evenements")
            .select("id, price_amount, currency")
            .eq("id", eventId)
            .maybeSingle();
          if (evErr) throw new Error(evErr.message);

          const amountTotal = typeof ev?.price_amount === "number" ? ev.price_amount : null;
          const currency = ev?.currency ? String(ev.currency).toLowerCase() : null;

          if (!amountTotal || amountTotal <= 0 || !currency) {
            await logEvent({
              category: "event_payment",
              action: "checkout.completed.skipped",
              status: "info",
              userId,
              context: { reason: "event_not_payable_or_missing_currency", eventId, session_id: session.id },
            });
            return res.json({ received: true });
          }

          const { data: existingPay, error: getPayErr } = await supabase
            .from("event_payments")
            .select("id, amount_total, amount_paid")
            .eq("event_id", eventId)
            .eq("user_id", userId)
            .maybeSingle();
          if (getPayErr) throw new Error(getPayErr.message);

          const prevPaid = typeof existingPay?.amount_paid === "number" ? existingPay.amount_paid : 0;
          const newPaid = Math.min(prevPaid + paidAmount, amountTotal);
          const newStatus = newPaid >= amountTotal ? "paid" : newPaid > 0 ? "deposit_paid" : "unpaid";

          const upsertPayload = {
            event_id: eventId,
            user_id: userId,
            amount_total: amountTotal,
            amount_paid: newPaid,
            currency,
            status: newStatus,
            stripe_checkout_session_id: session.id,
            stripe_payment_intent_id: session.payment_intent || null,
            updated_at: new Date().toISOString(),
          };

          const { error: upsertErr } = await supabase
            .from("event_payments")
            .upsert(upsertPayload, { onConflict: "event_id,user_id" });
          if (upsertErr) throw new Error(upsertErr.message);

          // Générer automatiquement un QR si absent
          const { data: existingQr, error: qrErr } = await supabase
            .from("event_qrcodes")
            .select("id")
            .eq("event_id", eventId)
            .eq("user_id", userId)
            .eq("status", "active")
            .maybeSingle();
          if (qrErr) throw new Error(qrErr.message);

          if (!existingQr) {
            const qrcode_value = crypto.randomUUID();
            const { error: insQrErr } = await supabase
              .from("event_qrcodes")
              .insert([{ user_id: userId, event_id: eventId, qrcode_value }]);
            if (insQrErr) throw new Error(insQrErr.message);
          }

          await logEvent({
            category: "event_payment",
            action: "checkout.completed",
            status: "success",
            userId,
            context: {
              eventId,
              paymentMode: paymentMode || null,
              paidAmount,
              amountTotal,
              amountPaid: newPaid,
              paymentStatus: newStatus,
              session_id: session.id,
            },
          });

          return res.json({ received: true });
        } catch (e) {
          console.error("❌ Event payment webhook error:", e?.message || e);
          await logEvent({
            category: "event_payment",
            action: "checkout.completed",
            status: "error",
            userId: userId || null,
            context: { eventId: eventId || null, error: e?.message || String(e), session_id: session.id },
          });
          return res.json({ received: true });
        }
      }

      // Cas 1 : Achat OK COINS
      if (packId) {
        try {
          const { error: evtErr } = await supabase
            .from("stripe_events")
            .insert({ event_id: event.id });
          if (evtErr && evtErr.code === "23505") {
            console.log("🔁 Événement déjà traité :", event.id);
            await logEvent({
              category: "okcoins",
              action: "checkout.completed.duplicate",
              status: "info",
              userId,
              context: { event_id: event.id, packId },
            });
            return res.json({ received: true });
          }

          const { data, error } = await supabase.rpc("okc_grant_pack_after_payment", {
            p_user: userId,
            p_pack_id: parseInt(packId, 10),
            p_status: "paid",
          });

          if (error) {
            console.error("❌ Erreur RPC Supabase (OK COINS):", error);
            await logEvent({
              category: "okcoins",
              action: "checkout.completed.credit",
              status: "error",
              userId,
              context: { packId, rpc_error: error.message },
            });
          } else {
            console.log("✅ OK COINS crédités :", data);
            await logEvent({
              category: "okcoins",
              action: "checkout.completed.credit",
              status: "success",
              userId,
              context: { packId, data },
            });
          }
        } catch (e) {
          await logEvent({
            category: "okcoins",
            action: "checkout.completed.credit",
            status: "error",
            userId,
            context: { packId, error: e?.message || e },
          });
          throw e;
        }
      }

      // Cas 2 : Tracking code promo influenceur (abonnements)
      if (session.mode === "subscription" && promoCode) {
        try {
          const normalizedCode = String(promoCode).trim();
          if (normalizedCode) {
            const { data: promo, error: promoErr } = await supabase
              .from("promo_codes")
              .select("id, code, actif, date_debut, date_fin")
              .eq("code", normalizedCode)
              .maybeSingle();

            if (promoErr) {
              console.error("❌ Erreur lecture promo_codes:", promoErr);
              await logEvent({
                category: "promo",
                action: "usage.lookup",
                status: "error",
                userId,
                context: { promoCode: normalizedCode, error: promoErr.message },
              });
            } else if (promo && promo.actif !== false) {
              const now = new Date();
              const startOk = !promo.date_debut || new Date(promo.date_debut) <= now;
              const endOk = !promo.date_fin || new Date(promo.date_fin) >= now;

              if (startOk && endOk) {
                const amountPaid = typeof session.amount_total === "number" ? session.amount_total : null;

                const { error: usageErr } = await supabase.from("promo_code_usages").insert({
                  promo_code_id: promo.id,
                  user_id: userId || null,
                  plan: planKey || null,
                  stripe_checkout_session_id: session.id,
                  stripe_customer_id: session.customer || null,
                  amount_paid: amountPaid,
                  ok_coins_granted: 0,
                });

                if (usageErr) {
                  console.error("❌ Erreur insert promo_code_usages:", usageErr);
                  await logEvent({
                    category: "promo",
                    action: "usage.insert",
                    status: "error",
                    userId,
                    context: { promoCode: normalizedCode, error: usageErr.message },
                  });
                } else {
                  await logEvent({
                    category: "promo",
                    action: "usage.insert",
                    status: "success",
                    userId,
                    context: { promoCode: normalizedCode, planKey, session_id: session.id },
                  });
                }
              }
            }
          }
        } catch (e) {
          console.error("❌ Exception tracking promo_code:", e?.message || e);
          await logEvent({
            category: "promo",
            action: "usage.exception",
            status: "error",
            userId,
            context: { promoCode, error: e?.message || String(e) },
          });
        }
      }

      // Cas 3 : Abonnement Stripe (Standard / VIP)
      if (session.mode === "subscription" && planKey) {
        try {
          const subscription = await stripe.subscriptions.retrieve(session.subscription);
          const priceId = subscription.items.data[0]?.price?.id ?? null;
          const currentPeriodEnd = new Date(subscription.current_period_end * 1000).toISOString();
          const cancelAtPeriodEnd = Boolean(subscription.cancel_at_period_end);
          const status =
            subscription.status === "trialing"
              ? "trialing"
              : subscription.status === "active"
              ? "active"
              : subscription.status === "canceled"
              ? "cancelled"
              : "active";

          const { error: rpcError } = await supabase.rpc("upsert_subscription_from_stripe", {
            p_user_id: userId,
            p_plan_key: planKey,
            p_stripe_customer_id: session.customer,
            p_stripe_subscription_id: subscription.id,
            p_stripe_price_id: priceId,
            p_status: status,
            p_current_period_end: currentPeriodEnd,
            p_cancel_at_period_end: cancelAtPeriodEnd,
          });

          if (rpcError) {
            console.error("❌ Erreur RPC Supabase (abo):", rpcError);
            await logEvent({
              category: "subscription",
              action: "upsert.from_webhook",
              status: "error",
              userId,
              context: { planKey, subscription_id: subscription.id, rpc_error: rpcError.message },
            });
          } else {
            console.log("✅ Abonnement mis à jour dans Supabase");
            await logEvent({
              category: "subscription",
              action: "upsert.from_webhook",
              status: "success",
              userId,
              context: { planKey, subscription_id: subscription.id },
            });
          }
        } catch (e) {
          await logEvent({
            category: "subscription",
            action: "upsert.from_webhook",
            status: "error",
            userId,
            context: { planKey, error: e?.message || e },
          });
          throw e;
        }
      }

      // Cas 4 : Achat unique “VIP à vie”
      if (session.mode === "payment" && planKey === "vip_lifetime") {
        try {
          const { error: insertErr } = await supabase.from("abonnements").insert({
            profile_id: userId,
            plan_name: "VIP à vie",
            status: "active",
            start_date: new Date().toISOString(),
            auto_renew: false,
            is_permanent: true,
          });
          if (insertErr) {
            console.error("❌ Erreur insert VIP à vie:", insertErr);
            await logEvent({
              category: "subscription",
              action: "vip_lifetime.insert",
              status: "error",
              userId,
              context: { error: insertErr.message },
            });
          } else {
            const { error: rpcErr } = await supabase.rpc("apply_plan_to_profile", {
              p_user_id: userId,
              p_plan_key: "vip",
            });
            if (rpcErr) {
              console.error("❌ Erreur RPC apply_plan_to_profile:", rpcErr);
              await logEvent({
                category: "subscription",
                action: "vip_lifetime.apply_plan",
                status: "error",
                userId,
                context: { error: rpcErr.message },
              });
            } else {
              await logEvent({
                category: "subscription",
                action: "vip_lifetime.completed",
                status: "success",
                userId,
                context: {},
              });
            }
          }
        } catch (e) {
          await logEvent({
            category: "subscription",
            action: "vip_lifetime",
            status: "error",
            userId,
            context: { error: e?.message || e },
          });
          throw e;
        }
      }
    }

    // =========================================================
    // (B) Mise à jour / annulation d’abonnement Stripe
    // =========================================================
    if (
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.deleted"
    ) {
      const sub = event.data.object;
      const priceId = sub.items.data[0]?.price?.id ?? null;
      const currentPeriodEnd = new Date(sub.current_period_end * 1000).toISOString();
      const cancelAtPeriodEnd = Boolean(sub.cancel_at_period_end);
      const status =
        event.type === "customer.subscription.deleted"
          ? "cancelled"
          : sub.status === "active"
          ? "active"
          : sub.status === "trialing"
          ? "trialing"
          : sub.status === "canceled"
          ? "cancelled"
          : "active";

      try {
        // Trouver l’utilisateur lié à cet abonnement Stripe
        const { data: abo, error: aboErr } = await supabase
          .from("abonnements")
          .select("profile_id")
          .eq("stripe_subscription_id", sub.id)
          .limit(1)
          .maybeSingle();

        if (aboErr) {
          console.error("Erreur recherche abo:", aboErr);
          await logEvent({
            category: "subscription",
            action: "stripe.sub.update.lookup_user",
            status: "error",
            context: { subscription_id: sub.id, error: aboErr.message },
          });
        }
        if (!abo?.profile_id) {
          await logEvent({
            category: "subscription",
            action: "stripe.sub.update.no_user",
            status: "info",
            context: { subscription_id: sub.id },
          });
          return res.json({ received: true });
        }

        // Identifier le plan
        const { data: plan } = await supabase
          .from("pricing_plans")
          .select("key")
          .eq("stripe_price_id", priceId)
          .maybeSingle();

        const planKey = plan?.key || "standard";

        // Appel RPC pour mise à jour
        const { error: rpcError } = await supabase.rpc("upsert_subscription_from_stripe", {
          p_user_id: abo.profile_id,
          p_plan_key: planKey,
          p_stripe_customer_id: sub.customer,
          p_stripe_subscription_id: sub.id,
          p_stripe_price_id: priceId,
          p_status: status,
          p_current_period_end: currentPeriodEnd,
          p_cancel_at_period_end: cancelAtPeriodEnd,
        });

        if (rpcError) {
          console.error("❌ Erreur update subscription:", rpcError);
          await logEvent({
            category: "subscription",
            action: "stripe.sub.update",
            status: "error",
            userId: abo.profile_id,
            context: { subscription_id: sub.id, planKey, error: rpcError.message },
          });
        } else {
          console.log("✅ Abonnement mis à jour après event Stripe");
          await logEvent({
            category: "subscription",
            action: "stripe.sub.update",
            status: "success",
            userId: abo.profile_id,
            context: { subscription_id: sub.id, planKey, status },
          });
        }
      } catch (e) {
        await logEvent({
          category: "subscription",
          action: "stripe.sub.update",
          status: "error",
          context: { subscription_id: sub?.id, error: e?.message || e },
        });
        throw e;
      }
    }

    res.json({ received: true });
  } catch (err) {
    console.error("❌ Erreur interne Webhook :", err);
    await logEvent({
      category: "stripe",
      action: "webhook.handler",
      status: "error",
      context: { event_type: event?.type, error: err?.message || err },
    });
    res.status(500).send("Erreur serveur interne");
  }
});

// ============================================================
// 📨 Messages de groupes (LAB) + détection @tous (dry-run)
// ============================================================

app.post("/api/groups/:groupId/messages", bodyParser.json(), async (req, res) => {
  try {
    const { groupId } = req.params;
    const { senderId, content } = req.body || {};

    if (!senderId || !groupId) {
      return res
        .status(400)
        .json({ error: "senderId et groupId sont requis" });
    }

    if (!content || typeof content !== "string") {
      return res.status(400).json({ error: "content est requis" });
    }

    const { data: inserted, error } = await supabase
      .from("messages_groupes")
      .insert({
        groupe_id: groupId,
        sender_id: senderId,
        contenu: content,
      })
      .select("id")
      .single();

    if (error) {
      console.error("❌ Erreur insert messages_groupes:", error.message);
      await logEvent({
        category: "group_message",
        action: "insert",
        status: "error",
        userId: senderId,
        context: { groupId, error: error.message },
      });
      return res
        .status(400)
        .json({ error: "Impossible d'enregistrer le message" });
    }

    await logEvent({
      category: "group_message",
      action: "insert",
      status: "success",
      userId: senderId,
      context: { groupId, message_id: inserted?.id },
    });

    // Détection @tous (dry-run, pas d'envoi réel pour l'instant)
    await handleAtTousIfAllowed({
      req,
      supabase,
      NOTIF_PROVIDER,
      authorId: senderId,
      contextType: "groupe",
      contextId: groupId,
      rawText: content,
    });

    res.json({ success: true, id: inserted?.id || null });
  } catch (e) {
    console.error("❌ Erreur /api/groups/:groupId/messages:", e?.message || e);
    res.status(500).json({ error: "Erreur interne serveur" });
  }
});

// ============================================================
// 🎧🎥 LiveKit - Appels de groupe (LAB)
// ============================================================

app.post("/api/groups/:groupId/call/start", bodyParser.json(), async (req, res) => {
  try {
    const { groupId } = req.params;
    const { userId } = req.body || {};

    if (!groupId || !userId) {
      return res.status(400).json({ error: "groupId et userId sont requis" });
    }

    await ensureUserIsGroupMember(groupId, userId);

    const roomName = await getOrCreateGroupLiveSession(groupId, userId);
    const token = createLivekitToken({ roomName, userId });

    res.json({
      roomName,
      token,
      url: LIVEKIT_URL || null,
    });
  } catch (e) {
    console.error("❌ POST /api/groups/:groupId/call/start:", e);
    const status = e.statusCode || 500;
    res.status(status).json({ error: e.message || "Erreur interne" });
  }
});

app.post("/api/groups/:groupId/call/join", bodyParser.json(), async (req, res) => {
  try {
    const { groupId } = req.params;
    const { userId } = req.body || {};

    if (!groupId || !userId) {
      return res.status(400).json({ error: "groupId et userId sont requis" });
    }

    await ensureUserIsGroupMember(groupId, userId);

    const { data: session, error } = await supabase
      .from("group_live_sessions")
      .select("room_name")
      .eq("group_id", groupId)
      .eq("is_live", true)
      .limit(1)
      .maybeSingle();

    if (error) {
      console.error("❌ Erreur lecture group_live_sessions (join):", error.message);
      throw new Error("Erreur serveur (group_live_sessions)");
    }

    if (!session) {
      return res.status(404).json({ error: "Aucun appel en cours pour ce groupe" });
    }

    const roomName = session.room_name;
    const token = createLivekitToken({ roomName, userId });

    res.json({
      roomName,
      token,
      url: LIVEKIT_URL || null,
    });
  } catch (e) {
    console.error("❌ POST /api/groups/:groupId/call/join:", e);
    const status = e.statusCode || 500;
    res.status(status).json({ error: e.message || "Erreur interne" });
  }
});

app.post("/api/groups/:groupId/call/end", bodyParser.json(), async (req, res) => {
  try {
    const { groupId } = req.params;
    const { userId } = req.body || {};

    if (!groupId || !userId) {
      return res.status(400).json({ error: "groupId et userId sont requis" });
    }

    await ensureUserIsGroupMember(groupId, userId);

    const { error } = await supabase
      .from("group_live_sessions")
      .update({ is_live: false, ended_at: new Date().toISOString(), ended_reason: "ended_by_user" })
      .eq("group_id", groupId)
      .eq("is_live", true);

    if (error) {
      console.error("❌ Erreur update group_live_sessions (end):", error.message);
      throw new Error("Impossible de terminer l'appel");
    }

    res.json({ success: true });
  } catch (e) {
    console.error("❌ POST /api/groups/:groupId/call/end:", e);
    const status = e.statusCode || 500;
    res.status(status).json({ error: e.message || "Erreur interne" });
  }
});

// ============================================================
// 2️⃣ Création de session Stripe - OK COINS
// ============================================================

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// PaymentIntent Elements pour OK COINS (LAB)
app.post("/api/okcoins/intent", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireUserJWT(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { packId } = req.body || {};
    if (!packId) return res.status(400).json({ error: "packId requis" });

    const { data: pack, error: packErr } = await supabase
      .from("okcoins_packs")
      .select("price_eur, is_active")
      .eq("id", packId)
      .maybeSingle();
    if (packErr) return res.status(500).json({ error: packErr.message || "pack_read_failed" });
    if (!pack || pack.is_active === false) return res.status(404).json({ error: "pack_not_found" });

    const amount = Math.max(1, Math.round(Number(pack.price_eur || 0) * 100));

    const intent = await stripe.paymentIntents.create({
      amount,
      currency: "eur",
      automatic_payment_methods: { enabled: true },
      metadata: { userId: guard.userId, packId: String(packId) },
    });

    return res.json({ clientSecret: intent.client_secret });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// ============================================================
// 🛡️ Admin - Modération Échange communautaire
//   - Suppression de posts texte (table posts)
//   - Suppression de posts vocaux (table comments, content_type='echange')
//   ⚠️ Sans toucher aux RLS : suppression via service-role après check is_admin
// ============================================================

async function requireAdminIsAdmin(req) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return { ok: false, status: 401, error: "unauthorized" };

  const supabaseAuth = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
  const { data: userData, error: userErr } = await supabaseAuth.auth.getUser(token);
  if (userErr || !userData?.user) return { ok: false, status: 401, error: "invalid_token" };

  const userId = userData.user.id;
  const { data: prof, error: pErr } = await supabase
    .from("profiles")
    .select("is_admin, role, username")
    .eq("id", userId)
    .maybeSingle();

  if (pErr || !prof) return { ok: false, status: 403, error: "forbidden" };
  const isAdmin = Boolean(prof.is_admin) || String(prof.role || "").toLowerCase() === "admin";
  if (!isAdmin) return { ok: false, status: 403, error: "forbidden" };
  return { ok: true, userId, adminUsername: prof.username || null };
}

app.get("/api/admin/users", async (req, res) => {
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const searchRaw = req.query.search ? String(req.query.search).trim() : "";
    const search = searchRaw.length ? searchRaw : "";
    const limitRaw = req.query.limit;
    const offsetRaw = req.query.offset;
    const limit = Math.min(Math.max(parseInt(limitRaw, 10) || 20, 1), 50);
    const offset = Math.max(parseInt(offsetRaw, 10) || 0, 0);

    const emailSearchMode = search.includes("@");
    let items = [];
    let total = null;

    if (emailSearchMode && supabase?.auth?.admin?.listUsers) {
      const page = Math.floor(offset / limit) + 1;
      const { data: uData, error: uErr } = await supabase.auth.admin.listUsers({ page, perPage: limit });
      if (uErr) return res.status(500).json({ error: uErr.message || "Erreur lecture utilisateurs" });

      const users = Array.isArray(uData?.users) ? uData.users : [];
      const q = search.toLowerCase();
      const filtered = users.filter((u) => String(u?.email || "").toLowerCase().includes(q));
      const ids = filtered.map((u) => u.id).filter(Boolean);
      if (ids.length === 0) return res.json({ items: [], total: 0, limit, offset });

      const { data: profs, error: pErr } = await supabase
        .from("profiles")
        .select("id, username, full_name, plan, role, is_admin, show_online_status, last_seen_at")
        .in("id", ids);
      if (pErr) return res.status(500).json({ error: pErr.message || "Erreur lecture profiles" });

      const profById = new Map((profs || []).map((p) => [String(p.id), p]));
      items = filtered
        .map((u) => {
          const p = profById.get(String(u.id));
          if (!p) return null;
          return {
            id: p.id,
            username: p.username || null,
            full_name: p.full_name || null,
            email: u.email || null,
            plan: p.plan || null,
            role: p.role || null,
            is_admin: p.is_admin,
            show_online_status: p.show_online_status,
            last_seen_at: p.last_seen_at,
          };
        })
        .filter(Boolean);
      total = items.length;
      return res.json({ items, total, limit, offset });
    }

    let q = supabase
      .from("profiles")
      .select("id, username, full_name, plan, role, is_admin, show_online_status, last_seen_at", { count: "exact" })
      .order("updated_at", { ascending: false });

    if (search) {
      q = q.or(`username.ilike.%${search}%,full_name.ilike.%${search}%`);
    }

    const { data: profs, error: pErr, count } = await q.range(offset, offset + limit - 1);
    if (pErr) return res.status(500).json({ error: pErr.message || "Erreur lecture profiles" });
    total = typeof count === "number" ? count : null;

    const emailByUserId = {};
    const ids = Array.isArray(profs) ? profs.map((p) => p?.id).filter(Boolean) : [];
    if (ids.length > 0 && supabase?.auth?.admin?.getUserById) {
      await Promise.all(
        ids.map(async (uid) => {
          try {
            const { data: uData, error: uErr } = await supabase.auth.admin.getUserById(uid);
            if (uErr) return;
            const email = String(uData?.user?.email || "").trim();
            if (email) emailByUserId[String(uid)] = email;
          } catch {
            // ignore
          }
        })
      );
    }

    items = (profs || []).map((p) => {
      const pid = p?.id ? String(p.id) : null;
      return {
        id: p.id,
        username: p.username || null,
        full_name: p.full_name || null,
        email: pid ? emailByUserId[pid] || null : null,
        plan: p.plan || null,
        role: p.role || null,
        is_admin: p.is_admin,
        show_online_status: p.show_online_status,
        last_seen_at: p.last_seen_at,
      };
    });

    if (search && !emailSearchMode) {
      const lowered = search.toLowerCase();
      const emailMatched = items.filter((it) => String(it.email || "").toLowerCase().includes(lowered));
      if (emailMatched.length > 0) {
        const mergedById = new Map(items.map((it) => [String(it.id), it]));
        emailMatched.forEach((it) => mergedById.set(String(it.id), it));
        items = Array.from(mergedById.values());
      }
    }

    return res.json({ items, total, limit, offset });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/admin/invites/users-stats", async (req, res) => {
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const period = String(req.query?.period || "30d").toLowerCase();
    const search = String(req.query?.search || "").trim();
    const limitRaw = req.query?.limit;
    const offsetRaw = req.query?.offset;
    const limit = Math.min(Math.max(parseInt(limitRaw, 10) || 20, 1), 50);
    const offset = Math.max(parseInt(offsetRaw, 10) || 0, 0);

    let sinceIso = null;
    if (period === "7d") sinceIso = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    else if (period === "30d") sinceIso = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

    const maxScan = 2000;
    const baseInvQuery = supabase
      .from("invites")
      .select("code, inviter_user_id, created_at")
      .is("revoked_at", null)
      .order("created_at", { ascending: false })
      .limit(search ? maxScan : limit)
      .range(search ? 0 : offset, search ? Math.min(maxScan - 1, maxScan - 1) : offset + limit - 1);

    const { data: invitesRaw, error: invErr } = await baseInvQuery;
    if (invErr) return res.status(500).json({ error: invErr.message || "invite_read_failed" });

    const invites = Array.isArray(invitesRaw) ? invitesRaw : [];
    const inviterIds = Array.from(new Set(invites.map((i) => i?.inviter_user_id).filter(Boolean)));

    const profById = new Map();
    if (inviterIds.length > 0) {
      const { data: profs, error: pErr } = await supabase
        .from("profiles")
        .select("id, username, email")
        .in("id", inviterIds);
      if (pErr) return res.status(500).json({ error: pErr.message || "profiles_read_failed" });
      (profs || []).forEach((p) => profById.set(String(p.id), p));
    }

    let filtered = invites
      .map((i) => {
        const uid = i?.inviter_user_id ? String(i.inviter_user_id) : null;
        const prof = uid ? profById.get(uid) || null : null;
        return {
          code: i?.code || null,
          inviter_user_id: uid,
          created_at: i?.created_at || null,
          username: prof?.username || null,
          email: prof?.email || null,
        };
      })
      .filter((r) => r.code && r.inviter_user_id);

    if (search) {
      const q = search.toLowerCase();
      filtered = filtered.filter((r) => {
        const u = String(r.username || "").toLowerCase();
        const e = String(r.email || "").toLowerCase();
        return u.includes(q) || e.includes(q);
      });
    }

    const count = filtered.length;
    const paged = filtered.slice(offset, offset + limit);
    const events = ["click", "signup", "first_login", "install"];

    const rows = [];
    for (const r of paged) {
      const stats = {};
      for (const ev of events) {
        let q = supabase
          .from("invite_events")
          .select("id", { count: "exact", head: true })
          .eq("code", r.code)
          .eq("event", ev);
        if (sinceIso) q = q.gte("created_at", sinceIso);
        const { count: c, error: cErr } = await q;
        if (cErr) return res.status(500).json({ error: cErr.message || "stats_read_failed" });
        stats[ev] = c || 0;
      }

      let recentQuery = supabase
        .from("invite_events")
        .select("id, event, created_at, user_id, user_username, user_email, meta")
        .eq("code", r.code)
        .order("created_at", { ascending: false })
        .limit(5);
      if (sinceIso) recentQuery = recentQuery.gte("created_at", sinceIso);
      const { data: recent, error: recErr } = await recentQuery;
      if (recErr) return res.status(500).json({ error: recErr.message || "events_read_failed" });

      rows.push({
        ...r,
        stats,
        recent: recent || [],
      });
    }

    return res.json({ rows, count, limit, offset, period });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.patch("/api/admin/users/:id", bodyParser.json(), async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) return res.status(400).json({ error: "id requis" });

    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const planRaw = req.body?.plan;
    const roleRaw = req.body?.role;

    const plan = planRaw != null ? String(planRaw).toLowerCase().trim() : null;
    const role = roleRaw != null ? String(roleRaw).toLowerCase().trim() : null;

    const allowedPlans = ["free", "standard", "vip"];
    const allowedRoles = ["user", "admin", "qrcode_verif"];

    if (plan && !allowedPlans.includes(plan)) {
      return res.status(400).json({ error: "Plan invalide" });
    }
    if (role && !allowedRoles.includes(role)) {
      return res.status(400).json({ error: "Rôle invalide" });
    }

    const updatePayload = {};
    if (plan) updatePayload.plan = plan;
    if (role) {
      updatePayload.role = role;
      updatePayload.is_admin = role === "admin";
    }

    if (Object.keys(updatePayload).length === 0) {
      return res.status(400).json({ error: "Aucune mise à jour" });
    }

    updatePayload.updated_at = new Date().toISOString();

    const { data: updated, error } = await supabase
      .from("profiles")
      .update(updatePayload)
      .eq("id", id)
      .select("id, username, full_name, plan, role, is_admin, show_online_status, last_seen_at")
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message || "Erreur update profil" });
    if (!updated) return res.status(404).json({ error: "Utilisateur introuvable" });

    let email = null;
    if (supabase?.auth?.admin?.getUserById) {
      try {
        const { data: uData, error: uErr } = await supabase.auth.admin.getUserById(updated.id);
        if (!uErr) email = String(uData?.user?.email || "").trim() || null;
      } catch {
        // ignore
      }
    }

    return res.json({
      item: {
        ...updated,
        email,
      },
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/admin/market/partners", async (req, res) => {
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const statusFilter = req.query.status ? String(req.query.status).trim().toLowerCase() : "";
    const search = req.query.search ? String(req.query.search).trim() : "";
    const limitRaw = req.query.limit;
    const offsetRaw = req.query.offset;
    const limit = Math.min(Math.max(parseInt(limitRaw, 10) || 50, 1), 200);
    const offset = Math.max(parseInt(offsetRaw, 10) || 0, 0);

    let q = supabase
      .from("partners_market")
      .select(
        "id, owner_user_id, display_name, category, base_currency, status, payout_status, is_open, logo_url, created_at, updated_at",
        { count: "exact" }
      )
      .order("created_at", { ascending: false });

    if (statusFilter && ["pending", "approved", "rejected"].includes(statusFilter)) {
      q = q.eq("status", statusFilter);
    }

    if (search) {
      q = q.ilike("display_name", `%${search}%`);
    }

    const { data: rows, error, count } = await q.range(offset, offset + limit - 1);
    if (error) return res.status(500).json({ error: error.message || "Erreur lecture boutiques" });

    const ownerIds = Array.isArray(rows)
      ? Array.from(new Set(rows.map((r) => r?.owner_user_id).filter(Boolean)))
      : [];

    const ownersById = new Map();
    if (ownerIds.length > 0) {
      const { data: owners, error: oErr } = await supabase.from("profiles").select("id, username, email").in("id", ownerIds);
      if (!oErr && Array.isArray(owners)) {
        owners.forEach((o) => ownersById.set(o.id, o));
      }
    }

    const partners = (rows || []).map((p) => {
      const owner = ownersById.get(p.owner_user_id) || null;
      return {
        ...p,
        owner_username: owner?.username || null,
        owner_email: owner?.email || null,
      };
    });

    return res.json({ partners, count: typeof count === "number" ? count : null, limit, offset });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.patch("/api/admin/market/partners/:partnerId", bodyParser.json(), async (req, res) => {
  try {
    const { partnerId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const patch = req.body || {};
    const update = {
      updated_at: new Date().toISOString(),
    };

    if (patch.status !== undefined) {
      const st = String(patch.status || "").trim().toLowerCase();
      if (!["pending", "approved", "rejected"].includes(st)) {
        return res.status(400).json({ error: "invalid_status" });
      }
      update.status = st;
    }

    if (patch.is_open !== undefined) {
      update.is_open = patch.is_open === true;
    }

    if (Object.keys(update).length === 1) {
      return res.status(400).json({ error: "nothing_to_update" });
    }

    const { error } = await supabase.from("partners_market").update(update).eq("id", partnerId);
    if (error) return res.status(500).json({ error: error.message || "Erreur mise à jour boutique" });
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.delete("/api/admin/market/partners/:partnerId", async (req, res) => {
  try {
    const { partnerId } = req.params;
    if (!partnerId) return res.status(400).json({ error: "partnerId requis" });

    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { data: orders, error: oErr } = await supabase.from("partner_orders").select("id").eq("partner_id", partnerId).limit(5000);
    if (oErr) return res.status(500).json({ error: oErr.message || "Erreur lecture commandes" });

    const orderIds = Array.isArray(orders) ? orders.map((o) => o.id).filter(Boolean) : [];
    if (orderIds.length > 0) {
      const { error: delOrderItemsErr } = await supabase.from("partner_order_items").delete().in("order_id", orderIds);
      if (delOrderItemsErr) return res.status(500).json({ error: delOrderItemsErr.message || "Erreur suppression lignes commande" });

      const { error: delOrderPaysErr } = await supabase.from("partner_order_payments").delete().in("order_id", orderIds);
      if (delOrderPaysErr) return res.status(500).json({ error: delOrderPaysErr.message || "Erreur suppression paiements commande" });

      const { error: delOrdersErr } = await supabase.from("partner_orders").delete().in("id", orderIds);
      if (delOrdersErr) return res.status(500).json({ error: delOrdersErr.message || "Erreur suppression commandes" });
    }

    const { error: delItemsErr } = await supabase.from("partner_items").delete().eq("partner_id", partnerId);
    if (delItemsErr) return res.status(500).json({ error: delItemsErr.message || "Erreur suppression produits" });

    const { error: delPartnerErr } = await supabase.from("partners_market").delete().eq("id", partnerId);
    if (delPartnerErr) return res.status(500).json({ error: delPartnerErr.message || "Erreur suppression boutique" });

    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/admin/market/partners/performance", async (req, res) => {
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const period = req.query.period ? String(req.query.period).trim().toLowerCase() : "30d";
    const currencyFilter = req.query.currency ? String(req.query.currency).trim().toUpperCase() : "ALL";
    const search = req.query.search ? String(req.query.search).trim() : "";
    const includeEmpty =
      req.query.includeEmpty === true ||
      req.query.includeEmpty === "true" ||
      req.query.includeEmpty === "1";
    const limitRaw = req.query.limit;
    const offsetRaw = req.query.offset;
    const limit = Math.min(Math.max(parseInt(limitRaw, 10) || 50, 1), 200);
    const offset = Math.max(parseInt(offsetRaw, 10) || 0, 0);

    const now = Date.now();
    const daysByPeriod = { "7d": 7, "30d": 30, "90d": 90, "365d": 365 };
    const days = daysByPeriod[period] || null;
    const sinceIso = days ? new Date(now - days * 24 * 60 * 60 * 1000).toISOString() : null;

    const maxRows = 10000;
    const pageSize = 1000;
    let fetched = 0;
    let pageOffset = 0;
    let paidOrders = [];

    while (fetched < maxRows) {
      let q = supabase
        .from("partner_orders")
        .select("id, partner_id, status, charge_currency, charge_amount_total, updated_at, created_at")
        .eq("status", "paid")
        .order("created_at", { ascending: false })
        .range(pageOffset, pageOffset + pageSize - 1);

      if (sinceIso) q = q.gte("created_at", sinceIso);
      if (currencyFilter && currencyFilter !== "ALL") q = q.eq("charge_currency", currencyFilter);

      const { data, error } = await q;
      if (error) return res.status(500).json({ error: error.message || "Erreur lecture commandes" });

      const rows = Array.isArray(data) ? data : [];
      if (rows.length === 0) break;
      paidOrders = paidOrders.concat(rows);
      fetched += rows.length;
      if (rows.length < pageSize) break;
      pageOffset += pageSize;
    }

    const statsByKey = new Map();
    const partnerIds = new Set();

    paidOrders.forEach((o) => {
      const pid = o?.partner_id ? String(o.partner_id) : null;
      const cur = o?.charge_currency ? String(o.charge_currency).toUpperCase() : null;
      const amt = Number(o?.charge_amount_total || 0);
      if (!pid || !cur || !Number.isFinite(amt)) return;

      partnerIds.add(pid);
      const key = `${pid}::${cur}`;
      const existing = statsByKey.get(key) || {
        partner_id: pid,
        currency: cur,
        orders_paid_count: 0,
        revenue_charge_total_minor: 0,
        last_paid_at: null,
      };

      existing.orders_paid_count += 1;
      existing.revenue_charge_total_minor += amt;

      const ts = o?.updated_at || o?.created_at || null;
      if (ts && (!existing.last_paid_at || String(ts) > String(existing.last_paid_at))) {
        existing.last_paid_at = ts;
      }

      statsByKey.set(key, existing);
    });

    const partnerIdList = Array.from(partnerIds);
    const partnerById = new Map();
    if (partnerIdList.length > 0) {
      const { data: partners, error: pErr } = await supabase
        .from("partners_market")
        .select("id, display_name, base_currency")
        .in("id", partnerIdList);
      if (pErr) return res.status(500).json({ error: pErr.message || "Erreur lecture boutiques" });
      (partners || []).forEach((p) => partnerById.set(String(p.id), p));
    }

    let allPartnersById = null;
    if (includeEmpty) {
      let pq = supabase.from("partners_market").select("id, display_name, base_currency, created_at");
      if (search) pq = pq.ilike("display_name", `%${search}%`);

      const { data: allPartners, error: apErr } = await pq.order("created_at", { ascending: false }).limit(2000);
      if (apErr) return res.status(500).json({ error: apErr.message || "Erreur lecture boutiques" });

      allPartnersById = new Map();
      (allPartners || []).forEach((p) => allPartnersById.set(String(p.id), p));
    }

    let rows = Array.from(statsByKey.values()).map((r) => {
      const p = partnerById.get(String(r.partner_id)) || null;
      const avg = r.orders_paid_count > 0 ? Math.round(r.revenue_charge_total_minor / r.orders_paid_count) : 0;
      return {
        ...r,
        avg_basket_minor: avg,
        partner_display_name: p?.display_name || null,
        partner_base_currency: p?.base_currency || null,
      };
    });

    if (search) {
      const searchLower = search.toLowerCase();
      rows = rows.filter((r) => String(r.partner_display_name || "").toLowerCase().includes(searchLower));
    }

    if (includeEmpty && allPartnersById) {
      allPartnersById.forEach((p) => {
        const pid = String(p.id);
        if (currencyFilter && currencyFilter !== "ALL") {
          const key = `${pid}::${currencyFilter}`;
          if (!statsByKey.has(key)) {
            rows.push({
              partner_id: pid,
              currency: currencyFilter,
              orders_paid_count: 0,
              revenue_charge_total_minor: 0,
              last_paid_at: null,
              avg_basket_minor: 0,
              partner_display_name: p.display_name || null,
              partner_base_currency: p.base_currency || null,
            });
          }
          return;
        }

        const baseCur = p.base_currency ? String(p.base_currency).toUpperCase() : "";
        const cur = baseCur || "EUR";
        const key = `${pid}::${cur}`;
        const exists = rows.some((r) => String(r.partner_id) === pid);
        if (!exists) {
          rows.push({
            partner_id: pid,
            currency: cur,
            orders_paid_count: 0,
            revenue_charge_total_minor: 0,
            last_paid_at: null,
            avg_basket_minor: 0,
            partner_display_name: p.display_name || null,
            partner_base_currency: p.base_currency || null,
          });
        }
      });
    }

    rows.sort((a, b) => {
      const da = Number(a.revenue_charge_total_minor || 0);
      const db = Number(b.revenue_charge_total_minor || 0);
      return db - da;
    });

    const paged = rows.slice(offset, offset + limit);
    return res.json({ rows: paged, count: rows.length, limit, offset, period, currency: currencyFilter });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/api/admin/moderation/warn", async (req, res) => {
  let actionId = null;
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const { targetUserId, contentType, contentId, reason, message } = req.body || {};
    if (!targetUserId || !contentType || !contentId || !reason || !message) {
      return res.status(400).json({ error: "targetUserId, contentType, contentId, reason, message requis" });
    }

    const typeNorm = String(contentType).toLowerCase();
    if (!["post", "audio_post"].includes(typeNorm)) {
      return res.status(400).json({ error: "contentType invalide" });
    }

    const { data: targetProfile, error: tErr } = await supabase
      .from("profiles")
      .select("id, username, email")
      .eq("id", targetUserId)
      .maybeSingle();
    if (tErr || !targetProfile) return res.status(404).json({ error: "target_not_found" });

    const notifTitle = "Avertissement de modération";
    const notifMessage = `${reason}: ${message}`;

    const pushResult = await sendSupabaseLightPush({
      title: notifTitle,
      message: notifMessage,
      targetUserIds: [targetUserId],
      url: "/echange",
      data: {
        type: "moderation_warning",
        contentType: typeNorm,
        contentId: String(contentId),
        senderId: guard.userId,
        reason,
      },
    });

    let emailSent = false;
    let emailError = null;
    if (targetProfile.email) {
      try {
        const subject = "Avertissement de modération - OneKamer";
        const body = `Bonjour ${targetProfile.username || "membre"},\n\nMotif : ${reason}\n\nMessage :\n${message}\n\n— L'équipe OneKamer`;
        await sendEmailViaBrevo({ to: targetProfile.email, subject, text: body });
        emailSent = true;
      } catch (e) {
        emailError = e?.message || "Erreur envoi email";
      }
    }

    const notificationSent = !!pushResult?.success;
    const deliveryError = emailError || (!notificationSent ? String(pushResult?.reason || "push_failed") : null);

    const { data: inserted, error: insErr } = await supabase
      .from("admin_moderation_actions")
      .insert({
        admin_user_id: guard.userId,
        admin_username: guard.adminUsername,
        target_user_id: targetUserId,
        target_username: targetProfile.username || null,
        content_type: typeNorm,
        content_id: String(contentId),
        action_type: "warning",
        reason: String(reason),
        message: String(message),
        email_sent: emailSent,
        notification_sent: notificationSent,
        delivery_error: deliveryError,
        meta: {},
      })
      .select("id")
      .maybeSingle();
    if (insErr) return res.status(500).json({ error: insErr.message || "Erreur insertion historique" });

    actionId = inserted?.id || null;

    return res.json({ success: true, actionId, emailSent, notificationSent, deliveryError });
  } catch (e) {
    console.error("❌ POST /api/admin/moderation/warn:", e);
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.get("/api/admin/moderation/actions", async (req, res) => {
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const limitRaw = req.query?.limit;
    const offsetRaw = req.query?.offset;
    const targetUserId = req.query?.targetUserId;
    const contentType = req.query?.contentType;

    const limit = Math.max(1, Math.min(parseInt(limitRaw || "50", 10) || 50, 200));
    const offset = Math.max(0, parseInt(offsetRaw || "0", 10) || 0);

    let q = supabase
      .from("admin_moderation_actions")
      .select("*")
      .order("created_at", { ascending: false });

    if (targetUserId) q = q.eq("target_user_id", targetUserId);
    if (contentType) q = q.eq("content_type", String(contentType).toLowerCase());

    q = q.range(offset, offset + limit - 1);

    const { data, error } = await q;
    if (error) return res.status(500).json({ error: error.message || "Erreur lecture historique" });

    return res.json({ items: data || [], limit, offset });
  } catch (e) {
    console.error("❌ GET /api/admin/moderation/actions:", e);
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.delete("/api/admin/echange/posts/:postId", async (req, res) => {
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const postId = req.params.postId;
    if (!postId) return res.status(400).json({ error: "postId requis" });

    await supabase.from("likes").delete().eq("content_type", "post").eq("content_id", postId);
    await supabase.from("comments").delete().eq("content_type", "post").eq("content_id", postId);

    const { error: delErr } = await supabase.from("posts").delete().eq("id", postId);
    if (delErr) return res.status(500).json({ error: delErr.message });

    return res.json({ deleted: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.delete("/api/admin/echange/audio/:commentId", async (req, res) => {
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const commentId = req.params.commentId;
    if (!commentId) return res.status(400).json({ error: "commentId requis" });

    const { data: row, error: getErr } = await supabase
      .from("comments")
      .select("id")
      .eq("id", commentId)
      .eq("content_type", "echange")
      .maybeSingle();
    if (getErr) return res.status(500).json({ error: getErr.message });
    if (!row) return res.status(404).json({ error: "not_found" });

    const { error: delErr } = await supabase
      .from("comments")
      .delete()
      .eq("id", commentId)
      .eq("content_type", "echange");
    if (delErr) return res.status(500).json({ error: delErr.message });

    return res.json({ deleted: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.delete("/api/admin/annonces/:annonceId", async (req, res) => {
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const annonceId = req.params.annonceId;
    if (!annonceId) return res.status(400).json({ error: "annonceId requis" });

    const { error: favErr } = await supabase
      .from("favorites")
      .delete()
      .eq("content_type", "annonce")
      .eq("content_id", annonceId);
    if (favErr) console.warn("[admin annonces delete] favorites delete warning:", favErr.message);

    const { error: delErr } = await supabase.from("annonces").delete().eq("id", annonceId);
    if (delErr) return res.status(500).json({ error: delErr.message });

    return res.json({ deleted: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.patch("/api/admin/annonces/:annonceId", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const annonceId = req.params.annonceId;
    if (!annonceId) return res.status(400).json({ error: "annonceId requis" });

    const patch = req.body || {};
    const update = {
      updated_at: new Date().toISOString(),
    };

    const allowedFields = [
      "titre",
      "categorie_id",
      "prix",
      "devise_id",
      "pays_id",
      "ville_id",
      "telephone",
      "email",
      "description",
      "media_url",
      "media_type",
    ];

    allowedFields.forEach((k) => {
      if (patch[k] !== undefined) update[k] = patch[k];
    });

    if (Object.keys(update).length === 1) {
      return res.status(400).json({ error: "nothing_to_update" });
    }

    const { error } = await supabase.from("annonces").update(update).eq("id", annonceId);
    if (error) return res.status(500).json({ error: error.message || "Erreur mise à jour annonce" });

    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.delete("/api/admin/evenements/:eventId", async (req, res) => {
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const eventId = req.params.eventId;
    if (!eventId) return res.status(400).json({ error: "eventId requis" });

    const { error: favErr } = await supabase
      .from("favorites")
      .delete()
      .eq("content_type", "evenement")
      .eq("content_id", eventId);
    if (favErr) console.warn("[admin evenements delete] favorites delete warning:", favErr.message);

    const { error: delErr } = await supabase.from("evenements").delete().eq("id", eventId);
    if (delErr) return res.status(500).json({ error: delErr.message });

    return res.json({ deleted: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.patch("/api/admin/evenements/:eventId", bodyParser.json(), async (req, res) => {
  try {
    const guard = await requireAdminIsAdmin(req);
    if (!guard.ok) return res.status(guard.status).json({ error: guard.error });

    const eventId = req.params.eventId;
    if (!eventId) return res.status(400).json({ error: "eventId requis" });

    const patch = req.body || {};
    const update = {
      updated_at: new Date().toISOString(),
    };

    const allowedFields = [
      "title",
      "date",
      "time",
      "location",
      "price",
      "type_id",
      "telephone",
      "email",
      "site_web",
      "organisateur",
      "latitude",
      "longitude",
      "devise_id",
      "media_url",
      "media_type",
    ];

    allowedFields.forEach((k) => {
      if (patch[k] !== undefined) update[k] = patch[k];
    });

    if (Object.keys(update).length === 1) {
      return res.status(400).json({ error: "nothing_to_update" });
    }

    const { error } = await supabase.from("evenements").update(update).eq("id", eventId);
    if (error) return res.status(500).json({ error: error.message || "Erreur mise à jour événement" });

    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// ============================================================
// 2bis️⃣ Création de session Stripe - Paiement Évènement (full / deposit)
// ============================================================

app.post("/api/events/:eventId/checkout", async (req, res) => {
  const { eventId } = req.params;

  try {
    const authHeader = req.headers["authorization"] || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: "unauthorized" });

    const supabaseAuth = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
    const { data: userData, error: userErr } = await supabaseAuth.auth.getUser(token);
    if (userErr || !userData?.user) return res.status(401).json({ error: "invalid_token" });

    const userId = userData.user.id;
    const { payment_mode } = req.body || {};
    const paymentMode = payment_mode === "deposit" ? "deposit" : "full";

    if (!eventId) return res.status(400).json({ error: "eventId requis" });

    const { data: ev, error: evErr } = await supabase
      .from("evenements")
      .select("id, title, price_amount, currency, deposit_percent")
      .eq("id", eventId)
      .maybeSingle();
    if (evErr) throw new Error(evErr.message);
    if (!ev) return res.status(404).json({ error: "event_not_found" });

    const amountTotal = typeof ev.price_amount === "number" ? ev.price_amount : 0;
    const currency = ev.currency ? String(ev.currency).toLowerCase() : null;
    const depositPercent = typeof ev.deposit_percent === "number" ? ev.deposit_percent : null;

    if (!currency || !["eur", "usd", "cad", "xaf"].includes(currency)) {
      return res.status(400).json({ error: "currency_invalid" });
    }
    if (!amountTotal || amountTotal <= 0) {
      return res.status(400).json({ error: "event_not_payable" });
    }

    const { data: pay, error: payErr } = await supabase
      .from("event_payments")
      .select("amount_total, amount_paid, status")
      .eq("event_id", eventId)
      .eq("user_id", userId)
      .maybeSingle();
    if (payErr) throw new Error(payErr.message);

    const alreadyPaid = typeof pay?.amount_paid === "number" ? pay.amount_paid : 0;
    const remaining = Math.max(amountTotal - alreadyPaid, 0);
    if (remaining <= 0) {
      return res.status(200).json({ alreadyPaid: true, message: "Déjà payé" });
    }

    let amountToPay = remaining;
    if (paymentMode === "deposit") {
      if (!depositPercent || depositPercent <= 0) {
        return res.status(400).json({ error: "deposit_not_enabled" });
      }
      const depositAmount = Math.max(1, Math.round((amountTotal * depositPercent) / 100));
      amountToPay = Math.min(depositAmount, remaining);
    }

    const { error: upErr } = await supabase
      .from("event_payments")
      .upsert(
        {
          event_id: eventId,
          user_id: userId,
          status: pay?.status || "unpaid",
          amount_total: amountTotal,
          amount_paid: alreadyPaid,
          currency,
          updated_at: new Date().toISOString(),
        },
        { onConflict: "event_id,user_id" }
      );
    if (upErr) throw new Error(upErr.message);

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency,
            product_data: { name: `Billet - ${ev.title || "Évènement"}` },
            unit_amount: amountToPay,
          },
          quantity: 1,
        },
      ],
      success_url: `${process.env.FRONTEND_URL}/paiement-success?eventId=${eventId}`,
      cancel_url: `${process.env.FRONTEND_URL}/paiement-annule?eventId=${eventId}`,
      metadata: { userId, eventId, paymentMode },
    });

    const { error: updSessionErr } = await supabase
      .from("event_payments")
      .update({ stripe_checkout_session_id: session.id, updated_at: new Date().toISOString() })
      .eq("event_id", eventId)
      .eq("user_id", userId);
    if (updSessionErr) throw new Error(updSessionErr.message);

    await logEvent({
      category: "event_payment",
      action: "checkout.create",
      status: "success",
      userId,
      context: { eventId, paymentMode, amountToPay, amountTotal, currency, session_id: session.id },
    });

    return res.json({ url: session.url });
  } catch (e) {
    console.error("❌ POST /api/events/:eventId/checkout:", e);
    await logEvent({
      category: "event_payment",
      action: "checkout.create",
      status: "error",
      userId: null,
      context: { eventId: req.params?.eventId || null, error: e?.message || String(e) },
    });
    return res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

app.post("/create-checkout-session", async (req, res) => {
  const { packId, userId } = req.body;

  try {
    if (!packId || !userId) {
      await logEvent({
        category: "okcoins",
        action: "checkout.create",
        status: "error",
        userId,
        context: { reason: "missing packId or userId" },
      });
      return res.status(400).json({ error: "packId et userId sont requis" });
    }

    // Récupère les infos du pack dans Supabase
    const { data: pack, error: packErr } = await supabase
      .from("okcoins_packs")
      .select("pack_name, price_eur, is_active")
      .eq("id", packId)
      .single();

    if (packErr || !pack || !pack.is_active) {
      await logEvent({
        category: "okcoins",
        action: "checkout.create",
        status: "error",
        userId,
        context: { packId, error: packErr?.message || "Pack introuvable ou inactif" },
      });
      return res.status(404).json({ error: "Pack introuvable ou inactif" });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "eur",
            product_data: { name: pack.pack_name },
            unit_amount: Math.round(Number(pack.price_eur) * 100),
          },
          quantity: 1,
        },
      ],
      success_url: `${process.env.FRONTEND_URL}/paiement-success?packId=${packId}`,
      cancel_url: `${process.env.FRONTEND_URL}/paiement-annule`,
      metadata: { userId, packId: String(packId) },
    });

    await logEvent({
      category: "okcoins",
      action: "checkout.create",
      status: "success",
      userId,
      context: { packId, session_id: session.id },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("❌ Erreur création session Stripe :", err);
    await logEvent({
      category: "okcoins",
      action: "checkout.create",
      status: "error",
      userId: req.body?.userId || null,
      context: { packId: req.body?.packId, error: err?.message || err },
    });
    res.status(500).json({ error: "Erreur serveur interne" });
  }
});

// ============================================================
// 3️⃣ Création de session Stripe - Abonnements
// ============================================================

app.post("/create-subscription-session", async (req, res) => {
  const { userId, planKey, priceId, promoCode } = req.body;

  try {
    if (!userId || !planKey) {
      await logEvent({
        category: "subscription",
        action: "checkout.subscription.create",
        status: "error",
        userId,
        context: { reason: "missing userId or planKey" },
      });
      return res.status(400).json({ error: "userId et planKey sont requis" });
    }

    let finalPriceId = priceId;
    let promotionCodeId = null;

    if (!finalPriceId) {
      const { data: plan, error: planErr } = await supabase
        .from("pricing_plans")
        .select("stripe_price_id")
        .eq("key", planKey)
        .maybeSingle();
      if (planErr || !plan) {
        await logEvent({
          category: "subscription",
          action: "checkout.subscription.create",
          status: "error",
          userId,
          context: { planKey, error: planErr?.message || "Impossible de trouver le plan Stripe ID" },
        });
        throw new Error("Impossible de trouver le plan Stripe ID");
      }
      finalPriceId = plan.stripe_price_id;
    }

    const isVip = planKey === "vip";

    if (promoCode) {
      try {
        const normalizedCode = String(promoCode).trim();
        if (normalizedCode) {
          const { data: promo, error: promoErr } = await supabase
            .from("promo_codes")
            .select("id, code, stripe_promotion_code_id, actif, date_debut, date_fin")
            .eq("code", normalizedCode)
            .maybeSingle();

          if (promoErr) {
            await logEvent({
              category: "promo",
              action: "checkout.lookup",
              status: "error",
              userId,
              context: { promoCode: normalizedCode, error: promoErr.message },
            });
            return res.status(400).json({ error: "Code promo invalide" });
          }

          if (!promo || promo.actif === false) {
            return res.status(400).json({ error: "Code promo inactif ou introuvable" });
          }

          const now = new Date();
          const startOk = !promo.date_debut || new Date(promo.date_debut) <= now;
          const endOk = !promo.date_fin || new Date(promo.date_fin) >= now;

          if (!startOk || !endOk) {
            return res.status(400).json({ error: "Code promo expiré ou non encore valide" });
          }

          if (promo.stripe_promotion_code_id) {
            promotionCodeId = promo.stripe_promotion_code_id;
          }
        }
      } catch (e) {
        console.error("❌ Erreur validation promoCode:", e?.message || e);
        await logEvent({
          category: "promo",
          action: "checkout.exception",
          status: "error",
          userId,
          context: { promoCode, error: e?.message || String(e) },
        });
        return res.status(400).json({ error: "Code promo invalide" });
      }
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: finalPriceId, quantity: 1 }],
      allow_promotion_codes: true,
      success_url: `${process.env.FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/cancel`,
      metadata: {
        userId,
        planKey,
        ...(promoCode && { promoCode: String(promoCode).trim() }),
      },
      ...(promotionCodeId && {
        discounts: [
          {
            promotion_code: promotionCodeId,
          },
        ],
      }),
      ...(isVip && {
        subscription_data: {
          trial_period_days: 30,
        },
      }),
    });

    await logEvent({
      category: "subscription",
      action: "checkout.subscription.create",
      status: "success",
      userId,
      context: { planKey, price_id: finalPriceId, session_id: session.id },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("❌ Erreur création session abonnement :", err);
    await logEvent({
      category: "subscription",
      action: "checkout.subscription.create",
      status: "error",
      userId: req.body?.userId || null,
      context: { planKey: req.body?.planKey, error: err?.message || err },
    });
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// 4️⃣ Activation du plan gratuit
// ============================================================

app.post("/activate-free-plan", async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) {
      await logEvent({
        category: "profile",
        action: "plan.free.activate",
        status: "error",
        context: { reason: "missing userId" },
      });
      return res.status(400).json({ error: "userId requis" });
    }

    const { error: rpcErr } = await supabase.rpc("apply_plan_to_profile", {
      p_user_id: userId,
      p_plan_key: "free",
    });
    if (rpcErr) {
      await logEvent({
        category: "profile",
        action: "plan.free.apply",
        status: "error",
        userId,
        context: { error: rpcErr.message },
      });
      throw new Error(rpcErr.message);
    }

    const { error: insertErr } = await supabase.from("abonnements").insert({
      profile_id: userId,
      plan_name: "Gratuit",
      status: "active",
      auto_renew: false,
    });
    if (insertErr) {
      await logEvent({
        category: "profile",
        action: "plan.free.insert",
        status: "error",
        userId,
        context: { error: insertErr.message },
      });
      throw new Error(insertErr.message);
    }

    await logEvent({
      category: "profile",
      action: "plan.free.activated",
      status: "success",
      userId,
      context: {},
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("❌ Erreur activation plan gratuit :", e);
    await logEvent({
      category: "profile",
      action: "plan.free.activate",
      status: "error",
      userId: req?.body?.userId || null,
      context: { error: e?.message || e },
    });
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// 5️⃣ Notification Telegram - Retrait OK COINS
// ============================================================

app.post("/notify-withdrawal", async (req, res) => {
  const { userId, username, email, amount } = req.body;

  if (!userId || !username || !email || !amount) {
    await logEvent({
      category: "withdrawal",
      action: "email.notify",
      status: "error",
      userId: userId || null,
      context: { reason: "missing fields", body: req.body },
    });
    return res.status(400).json({ error: "Informations incomplètes pour la notification." });
  }

  try {
    const numericAmount = Number(amount);
    const safeAmount = Number.isFinite(numericAmount) ? numericAmount : 0;
    const withdrawalEmail = process.env.WITHDRAWAL_ALERT_EMAIL || "contact@onekamer.co";

    const text = [
      "Nouvelle demande de retrait OK COINS",
      "",
      `Utilisateur : ${username}`,
      `Email : ${email}`,
      `ID utilisateur : ${userId}`,
      `Montant demandé : ${safeAmount.toLocaleString("fr-FR")} pièces`,
      `Date : ${new Date().toLocaleString("fr-FR")}`,
      "",
      "— Notification automatique OneKamer.co",
    ].join("\n");

    await sendEmailViaBrevo({
      to: withdrawalEmail,
      subject: "Nouvelle demande de retrait OK COINS",
      text,
    });

    console.log("📧 Notification retrait OK COINS envoyée par email.");
    await logEvent({
      category: "withdrawal",
      action: "email.notify",
      status: "success",
      userId,
      context: { to: withdrawalEmail, amount: safeAmount },
    });

    // 🔔 Notification push admin (système natif supabase_light)
    await sendAdminWithdrawalPush(req, { username, amount: safeAmount });

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Erreur notification retrait par email :", err);
    await logEvent({
      category: "withdrawal",
      action: "email.notify",
      status: "error",
      userId,
      context: { error: err?.message || err },
    });
    res.status(500).json({ error: "Échec notification email" });
  }
});

// ============================================================
// 8️⃣ Emails admin (LAB) - email_jobs
// ============================================================

function assertAdmin(req) {
  const token = req.headers["x-admin-token"];
  if (!token || token !== process.env.ADMIN_API_TOKEN) {
    const err = new Error("Accès refusé (admin token invalide)");
    err.statusCode = 401;
    throw err;
  }
}

function buildInfoAllBody({ username, message }) {
  const safeName = username || "membre";
  return `Bonjour ${safeName},\n\n${message}\n\n— L'équipe OneKamer`;
}

app.options("/admin/email/enqueue-info-all-users", cors());
app.options("/admin/email/process-jobs", cors());
app.options("/admin/email/count-segment", cors());

app.post("/admin/email/enqueue-info-all-users", cors(), async (req, res) => {
  try {
    assertAdmin(req);

    const { subject, message, limit, emails, segment } = req.body || {};
    if (!subject || !message) {
      return res.status(400).json({ error: "subject et message sont requis" });
    }

    // Option 1: liste d'emails explicite fournie dans le body
    if (Array.isArray(emails) && emails.length > 0) {
      const cleanEmails = emails
        .map((e) => (typeof e === "string" ? e.trim() : ""))
        .filter((e) => e.length > 0);

      if (cleanEmails.length === 0) {
        return res.json({ inserted: 0, message: "Aucune adresse email valide dans emails[]" });
      }

      // ✅ On essaie de retrouver les usernames correspondants pour personnaliser "Bonjour {username}"
      const emailUsernameMap = new Map();
      const { data: profilesByEmail, error: profilesByEmailErr } = await supabase
        .from("profiles")
        .select("email, username")
        .in("email", cleanEmails);

      if (profilesByEmailErr) {
        console.error("⚠️ Erreur lecture profiles pour emails explicites:", profilesByEmailErr.message);
      } else if (profilesByEmail && profilesByEmail.length > 0) {
        for (const p of profilesByEmail) {
          if (p.email) {
            emailUsernameMap.set(p.email, p.username || null);
          }
        }
      }

      const rows = cleanEmails.map((email) => ({
        status: "pending",
        type: "info_all_users",
        to_email: email,
        subject,
        template: "INFO_ALL",
        payload: {
          user_id: null,
          username: emailUsernameMap.get(email) || null,
          message,
        },
      }));

      const { error: insertErr } = await supabase.from("email_jobs").insert(rows);
      if (insertErr) {
        console.error("❌ Erreur insert email_jobs (emails explicites):", insertErr.message);
        return res.status(500).json({ error: "Erreur création jobs" });
      }

      return res.json({ inserted: rows.length, mode: "explicit_emails" });
    }

    // Option 2: comportement basé sur la table profiles, avec ciblage éventuel par plan
    const max = typeof limit === "number" && limit > 0 ? Math.min(limit, 1000) : 500;

    let profilesQuery = supabase
      .from("profiles")
      .select("id, email, username, plan")
      .not("email", "is", null);

    const normalizedSegment = (segment || "all").toString().toLowerCase();
    if (["free", "standard", "vip"].includes(normalizedSegment)) {
      profilesQuery = profilesQuery.eq("plan", normalizedSegment);
    }

    profilesQuery = profilesQuery.limit(max);

    const { data: profiles, error } = await profilesQuery;

    if (error) {
      console.error("❌ Erreur lecture profiles pour email_jobs:", error.message);
      return res.status(500).json({ error: "Erreur lecture profils" });
    }

    if (!profiles || profiles.length === 0) {
      return res.json({ inserted: 0, message: "Aucun profil avec email" });
    }

    const rows = profiles.map((p) => ({
      status: "pending",
      type: "info_all_users",
      to_email: p.email,
      subject,
      template: "INFO_ALL",
      payload: {
        user_id: p.id,
        username: p.username,
        message,
      },
    }));

    const { error: insertErr } = await supabase.from("email_jobs").insert(rows);
    if (insertErr) {
      console.error("❌ Erreur insert email_jobs:", insertErr.message);
      return res.status(500).json({ error: "Erreur création jobs" });
    }

    res.json({ inserted: rows.length, mode: normalizedSegment });
  } catch (e) {
    const status = e.statusCode || 500;
    console.error("❌ /admin/email/enqueue-info-all-users:", e);
    res.status(status).json({ error: e.message || "Erreur interne" });
  }
});

app.post("/admin/email/count-segment", cors(), async (req, res) => {
  try {
    assertAdmin(req);

    const { segment } = req.body || {};
    const normalizedSegment = (segment || "all").toString().toLowerCase();

    let profilesQuery = supabase
      .from("profiles")
      .select("id", { count: "exact", head: true })
      .not("email", "is", null);

    if (["free", "standard", "vip"].includes(normalizedSegment)) {
      profilesQuery = profilesQuery.eq("plan", normalizedSegment);
    }

    const { count, error } = await profilesQuery;

    if (error) {
      console.error("❌ /admin/email/count-segment:", error.message);
      return res.status(500).json({ error: "Erreur lecture profils" });
    }

    res.json({ segment: normalizedSegment, count: count || 0 });
  } catch (e) {
    const status = e.statusCode || 500;
    console.error("❌ /admin/email/count-segment (handler):", e);
    res.status(status).json({ error: e.message || "Erreur interne" });
  }
});

app.post("/admin/email/process-jobs", cors(), async (req, res) => {
  try {
    assertAdmin(req);

    const { limit } = req.body || {};
    const max = typeof limit === "number" && limit > 0 ? Math.min(limit, 100) : 50;

    const { data: jobs, error } = await supabase
      .from("email_jobs")
      .select("id, to_email, subject, template, payload")
      .eq("status", "pending")
      .order("created_at", { ascending: true })
      .limit(max);

    if (error) {
      console.error("❌ Erreur lecture email_jobs:", error.message);
      return res.status(500).json({ error: "Erreur lecture jobs" });
    }

    if (!jobs || jobs.length === 0) {
      return res.json({ processed: 0, message: "Aucun job pending" });
    }

    console.log("📧 /admin/email/process-jobs → récupération", jobs.length, "jobs pending");

    let sentCount = 0;
    const errors = [];

    for (const job of jobs) {
      try {
        let textBody = "";
        if (job.template === "INFO_ALL") {
          textBody = buildInfoAllBody({
            username: job.payload?.username,
            message: job.payload?.message,
          });
        } else {
          textBody = job.payload?.message || "";
        }

        console.log("📧 Envoi email job", job.id, "→", job.to_email);

        // Envoi via Brevo HTTP API (ou fallback SMTP interne si BREVO_API_KEY manquante)
        await sendEmailViaBrevo({
          to: job.to_email,
          subject: job.subject,
          text: textBody,
        });

        console.log("✅ Email envoyé job", job.id);

        sentCount += 1;

        await supabase
          .from("email_jobs")
          .update({ status: "sent", updated_at: new Date().toISOString() })
          .eq("id", job.id);
      } catch (err) {
        console.error("❌ Erreur envoi email pour job", job.id, ":", err.message);
        errors.push({ id: job.id, error: err.message });
        await supabase
          .from("email_jobs")
          .update({
            status: "failed",
            updated_at: new Date().toISOString(),
            error_message: err.message,
          })
          .eq("id", job.id);
      }
    } // <--- Added closing bracket here
    console.log("📧 /admin/email/process-jobs terminé →", {
      processed: jobs.length,
      sent: sentCount,
      errorsCount: errors.length,
    });

    res.json({ processed: jobs.length, sent: sentCount, errors });
  } catch (e) {
    const status = e.statusCode || 500;
    console.error("❌ /admin/email/process-jobs (handler):", e);
    res.status(status).json({ error: e.message || "Erreur interne" });
  }
});

// ============================================================
// 9️⃣ Influenceurs & Codes promo (LAB)
//    - Vue admin : stats globales via view_influenceurs_promo_stats
//    - Vue influenceur : stats perso via user_id
// ============================================================

app.get("/admin/influenceurs-promo", cors(), async (req, res) => {
  try {
    assertAdmin(req);

    const { data, error } = await supabase
      .from("view_influenceurs_promo_stats")
      .select("*")
      .order("nom_public", { ascending: true });

    if (error) {
      console.error("❌ Erreur lecture view_influenceurs_promo_stats:", error.message);
      return res.status(500).json({ error: "Erreur lecture des stats influenceurs" });
    }

    res.json({ items: data || [] });
  } catch (e) {
    const status = e.statusCode || 500;
    console.error("❌ /admin/influenceurs-promo (handler):", e);
    res.status(status).json({ error: e.message || "Erreur interne" });
  }
});

app.post("/admin/influenceurs-promo", cors(), async (req, res) => {
  try {
    assertAdmin(req);

    const {
      nom_public,
      identifiant_reseau,
      email,
      code,
      stripe_promotion_code_id,
      date_debut,
      date_fin,
      actif,
      ok_coins_bonus,
    } = req.body || {};

    if (!nom_public || !code || !stripe_promotion_code_id) {
      return res.status(400).json({
        error: "nom_public, code et stripe_promotion_code_id sont requis",
      });
    }

    let linkedUserId = null;
    if (email && typeof email === "string" && email.trim().length > 0) {
      const cleanEmail = email.trim().toLowerCase();
      const { data: profile, error: profileErr } = await supabase
        .from("profiles")
        .select("id, email")
        .ilike("email", cleanEmail)
        .maybeSingle();

      if (profileErr) {
        console.error("❌ Erreur recherche profil par email:", profileErr.message);
        return res.status(500).json({ error: "Erreur recherche profil par email" });
      }

      if (!profile) {
        return res.status(400).json({
          error: "Aucun profil trouvé avec cet email",
        });
      }

      linkedUserId = profile.id;
    }

    const { data: influenceur, error: inflErr } = await supabase
      .from("influenceurs")
      .insert({
        nom_public,
        handle: identifiant_reseau || null,
        canal_principal: null,
        user_id: linkedUserId,
      })
      .select("id")
      .maybeSingle();

    if (inflErr || !influenceur) {
      console.error("❌ Erreur création influenceur:", inflErr?.message || inflErr);
      return res.status(500).json({ error: "Erreur création influenceur" });
    }

    const { data: promo, error: promoErr } = await supabase
      .from("promo_codes")
      .insert({
        influenceur_id: influenceur.id,
        code,
        stripe_promotion_code_id,
        actif: typeof actif === "boolean" ? actif : true,
        date_debut: date_debut || null,
        date_fin: date_fin || null,
        ok_coins_bonus: typeof ok_coins_bonus === "number" ? ok_coins_bonus : 0,
      })
      .select("id")
      .maybeSingle();

    if (promoErr || !promo) {
      console.error("❌ Erreur création promo_codes:", promoErr?.message || promoErr);
      return res.status(500).json({ error: "Erreur création du code promo" });
    }

    return res.json({
      success: true,
      message: "Influenceur et code promo créés",
      promo_code_id: promo.id,
    });
  } catch (e) {
    const status = e.statusCode || 500;
    console.error("❌ /admin/influenceurs-promo (POST handler):", e);
    res.status(status).json({ error: e.message || "Erreur interne" });
  }
});

app.patch("/admin/influenceurs-promo/:promoCodeId", cors(), async (req, res) => {
  try {
    assertAdmin(req);

    const promoCodeId = req.params.promoCodeId;
    const { actif, date_debut, date_fin, ok_coins_bonus, stripe_promotion_code_id } = req.body || {};

    if (!promoCodeId) {
      return res.status(400).json({ error: "promoCodeId requis" });
    }

    const updatePayload = {};
    if (typeof actif === "boolean") updatePayload.actif = actif;
    if (date_debut !== undefined) updatePayload.date_debut = date_debut;
    if (date_fin !== undefined) updatePayload.date_fin = date_fin;
    if (ok_coins_bonus !== undefined) updatePayload.ok_coins_bonus = ok_coins_bonus;
    if (stripe_promotion_code_id !== undefined) updatePayload.stripe_promotion_code_id = stripe_promotion_code_id;

    if (Object.keys(updatePayload).length === 0) {
      return res.status(400).json({ error: "Aucun champ à mettre à jour" });
    }

    const { data, error } = await supabase
      .from("promo_codes")
      .update(updatePayload)
      .eq("id", promoCodeId)
      .select("*")
      .maybeSingle();

    if (error) {
      console.error("❌ Erreur update promo_codes:", error.message);
      return res.status(500).json({ error: "Erreur mise à jour du code promo" });
    }

    res.json({ item: data });
  } catch (e) {
    const status = e.statusCode || 500;
    console.error("❌ /admin/influenceurs-promo/:promoCodeId (handler):", e);
    res.status(status).json({ error: e.message || "Erreur interne" });
  }
});

app.get("/influenceur/mes-stats", cors(), async (req, res) => {
  try {
    const userId = req.query.userId || req.body?.userId;
    if (!userId) {
      return res.status(400).json({ error: "userId requis" });
    }

    const { data, error } = await supabase
      .from("view_influenceurs_promo_stats")
      .select("*")
      .eq("user_id", userId)
      .maybeSingle();

    if (error && error.code !== "PGRST116") {
      console.error("❌ Erreur lecture mes-stats influenceur:", error.message);
      return res.status(500).json({ error: "Erreur lecture des stats" });
    }

    if (!data) {
      return res.json({ item: null });
    }

    res.json({ item: data });
  } catch (e) {
    const status = e.statusCode || 500;
    console.error("❌ /influenceur/mes-stats (handler):", e);
    res.status(status).json({ error: e.message || "Erreur interne" });
  }
});

app.get("/", (req, res) => {
  res.send("✅ OneKamer backend est opérationnel !");
});

// ============================================================
// 🔁 Auto-Fix Images (annonces, partenaires, événements)
// ============================================================

const FIX_URLS = [
  "https://onekamer-server.onrender.com/api/fix-annonces-images",
  "https://onekamer-server.onrender.com/api/fix-partenaire-images",
  "https://onekamer-server.onrender.com/api/fix-evenements-images",
];

// ✅ Fonction d’appel automatique
const runAutoFix = async () => {
  console.log("🧩 Vérification automatique des images par défaut...");
  for (const url of FIX_URLS) {
    try {
      const res = await fetch(url);
      const text = await res.text();
      console.log(`✅ [AUTO-FIX] ${url} →`, text);
    } catch (err) {
      console.warn(`⚠️ Erreur auto-fix pour ${url}:`, err.message);
    }
  }
};

// 🚀 Lancer une première vérification au démarrage
runAutoFix();

// ⏱ Répéter toutes les 15 minutes (900 000 ms)
setInterval(runAutoFix, 15 * 60 * 1000);

// ============================================================
// 7️⃣ Lancement serveur
// ============================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Serveur OneKamer actif sur port ${PORT}`);
});
