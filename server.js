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
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
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

app.get("/api/market/partners", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("partners_market")
      .select(
        "id, display_name, description, category, country_code, base_currency, status, payout_status, is_open, created_at"
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

    const frontendBase = "https://onekamer-front-lab.onrender.com";
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
