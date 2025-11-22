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
import bodyParser from "body-parser";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import { AccessToken } from "livekit-server-sdk";
import nodemailer from "nodemailer";
import uploadRoute from "./api/upload.js";
import partenaireDefaultsRoute from "./api/fix-partenaire-images.js";
import fixAnnoncesImagesRoute from "./api/fix-annonces-images.js";
import fixEvenementsImagesRoute from "./api/fix-evenements-images.js";
import notificationsRouter from "./api/notifications.js";


// ✅ Correction : utiliser le fetch natif de Node 18+ (pas besoin d'import)
const fetch = globalThis.fetch;
// =======================================================
// ✅ CONFIGURATION CORS — OneKamer Render + Horizon
// =======================================================
const app = express();
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
app.use("/api", notificationsRouter);


const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: "2024-06-20",
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ============================================================
// 📧 Email - Brevo HTTP API (LAB) + fallback Nodemailer
// ============================================================

const smtpHost = process.env.SMTP_HOST;
const smtpPort = process.env.SMTP_PORT
  ? parseInt(process.env.SMTP_PORT, 10)
  : 587;
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
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const { userId, packId, planKey } = session.metadata || {};

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

      // Cas 2 : Abonnement Stripe (Standard / VIP)
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

      // Cas 3 : Achat unique “VIP à vie”
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
  const { userId, planKey, priceId } = req.body;

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

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: finalPriceId, quantity: 1 }],
      allow_promotion_codes: true,
      success_url: `${process.env.FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/cancel`,
      metadata: { userId, planKey },
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

// 7️⃣ Notifications OneSignal
// ============================================================

app.post("/send-notification", async (req, res) => {
  const { title, message } = req.body;

  if (!title || !message) {
    return res.status(400).json({ error: "title et message requis" });
  }

  try {
    const response = await fetch("https://onesignal.com/api/v1/notifications", {
      method: "POST",
      headers: {
        "Authorization": `Basic ${process.env.ONESIGNAL_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        app_id: process.env.ONESIGNAL_APP_ID,
        headings: { en: title },
        contents: { en: message },
        included_segments: ["All"], // Tous les abonnés
        url: "https://onekamer.co",  // Lien cliquable optionnel
      }),
    });

    const data = await response.json();

    if (data.errors) {
      console.error("❌ Erreur OneSignal:", data.errors);
      await logEvent({
        category: "onesignal",
        action: "notification.send",
        status: "error",
        context: { title, message, errors: data.errors },
      });
      return res.status(500).json({ error: data.errors });
    }

    console.log("✅ Notification OneSignal envoyée :", data.id);
    await logEvent({
      category: "onesignal",
      action: "notification.send",
      status: "success",
      context: { title, message, notification_id: data.id },
    });

    res.json({ success: true, notification_id: data.id });
  } catch (err) {
    console.error("❌ Erreur envoi OneSignal:", err);
    await logEvent({
      category: "onesignal",
      action: "notification.send",
      status: "error",
      context: { title, message, error: err.message },
    });
    res.status(500).json({ error: err.message });
  }
});

console.log("✅ Route OneSignal /send-notification chargée");

// ============================================================
// 🔁 Alias de compatibilité : /notifications/onesignal
// (utilisé par le front Horizon / Codex)
// ============================================================
app.post("/notifications/onesignal", (req, res, next) => {
  console.log("🔁 Alias activé : /notifications/onesignal → /send-notification");
  req.url = "/send-notification";
  app._router.handle(req, res, next);
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
    }

    console.log("📧 /admin/email/process-jobs terminé →", {
      processed: jobs.length,
      sent: sentCount,
      errorsCount: errors.length,
    });

    res.json({ processed: jobs.length, sent: sentCount, errors });
  } catch (e) {
    const status = e.statusCode || 500;
    console.error("❌ /admin/email/process-jobs:", e);
    res.status(status).json({ error: e.message || "Erreur interne" });
  }
});

// ============================================================
// 6️⃣ Route de santé (Render health check)
// ============================================================

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
