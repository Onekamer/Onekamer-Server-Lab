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
import uploadRoute from "./api/upload.js";
import partenaireDefaultsRoute from "./api/fix-partenaire-images.js";
import fixAnnoncesImagesRoute from "./api/fix-annonces-images.js";
import fixEvenementsImagesRoute from "./api/fix-evenements-images.js";
import qrcodeRouter from "./api/qrcode.js";
import pushRouter from "./api/push.js";
import webpush from "web-push";
import cron from "node-cron";
import { AccessToken } from "livekit-server-sdk";


// ✅ Correction : utiliser le fetch natif de Node 18+ (pas besoin d'import)
const fetch = globalThis.fetch;
// =======================================================
// ✅ CONFIGURATION CORS — OneKamer Render + Horizon
// =======================================================
const app = express();
const NOTIF_PROVIDER = process.env.NOTIFICATIONS_PROVIDER || "onesignal";
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

function isUUID(v) {
  return (
    typeof v === "string" &&
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v)
  );
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

// ============================================================
// 🔧 Helpers LiveKit / Groupes
// ============================================================

function getLivekitUrl() {
  return (
    process.env.LIVEKIT_HOST_URL ||
    process.env.LIVEKIT_URL ||
    ""
  );
}

async function isGroupAdminOrFounder(groupId, userId) {
  try {
    // Fondateur ?
    const { data: grp } = await supabase
      .from("groupes")
      .select("fondateur_id")
      .eq("id", groupId)
      .maybeSingle();
    if (grp?.fondateur_id === userId) return true;

    // Admin déclaré ?
    const { data: memb } = await supabase
      .from("groupes_membres")
      .select("is_admin")
      .eq("groupe_id", groupId)
      .eq("user_id", userId)
      .maybeSingle();
    return !!memb?.is_admin;
  } catch (_e) {
    return false;
  }
}

async function buildLivekitToken({ userId, roomName, isHost }) {
  const apiKey = process.env.LIVEKIT_API_KEY;
  const apiSecret = process.env.LIVEKIT_API_SECRET;
  if (!apiKey || !apiSecret) throw new Error("LIVEKIT_API_KEY/SECRET manquants");

  // API v2
  const at = new AccessToken({
    issuer: apiKey,
    secret: apiSecret,
  });
  at.identity = userId;
  at.addGrant({
    roomJoin: true,
    room: roomName,
    canPublish: !!isHost,
    canSubscribe: true,
    canPublishData: !!isHost,
  });
  const jwt = await at.toJwt();
  return jwt;
}

// ============================================================
// 🔔 Web Push (VAPID) - Configuration si variables présentes
// ============================================================
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || "mailto:contact@onekamer.co";

if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  try {
    webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
    console.log("✅ VAPID configuré (Web Push activé)");
  } catch (e) {
    console.warn("⚠️ Échec configuration VAPID:", e?.message || e);
  }
} else {
  console.warn("ℹ️ VAPID non configuré (VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY manquants)");
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
// 🎥 LiveKit - Group Live Sessions (LAB)
// ============================================================

// GET statut live d'un groupe
app.get("/api/groups/:groupId/live", async (req, res) => {
  try {
    const groupId = req.params.groupId;
    if (!groupId) return res.status(400).json({ error: "groupId requis" });
    if (!isUUID(groupId)) return res.status(400).json({ error: "invalid_group_id" });

    const { data, error } = await supabase
      .from("group_live_sessions")
      .select("id, group_id, host_user_id, room_name, is_live, started_at")
      .eq("group_id", groupId)
      .eq("is_live", true)
      .maybeSingle();
    if (error) throw new Error(error.message);

    if (!data) return res.json({ isLive: false });
    res.json({
      isLive: true,
      roomName: data.room_name,
      hostUserId: data.host_user_id,
      startedAt: data.started_at,
    });
  } catch (e) {
    console.error("❌ GET /api/groups/:groupId/live:", e);
    await logEvent({ category: "live", action: "status", status: "error", context: { error: e?.message || e } });
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// POST démarrer un live (host/admin uniquement)
app.post("/api/groups/:groupId/live/start", bodyParser.json(), async (req, res) => {
  try {
    const groupId = req.params.groupId;
    const { userId } = req.body || {};
    if (!groupId || !userId) return res.status(400).json({ error: "groupId et userId requis" });
    if (!isUUID(groupId)) return res.status(400).json({ error: "invalid_group_id" });
    if (!isUUID(userId)) return res.status(400).json({ error: "invalid_user_id" });

    const isAllowed = await isGroupAdminOrFounder(groupId, userId);
    if (!isAllowed) return res.status(403).json({ error: "Accès refusé" });

    // Un seul live actif par groupe
    const { data: existing } = await supabase
      .from("group_live_sessions")
      .select("id")
      .eq("group_id", groupId)
      .eq("is_live", true)
      .maybeSingle();
    if (existing) return res.status(409).json({ error: "Live déjà en cours" });

    const roomName = `group_${groupId}_${Date.now()}`;
    const { data: created, error } = await supabase
      .from("group_live_sessions")
      .insert({ group_id: groupId, host_user_id: userId, room_name: roomName, is_live: true })
      .select("id, room_name")
      .maybeSingle();
    if (error) throw new Error(error.message);

    await logEvent({ category: "live", action: "start", status: "success", userId, context: { groupId, roomName } });
    res.json({ isLive: true, roomName: created.room_name });
  } catch (e) {
    console.error("❌ POST /api/groups/:groupId/live/start:", e);
    await logEvent({ category: "live", action: "start", status: "error", context: { error: e?.message || e } });
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// POST arrêter un live (host/admin uniquement)
app.post("/api/groups/:groupId/live/stop", bodyParser.json(), async (req, res) => {
  try {
    const groupId = req.params.groupId;
    const { userId, reason } = req.body || {};
    if (!groupId || !userId) return res.status(400).json({ error: "groupId et userId requis" });
    if (!isUUID(groupId)) return res.status(400).json({ error: "invalid_group_id" });
    if (!isUUID(userId)) return res.status(400).json({ error: "invalid_user_id" });

    const isAllowed = await isGroupAdminOrFounder(groupId, userId);
    if (!isAllowed) return res.status(403).json({ error: "Accès refusé" });

    const { data: active } = await supabase
      .from("group_live_sessions")
      .select("id")
      .eq("group_id", groupId)
      .eq("is_live", true)
      .maybeSingle();
    if (!active) return res.status(404).json({ error: "Aucune session active" });

    const { error } = await supabase
      .from("group_live_sessions")
      .update({ is_live: false, ended_at: new Date().toISOString(), ended_reason: reason || "stopped" })
      .eq("id", active.id);
    if (error) throw new Error(error.message);

    await logEvent({ category: "live", action: "stop", status: "success", userId, context: { groupId } });
    res.json({ stopped: true });
  } catch (e) {
    console.error("❌ POST /api/groups/:groupId/live/stop:", e);
    await logEvent({ category: "live", action: "stop", status: "error", context: { error: e?.message || e } });
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// POST génération token LiveKit
app.post("/api/livekit/token", bodyParser.json(), async (req, res) => {
  try {
    const { userId, groupId, roomName: bodyRoom } = req.body || {};
    if (!userId) return res.status(400).json({ error: "userId requis" });
    if (!isUUID(userId)) return res.status(400).json({ error: "invalid_user_id" });

    let roomName = bodyRoom;
    if (!roomName && groupId) {
      if (!isUUID(groupId)) return res.status(400).json({ error: "invalid_group_id" });
      const { data: live } = await supabase
        .from("group_live_sessions")
        .select("room_name, host_user_id")
        .eq("group_id", groupId)
        .eq("is_live", true)
        .maybeSingle();
      roomName = live?.room_name || null;
    }
    if (!roomName) return res.status(400).json({ error: "roomName ou groupId requis" });

    const isHost = groupId ? await isGroupAdminOrFounder(groupId, userId) : false;
    const token = await buildLivekitToken({ userId, roomName, isHost });
    const hostUrl = getLivekitUrl();

    res.json({ token, hostUrl, roomName, role: isHost ? "host" : "viewer" });
  } catch (e) {
    console.error("❌ POST /api/livekit/token:", e);
    await logEvent({ category: "live", action: "token", status: "error", context: { error: e?.message || e } });
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// ============================================================
// 🔔 Web Push (Option C) — Routes natives
// ============================================================

// Enregistre la subscription Web Push pour un utilisateur
app.post("/push/subscribe", bodyParser.json(), async (req, res) => {
  if (NOTIF_PROVIDER !== "supabase_light") return res.status(200).json({ ignored: true });

  try {
    const { userId, endpoint, keys } = req.body || {};
    if (!userId || !endpoint || !keys?.p256dh || !keys?.auth) {
      return res.status(400).json({ error: "userId, endpoint, keys.p256dh et keys.auth requis" });
    }

    // Upsert par endpoint
    await supabase.from("push_subscriptions").delete().eq("endpoint", endpoint);
    const { error } = await supabase.from("push_subscriptions").insert({
      user_id: userId,
      endpoint,
      p256dh: keys.p256dh,
      auth: keys.auth,
    });
    if (error) {
      console.error("❌ Erreur insert subscription:", error.message);
      return res.status(500).json({ error: "Erreur enregistrement subscription" });
    }

    await logEvent({
      category: "notifications",
      action: "push.subscribe",
      status: "success",
      userId,
      context: { endpoint },
    });

    res.json({ success: true });
  } catch (e) {
    console.error("❌ Erreur /push/subscribe:", e);
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// Désinscrit (désactive) l'appareil courant en supprimant l'endpoint en base
app.post("/push/unsubscribe", bodyParser.json(), async (req, res) => {
  if (NOTIF_PROVIDER !== "supabase_light") return res.status(200).json({ ignored: true });

  try {
    const { endpoint, userId } = req.body || {};
    if (!endpoint) {
      return res.status(400).json({ error: "endpoint requis" });
    }

    const { error, count } = await supabase
      .from("push_subscriptions")
      .delete()
      .eq("endpoint", endpoint)
      .select("id", { count: "exact" });
    if (error) {
      console.error("❌ Erreur delete subscription:", error.message);
      return res.status(500).json({ error: "Erreur suppression subscription" });
    }

    await logEvent({
      category: "notifications",
      action: "push.unsubscribe",
      status: "success",
      userId: isUUID(userId) ? userId : null,
      context: { endpoint, deleted: count ?? 0 },
    });

    res.json({ success: true, deleted: count ?? 0 });
  } catch (e) {
    console.error("❌ Erreur /push/unsubscribe:", e);
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// Dispatch d'un événement: insert en base + envoi Web Push
app.post("/notifications/dispatch", async (req, res) => {
  if (NOTIF_PROVIDER !== "supabase_light") return res.status(200).json({ ignored: true });

  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    console.warn("⚠️ Dispatch refusé: VAPID non configuré");
    return res.status(200).json({ success: false, reason: "vapid_not_configured" });
  }

  try {
    const { title, message, targetUserIds = [], data = {}, url = "/" } = req.body || {};
    if (!title || !message || !Array.isArray(targetUserIds) || targetUserIds.length === 0) {
      return res.status(400).json({ error: "title, message et targetUserIds requis" });
    }

    // 1) Insert notifications (best-effort)
    try {
      const rows = targetUserIds.map((uid) => ({
        user_id: uid,
        title,
        message,
        type: data?.type || null,
        link: url,
      }));
      const { error: insErr } = await supabase.from("notifications").insert(rows);
      if (insErr) console.warn("⚠️ Insert notifications échoué:", insErr.message);
    } catch (e) {
      console.warn("⚠️ Insert notifications (best-effort) erreur:", e?.message || e);
    }

    // 2) Récup subscriptions et envoi push
    const { data: subs, error: subErr } = await supabase
      .from("push_subscriptions")
      .select("user_id, endpoint, p256dh, auth")
      .in("user_id", targetUserIds);
    if (subErr) {
      console.warn("⚠️ Lecture subscriptions échouée:", subErr.message);
    }

    const icon = "https://onekamer-media-cdn.b-cdn.net/logo/IMG_0885%202.PNG";
    const badge = "https://onekamer-media-cdn.b-cdn.net/android-chrome-72x72.png";
    const payload = (uid) => JSON.stringify({
      title: title || "OneKamer",
      body: message,
      icon,
      badge,
      url,
      data,
    });

    let sent = 0;
    if (Array.isArray(subs)) {
      for (const s of subs) {
        try {
          await webpush.sendNotification(
            {
              endpoint: s.endpoint,
              expirationTime: null,
              keys: { p256dh: s.p256dh, auth: s.auth },
            },
            payload(s.user_id)
          );
          sent++;
        } catch (e) {
          console.warn("⚠️ Échec envoi push à", s.user_id, e?.statusCode || e?.message || e);
        }
      }
    }

    await logEvent({
      category: "notifications",
      action: "dispatch",
      status: "success",
      context: { target_count: targetUserIds.length, sent },
    });

    res.json({ success: true, sent });
  } catch (e) {
    console.error("❌ Erreur /notifications/dispatch:", e);
    await logEvent({
      category: "notifications",
      action: "dispatch",
      status: "error",
      context: { error: e?.message || e },
    });
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// ============================================================
// 🔁 Aliases compatibilité pour chemins /api
// ============================================================
app.post("/api/push/subscribe", (req, res, next) => {
  console.log("🔁 Alias activé : /api/push/subscribe → /push/subscribe");
  req.url = "/push/subscribe";
  app._router.handle(req, res, next);
});

app.post("/api/notifications/dispatch", (req, res, next) => {
  console.log("🔁 Alias activé : /api/notifications/dispatch → /notifications/dispatch");
  req.url = "/notifications/dispatch";
  app._router.handle(req, res, next);
});

// Legacy Supabase webhook targets → route vers le nouveau relais Web Push
app.post("/api/supabase-notification", (req, res, next) => {
  console.log("🔁 Alias activé : /api/supabase-notification → /push/supabase-notification");
  req.url = "/push/supabase-notification";
  app._router.handle(req, res, next);
});

app.post("/notifications/onesignal", (req, res, next) => {
  console.log("🔁 Alias activé : /notifications/onesignal → /api/push/relay");
  req.url = "/api/push/relay";
  app._router.handle(req, res, next);
});

// Alias pour désinscription push
app.post("/api/push/unsubscribe", (req, res, next) => {
  console.log("🔁 Alias activé : /api/push/unsubscribe → /push/unsubscribe");
  req.url = "/push/unsubscribe";
  app._router.handle(req, res, next);
});

// ============================================================
// 📥 Notifications API (liste + lecture)
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
      .select("id, created_at, title, message, type, link, is_read")
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

    const { data: cntData, error: cntErr } = await supabase
      .from("notifications")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .eq("is_read", false);
    if (cntErr) console.warn("⚠️ unreadCount error:", cntErr.message);

    res.json({
      items: items?.map((n) => ({
        id: n.id,
        created_at: n.created_at,
        title: n.title,
        body: n.message,
        type: n.type,
        deeplink: n.link || "/",
        is_read: !!n.is_read,
      })) || [],
      nextCursor,
      hasMore,
      unreadCount: cntData === null ? 0 : (cntData?.length ?? 0),
    });
  } catch (e) {
    console.error("❌ GET /notifications:", e);
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// Marquer une notification comme lue
// Body: { userId, id }
app.post("/notifications/mark-read", bodyParser.json(), async (req, res) => {
  try {
    const { userId, id } = req.body || {};
    if (!userId || !id) return res.status(400).json({ error: "userId et id requis" });

    const { error } = await supabase
      .from("notifications")
      .update({ is_read: true, read_at: new Date().toISOString() })
      .eq("id", id)
      .eq("user_id", userId);
    if (error) throw new Error(error.message);

    res.json({ success: true });
  } catch (e) {
    console.error("❌ POST /notifications/mark-read:", e);
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// Tout marquer comme lu pour un utilisateur
// Body: { userId }
app.post("/notifications/mark-all-read", bodyParser.json(), async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) return res.status(400).json({ error: "userId requis" });

    const { error } = await supabase
      .from("notifications")
      .update({ is_read: true, read_at: new Date().toISOString() })
      .eq("user_id", userId)
      .eq("is_read", false);
    if (error) throw new Error(error.message);

    res.json({ success: true });
  } catch (e) {
    console.error("❌ POST /notifications/mark-all-read:", e);
    res.status(500).json({ error: e?.message || "Erreur interne" });
  }
});

// Aliases /api
app.get("/api/notifications", (req, res, next) => {
  console.log("🔁 Alias activé : /api/notifications → /notifications");
  req.url = "/notifications";
  app._router.handle(req, res, next);
});

app.post("/api/notifications/mark-read", (req, res, next) => {
  console.log("🔁 Alias activé : /api/notifications/mark-read → /notifications/mark-read");
  req.url = "/notifications/mark-read";
  app._router.handle(req, res, next);
});

app.post("/api/notifications/mark-all-read", (req, res, next) => {
  console.log("🔁 Alias activé : /api/notifications/mark-all-read → /notifications/mark-all-read");
  req.url = "/notifications/mark-all-read";
  app._router.handle(req, res, next);
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
// Expiration automatique des QR Codes (horaire)
// ============================================================
try {
  cron.schedule("0 * * * *", async () => {
    try {
      const today = new Date().toISOString().slice(0, 10);
      const { data: pastEvents, error: pastErr } = await supabase
        .from("evenements")
        .select("id")
        .lt("date", today);
      if (pastErr) {
        await logEvent({ category: "qrcode", action: "expire.scan", status: "error", context: { error: pastErr.message } });
        return;
      }
      const ids = Array.isArray(pastEvents) ? pastEvents.map((e) => e.id) : [];
      if (ids.length === 0) {
        await logEvent({ category: "qrcode", action: "expire.scan", status: "success", context: { updated: 0 } });
        return;
      }
      const { data: updated, error: upErr } = await supabase
        .from("event_qrcodes")
        .update({ status: "expired" })
        .in("event_id", ids)
        .eq("status", "active")
        .select("id");
      if (upErr) {
        await logEvent({ category: "qrcode", action: "expire.update", status: "error", context: { error: upErr.message } });
      } else {
        await logEvent({ category: "qrcode", action: "expire.update", status: "success", context: { updated: (updated?.length || 0) } });
      }
    } catch (e) {
      await logEvent({ category: "qrcode", action: "expire.cron", status: "error", context: { error: e?.message || String(e) } });
    }
  });
} catch {}

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

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: finalPriceId, quantity: 1 }],
      allow_promotion_codes: true,
      success_url: `${process.env.FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/cancel`,
      metadata: { userId, planKey },
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
      action: "telegram.notify",
      status: "error",
      userId: userId || null,
      context: { reason: "missing fields", body: req.body },
    });
    return res.status(400).json({ error: "Informations incomplètes pour la notification." });
  }

  try {
    const message = `
💸 *Nouvelle demande de retrait OK COINS*  
👤 Utilisateur : ${username}  
📧 Email : ${email}  
🆔 ID : ${userId}  
💰 Montant demandé : ${Number(amount).toLocaleString("fr-FR")} pièces  
🕒 ${new Date().toLocaleString("fr-FR")}
`;

    const response = await fetch(
      `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: process.env.TELEGRAM_CHAT_ID,
          text: message,
          parse_mode: "Markdown",
        }),
      }
    );

    const data = await response.json();
    if (!data.ok) throw new Error(data.description || "Erreur API Telegram");

    console.log("📨 Notification Telegram envoyée avec succès.");
    await logEvent({
      category: "withdrawal",
      action: "telegram.notify",
      status: "success",
      userId,
      context: { telegram_message_id: data?.result?.message_id || null },
    });

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Erreur notification Telegram :", err);
    await logEvent({
      category: "withdrawal",
      action: "telegram.notify",
      status: "error",
      userId,
      context: { error: err?.message || err },
    });
    return res.status(500).json({ error: "Échec notification Telegram" });
  }
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
