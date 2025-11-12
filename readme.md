# 🧪 OneKamer.co – Backend API (LAB)

## 🌍 Description
Version **de test et de développement** du serveur **OneKamer.co**, construite avec **Node.js / Express**  
et connectée à **Supabase**, **Stripe (mode test)** et **BunnyCDN**.  

Ce serveur permet de valider et déboguer toutes les intégrations avant passage en production.

- 💳 Paiements et abonnements **Stripe (test mode)**
- 🧾 Synchronisation des profils et plans avec **Supabase (dev)**
- 🪙 Gestion automatique des **OK COINS**
- 🖼️ Stockage et diffusion média via **BunnyCDN**
- 🛡️ Webhooks Stripe sécurisés
- ⚙️ RPC Supabase : `upsert_subscription_from_stripe()` et `apply_plan_to_profile()`

---

## 🧠 Architecture & Environnement

| Composant | Technologie | Hébergement |
|------------|-------------|--------------|
| Backend API | Node.js / Express | Render (Environnement de test) |
| Base de données | Supabase (PostgreSQL - Dev) | Supabase Cloud |
| Paiement | Stripe (Test Mode) | Render |
| Stockage médias | BunnyCDN (Edge Storage + CDN) | Bunny.net |
| Sécurité | RLS + Policies | Supabase |

---

## ⚙️ Variables d’environnement

```bash
SUPABASE_URL=<ton_supabase_dev_url>
SUPABASE_SERVICE_ROLE_KEY=<ta_cle_service_role_dev>
STRIPE_SECRET_KEY=<ta_cle_stripe_test>
STRIPE_WEBHOOK_SECRET=<ta_cle_webhook_test>
FRONTEND_URL=http://localhost:3000
BUNNY_API_KEY=<ta_cle_bunny>
BUNNY_STORAGE_ZONE=<ta_zone_storage>
BUNNY_CDN_URL=https://onekamer-media-cdn.b-cdn.net
PORT=10000

### Routes principales

| Méthode | Route | Description |
|----------|--------|-------------|
| `POST` | `/create-checkout-session` | Crée une session Stripe Checkout (test mode) |
| `POST` | `/activate-free-plan` | Active un plan gratuit utilisateur |
| `POST` | `/webhook` | Webhook Stripe pour paiements et abonnements |
| `GET`  | `/fix-partenaire-images` | (Maintenance) Correction automatique des images partenaires Bunny |

### Fonctionnalités clés

- Vérification automatique de la signature Stripe ✅  
- Synchronisation des abonnements Supabase ↔ Stripe 🧾  
- Attribution dynamique des accès via `plan_features` 🔑  
- Gestion complète des événements Stripe (`stripe_events`, `stripe_events_log`) 📊  
- Stockage et diffusion des médias via **BunnyCDN** 🌍  
- Support des achats OK COINS 💰  
- Environnement isolé de test et logs détaillés pour debug 🔍

### Commandes utiles

# Installation des dépendances
npm install

# Lancement du serveur (mode test)
npm start

### Auteurs

Développé par **William Soppo** & **Annaëlle Bilounga**  
© 2025 **OneKamer SAS** — Tous droits réservés.  

### Licence

Version de test interne – Propriété OneKamer SAS.  
Ce code est réservé aux environnements de développement et ne doit pas être diffusé ou utilisé en production.


