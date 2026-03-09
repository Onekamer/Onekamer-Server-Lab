import express from "express";
import multer from "multer";
import mime from "mime-types";
import { createClient } from "@supabase/supabase-js";
import fixAnnoncesImages from "./fix-annonces-images.js";
import fixPartenaireImages from "./fix-partenaire-images.js";
import fixEvenementsImages from "./fix-evenements-images.js";
import fs from "fs";


const router = express.Router();
const storage = multer.diskStorage({
  destination: "/tmp",
  filename: (req, file, cb) => {
    const orig = (file.originalname || "upload").replace(/\s+/g, "_");
    const unique = `${Date.now()}_${Math.random().toString(36).slice(2)}_${orig}`;
    cb(null, unique);
  },
});
const upload = multer({ storage });

// ✅ Initialisation Supabase (pour synchroniser les fichiers)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// 🟢 Route universelle d’upload vers BunnyCDN (+ sync Supabase)
router.post("/upload", upload.single("file"), async (req, res) => {
  try {
    const startedAt = Date.now();
    // ✅ Compatibilité étendue avec anciens et nouveaux champs
    const folder = req.body.folder || req.body.type || "misc";
    const userId = req.body.user_id || req.body.userId || req.body.recordId;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: "Aucun fichier reçu." });
    }

    // ✅ Dossiers autorisés
    const allowedFolders = [
      "avatars",
      "posts",
      "partenaires",
      "marketplace_items",
      "annonces",
      "evenements",
      "comments_audio",
      "comments",
      "misc",
      "groupes",
      "faits_divers",
      "rencontres",
    ];
    if (!allowedFolders.includes(folder)) {
      return res.status(400).json({ error: `Dossier non autorisé: ${folder}` });
    }

    // ✅ Types MIME autorisés
    const ALLOWED_AUDIO_TYPES = [
      "audio/webm",
      "audio/mpeg",
      "audio/mp4",
      "audio/ogg",
      "audio/wav",
      "audio/x-m4a",
      "audio/x-aac",
    ];

    const mimeType = file.mimetype || "application/octet-stream";
    const ext = mime.extension(mimeType) || "bin";
    const isImage = mimeType.startsWith("image/");
    const isVideo = mimeType.startsWith("video/");
    const isAudio = ALLOWED_AUDIO_TYPES.includes(mimeType);

    if (!isImage && !isVideo && !isAudio) {
      return res.status(400).json({
        success: false,
        message: `Type de fichier non pris en charge (${mimeType}).`,
      });
    }

    // 🔧 Nom de fichier sûr et unique
const originalName = file.originalname?.replace(/\s+/g, "_") || `upload.${ext}`;
const fileName = `${Date.now()}_${originalName}`;

// ✅ Organisation claire : sous-dossier par utilisateur pour "rencontres"
let uploadPath;
if (folder === "rencontres" && userId) {
  uploadPath = `${folder}/${userId}/${fileName}`;
} else {
  uploadPath = `${folder}/${fileName}`;
}

// 🧾 Log lisible dans Render pour vérification
console.log(`
=============================================
📤 Nouveau upload détecté
👤 Utilisateur: ${userId || "inconnu"}
📁 Dossier cible: ${folder}
🗂️  Chemin complet: ${uploadPath}
📸 Type MIME: ${mimeType}
=============================================
`);

    // 🚀 Upload vers BunnyCDN (stream depuis /tmp avec Content-Length)
    const tmpPath = file.path;
    const stat = await fs.promises.stat(tmpPath);
    const stream = fs.createReadStream(tmpPath);
    const response = await fetch(
      `https://storage.bunnycdn.com/${process.env.BUNNY_STORAGE_ZONE}/${uploadPath}`,
      {
        method: "PUT",
        headers: {
          AccessKey: process.env.BUNNY_ACCESS_KEY,
          "Content-Type": mimeType,
          "Content-Length": String(stat.size),
        },
        duplex: "half",
        body: stream,
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.error("❌ Erreur BunnyCDN:", { status: response.status, errorText, uploadPath, sizeBytes: stat.size });
      throw new Error(`Échec de l’upload sur BunnyCDN (${response.status})`);
    }

    // 🌍 URL finale (CDN public)
    let cdnUrl = `${process.env.BUNNY_CDN_URL}/${uploadPath}`;

   // 🪄 Synchronisation automatique dans Supabase uniquement pour "rencontres" et seulement pour les images
if (folder === "rencontres" && isImage) {
  try {
    // ✅ Structure finale dans Supabase :
    // Bucket: rencontres
    // Dossier: rencontres/<uuid>/<fichier>
    const supabasePath = userId
      ? `${folder}/${userId}/${fileName}`
      : `${folder}/${fileName}`;

    console.log(`
🧩 Synchronisation Supabase en cours...
📦 Bucket: rencontres
📁 Dossier: ${folder}
👤 Utilisateur: ${userId || "inconnu"}
📸 Fichier: ${fileName}
➡️  Chemin complet: ${supabasePath}
    `);

    const { error: supabaseError } = await supabase.storage
      .from("rencontres")
      .upload(supabasePath, await fs.promises.readFile(tmpPath), {
        contentType: mimeType,
        upsert: true,
      });

    if (supabaseError) {
      console.warn("⚠️ Upload Bunny réussi, mais échec Supabase :", supabaseError.message);
    } else {
      console.log(`
✅ Fichier aussi ajouté dans Supabase !
📦 Bucket: rencontres
📁 Chemin interne: ${supabasePath}
📤 Upload terminé avec succès 🚀
      `);
    }
  } catch (syncErr) {
    console.warn("⚠️ Erreur de synchronisation Supabase :", syncErr.message);
  }
}

   // ✅ Succès — normalisation finale des URLs
cdnUrl = `${process.env.BUNNY_CDN_URL}/${uploadPath}`;

// 🧩 Sécurité : forcer https complet, corriger éventuels doubles slashs
cdnUrl = cdnUrl.replace(/([^:]\/)\/+/g, "$1");

// 🧩 Fallback : si BUNNY_CDN_URL n’est pas défini, basculer sur ton domaine Hostinger
if (!process.env.BUNNY_CDN_URL || !cdnUrl.startsWith("http")) {
  cdnUrl = `https://onekamer-media-cdn.b-cdn.net/${uploadPath}`;
}

// 📦 Log clair avec durée totale
const durationMs = Date.now() - startedAt;
console.log(`
✅ Upload finalisé :
🌍 URL publique : ${cdnUrl}
📁 Dossier interne : ${uploadPath}
📏 Taille (octets) : ${stat.size}
⏱️ Durée totale : ${durationMs} ms
`);

await fs.promises.unlink(tmpPath).catch(() => {});
return res.status(200).json({
  success: true,
  url: cdnUrl,          // 👈 toujours l'URL complète
  full_url: cdnUrl,     // 👈 alias pour compatibilité ancienne
  path: uploadPath,     // 👈 utile pour debug uniquement
  mimeType,
  sizeBytes: stat.size,
  durationMs,
  message: `✅ Upload réussi vers ${cdnUrl}`,
});
  
 // 🚀 Lancer le correctif localement sans HTTP
try {
  const folder = (req.body.folder || req.body.type || "").toLowerCase();

  if (folder.startsWith("annonce")) {
    console.log("🧩 Lancement local du fix annonces...");
    await fixAnnoncesImages.runFix(); // <-- nouvelle méthode exportée
  } else if (folder.startsWith("evenement")) {
    console.log("🧩 Lancement local du fix événements...");
    await fixEvenementsImages.runFix();
  } else if (folder.startsWith("partenaire")) {
    console.log("🧩 Lancement local du fix partenaires...");
    await fixPartenaireImages.runFix();
  }
} catch (err) {
  console.warn("⚠️ Auto-fix local échoué:", err.message);
}
    
  } catch (err) {
    console.error("❌ Erreur upload:", err.message);
    try { if (req?.file?.path) { await fs.promises.unlink(req.file.path); } } catch {}
    return res.status(500).json({
      success: false,
      error: err.message,
      hint: "Vérifie ta clé BunnyCDN, ton dossier autorisé, et le Content-Type.",
    });
  }
});

export default router;
