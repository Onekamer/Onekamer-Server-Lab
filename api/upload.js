import express from "express";
import multer from "multer";
import mime from "mime-types";
import { createClient } from "@supabase/supabase-js";

const router = express.Router();
const upload = multer();

// ✅ Initialisation Supabase (pour synchroniser les fichiers)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// 🟢 Route universelle d’upload vers BunnyCDN (+ sync Supabase)
router.post("/upload", upload.single("file"), async (req, res) => {
  try {
    // ✅ Compatibilité étendue avec anciens et nouveaux champs
    const folder = req.body.folder || req.body.type || "misc";
    const userId = req.body.userId || req.body.recordId;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: "Aucun fichier reçu." });
    }

    // ✅ Dossiers autorisés
    const allowedFolders = [
      "avatars",
      "posts",
      "partenaires",
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
    const uploadPath = `${folder}/${userId ? `${userId}_` : ""}${fileName}`;

    console.log("📁 Upload vers:", uploadPath, "| Type:", mimeType);

    // 🚀 Upload vers BunnyCDN
    const response = await fetch(
      `https://storage.bunnycdn.com/${process.env.BUNNY_STORAGE_ZONE}/${uploadPath}`,
      {
        method: "PUT",
        headers: {
          AccessKey: process.env.BUNNY_ACCESS_KEY,
          "Content-Type": mimeType,
        },
        body: file.buffer,
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.error("❌ Erreur BunnyCDN:", errorText);
      throw new Error(`Échec de l’upload sur BunnyCDN (${response.status})`);
    }

    // 🌍 URL finale (CDN public)
    const cdnUrl = `${process.env.BUNNY_CDN_URL}/${uploadPath}`;

    // 🪄 Synchronisation automatique dans Supabase uniquement pour "rencontres"
    if (folder === "rencontres") {
      try {
        // ✅ Correction ici : sauvegarde dans le sous-dossier 'rencontres/' de Supabase
        const { error: supabaseError } = await supabase.storage
          .from("rencontres")
          .upload(uploadPath, file.buffer, {
            contentType: mimeType,
            upsert: true,
          });

        if (supabaseError) {
          console.warn("⚠️ Upload Bunny réussi, mais échec Supabase :", supabaseError.message);
        } else {
          console.log("✅ Fichier aussi ajouté dans Supabase bucket 'rencontres/rencontres'");
        }
      } catch (syncErr) {
        console.warn("⚠️ Erreur de synchronisation Supabase :", syncErr.message);
      }
    }

    // ✅ Succès
    return res.status(200).json({
      success: true,
      url: cdnUrl,
      path: uploadPath,
      mimeType,
      message: `✅ Upload réussi vers ${cdnUrl}`,
    });
  } catch (err) {
    console.error("❌ Erreur upload:", err.message);
    return res.status(500).json({
      success: false,
      error: err.message,
      hint: "Vérifie ta clé BunnyCDN, ton dossier autorisé, et le Content-Type.",
    });
  }
});

export default router;
