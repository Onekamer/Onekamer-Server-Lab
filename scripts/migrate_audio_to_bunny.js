/*
  Migration audio Supabase -> Bunny
  - Dry-run: node scripts/migrate_audio_to_bunny.js --dry-run [--limit=20]
  - Run    : node scripts/migrate_audio_to_bunny.js [--limit=20]

  Variables d'environnement requises (LAB):
  - SUPABASE_URL
  - SUPABASE_SERVICE_KEY (service role)
  - BUNNY_STORAGE_ZONE (ex: onekamer-media)
  - BUNNY_STORAGE_KEY  (Password d'accès Storage Zone)
  - BUNNY_CDN_BASE     (ex: https://onekamer-media.b-cdn.net)

  Stratégie:
  1) Lister les objets du bucket Supabase 'comments_audio'.
  2) Pour chaque fichier, vérifier s'il existe déjà sur Bunny (HEAD).
  3) S'il n'existe pas et si run (non dry-run), télécharger depuis Supabase et uploader vers Bunny.
  4) Mettre à jour public.comments.audio_url pour les rows qui contiennent ce filename dans l'URL (pattern LIKE %<filename>%).
  5) Insérer une ligne dans public.migrations_audio_log.
*/

import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

const SUPABASE_URL = process.env.SUPABASE_URL
// Support alias: SUPABASE_SERVICE_KEY ou SUPABASE_SERVICE_ROLE_KEY
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
const BUNNY_STORAGE_ZONE = process.env.BUNNY_STORAGE_ZONE
// Support alias: BUNNY_STORAGE_KEY ou BUNNY_ACCESS_KEY
const BUNNY_STORAGE_KEY = process.env.BUNNY_STORAGE_KEY || process.env.BUNNY_ACCESS_KEY
// Support alias: BUNNY_CDN_BASE ou BUNNY_CDN_URL
const BUNNY_CDN_BASE = process.env.BUNNY_CDN_BASE || process.env.BUNNY_CDN_URL || 'https://onekamer-media.b-cdn.net'

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('❌ SUPABASE_URL ou SUPABASE_SERVICE_KEY manquant')
  process.exit(1)
}
if (!BUNNY_STORAGE_ZONE || !BUNNY_STORAGE_KEY) {
  console.error('❌ BUNNY_STORAGE_ZONE ou BUNNY_STORAGE_KEY manquant')
  process.exit(1)
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

function parseArgs() {
  const args = process.argv.slice(2)
  const flags = { dryRun: false, limit: 0 }
  for (const a of args) {
    if (a === '--dry-run') flags.dryRun = true
    else if (a.startsWith('--limit=')) flags.limit = parseInt(a.split('=')[1] || '0', 10)
  }
  return flags
}

async function listSupabaseAudio(limit = 0) {
  // Liste tous les fichiers à la racine du bucket comments_audio
  const perPage = 1000
  let from = '' // dossier racine
  let page = 0
  const files = []
  while (true) {
    const { data, error } = await supabase.storage.from('comments_audio').list(from, {
      limit: perPage,
      offset: page * perPage,
      search: ''
    })
    if (error) throw error
    if (!data || data.length === 0) break
    for (const f of data) {
      if (f.id) continue // supabase v2 list ne renvoie pas id, on garde name
      if (f.name) files.push(f.name)
    }
    page++
    if (limit && files.length >= limit) break
  }
  return limit ? files.slice(0, limit) : files
}

async function bunnyHeadExists(filename) {
  const url = `https://storage.bunnycdn.com/${encodeURIComponent(BUNNY_STORAGE_ZONE)}/comments_audio/${encodeURIComponent(filename)}`
  const res = await fetch(url, {
    method: 'HEAD',
    headers: { AccessKey: BUNNY_STORAGE_KEY },
  })
  return res.status === 200
}

async function downloadFromSupabase(filename) {
  const { data, error } = await supabase.storage.from('comments_audio').download(filename)
  if (error) throw error
  return data // Blob
}

async function uploadToBunny(filename, blob) {
  const url = `https://storage.bunnycdn.com/${encodeURIComponent(BUNNY_STORAGE_ZONE)}/comments_audio/${encodeURIComponent(filename)}`
  const arrayBuffer = await blob.arrayBuffer()
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      AccessKey: BUNNY_STORAGE_KEY,
      'Content-Type': 'application/octet-stream',
    },
    body: Buffer.from(arrayBuffer)
  })
  if (!res.ok) {
    const txt = await res.text().catch(() => '')
    throw new Error(`Bunny upload failed ${res.status}: ${txt}`)
  }
}

async function updateCommentUrls(filename, newUrl) {
  // Met à jour toutes les lignes comments.audio_url qui contiennent ce filename
  const { data, error } = await supabase
    .from('comments')
    .update({ audio_url: newUrl })
    .like('audio_url', `%${filename}%`)
    .select('id')
  if (error) throw error
  return data?.map(r => r.id) || []
}

async function insertLog({ commentIds, filename, oldUrl, newUrl, status, error }) {
  // Insère une ligne par commentaire touché; si aucun, log global sans comment_id
  if (commentIds && commentIds.length) {
    const rows = commentIds.map(cid => ({ comment_id: cid, old_url: oldUrl || null, new_url: newUrl, filename, status, error }))
    const { error: e2 } = await supabase.from('migrations_audio_log').insert(rows)
    if (e2) console.warn('⚠️ log insert error:', e2.message)
  } else {
    const { error: e2 } = await supabase.from('migrations_audio_log').insert([{ filename, old_url: oldUrl || null, new_url: newUrl, status, error }])
    if (e2) console.warn('⚠️ log insert error:', e2.message)
  }
}

async function main() {
  const { dryRun, limit } = parseArgs()
  console.log(`▶️ Migration comments_audio -> Bunny | dryRun=${dryRun} limit=${limit||'all'}`)

  const files = await listSupabaseAudio(limit)
  console.log(`📦 Fichiers détectés (Supabase): ${files.length}`)

  for (const filename of files) {
    const targetUrl = `${BUNNY_CDN_BASE}/comments_audio/${filename}`
    try {
      const exists = await bunnyHeadExists(filename)
      if (exists) {
        console.log(`✅ Déjà présent sur Bunny: ${filename}`)
        if (!dryRun) {
          // Mettre à jour DB quand même pour pointer CDN si besoin
          const ids = await updateCommentUrls(filename, targetUrl)
          await insertLog({ commentIds: ids, filename, newUrl: targetUrl, status: 'updated' })
        }
        continue
      }

      if (dryRun) {
        console.log(`📝 [dry-run] Copier -> Bunny: ${filename} -> ${targetUrl}`)
        await insertLog({ commentIds: [], filename, newUrl: targetUrl, status: 'planned' })
        continue
      }

      // Téléchargement puis upload
      const blob = await downloadFromSupabase(filename)
      await uploadToBunny(filename, blob)

      // Mise à jour DB
      const ids = await updateCommentUrls(filename, targetUrl)
      await insertLog({ commentIds: ids, filename, newUrl: targetUrl, status: 'updated' })
      console.log(`🚚 Migré: ${filename} (${ids.length} refs mises à jour)`)      
    } catch (e) {
      console.error(`❌ Erreur sur ${filename}:`, e.message)
      await insertLog({ commentIds: [], filename, newUrl: targetUrl, status: 'failed', error: e.message })
    }
  }

  console.log('🏁 Terminé')
}

main().catch(err => {
  console.error('Fatal:', err)
  process.exit(1)
})
