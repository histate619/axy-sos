// 公開版的解密（瀏覽器 WebCrypto；Node 18+ 也有同樣的 API，可單測）。
// vault.json 格式見 tools/lb-encrypt.mjs：PBKDF2-SHA256 → AES-256-GCM，明文是 gzip 過的 JSON。
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0))
const b64e = u => btoa(String.fromCharCode(...u))

export async function deriveKeyBytes(password, vault) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: b64d(vault.kdf.salt), iterations: vault.kdf.iter }, base, 256)
  return new Uint8Array(bits)
}

// 密碼錯 → AES-GCM 驗證失敗而拋錯；呼叫端據此顯示「密碼錯誤」
export async function openVault(keyBytes, vault) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt'])
  const gz = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(vault.iv) }, key, b64d(vault.ct))
  const text = await new Response(new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip'))).text()
  return JSON.parse(text)
}

export const keyToText = b64e
export const keyFromText = b64d
