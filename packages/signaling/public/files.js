'use strict';
// Attachments (docs/phase1-protocol.md §3): every file is encrypted on this device with a fresh AES-256-GCM key
// before upload, so the server only ever stores ciphertext (nonce || ciphertext || tag) under a random id. The key
// and the ciphertext's SHA-256 travel inside the end-to-end encrypted message. Downloads are verified against that
// hash before decrypting; decrypted bytes stay in memory as blob: URLs. Also: thumbnails (canvas), link-preview
// images and voice recording (MediaRecorder with a live level meter and a 64-bar waveform).
(() => {
  const MAX_SIZE = 25 * 1024 * 1024, THUMB_MAX = 4096, EAGER = 2 * 1024 * 1024;
  // Keyed by blob id AND ciphertext hash: an id the server hands out twice can never show content that this
  // message's sha256 did not verify.
  const cache = new Map(); // `${blob}.${sha256}` → Promise<{ url, blob }>
  const cacheKey = attachment => `${attachment.blob}.${attachment.sha256}`;
  // Bidi controls, isolates and zero-width characters let "report\u202Efdp.exe" read as "reportexe.pdf".
  const INVISIBLE = /[\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g;
  /** A file name as it really is: without characters that hide or reorder its extension. */
  const cleanName = name => String(name || '').replace(INVISIBLE, '').trim() || 'file';
  /** What we send: also without path parts, control characters or soft hyphens (as the apps send). */
  const outgoingName = name => cleanName(String(name || '').split(/[\\/]/).pop().replace(/[\u0000-\u001F\u007F-\u009F\u00AD]/g, ''));
  const coded = (code, message) => Object.assign(new Error(message), { code });

  const b64url = bytes => { let binary = ''; for (let at = 0; at < bytes.length; at += 8192) binary += String.fromCharCode(...bytes.subarray(at, at + 8192)); return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  const unb64url = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4)), character => character.charCodeAt(0));
  const sha256 = async bytes => b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));

  /** nonce(12) || AES-256-GCM(key, nonce, plaintext) with its 16-byte tag; no AAD. */
  async function encrypt(plaintext) {
    const raw = crypto.getRandomValues(new Uint8Array(32)), nonce = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, plaintext));
    const ciphertext = new Uint8Array(12 + sealed.length); ciphertext.set(nonce); ciphertext.set(sealed, 12);
    return { ciphertext, key: b64url(raw), sha256: await sha256(ciphertext) };
  }
  async function decrypt(ciphertext, keyText, expectedHash) {
    if (ciphertext.length < 28 || await sha256(ciphertext) !== expectedHash) throw coded('integrity', 'That file couldn’t be read.');
    try {
      const key = await crypto.subtle.importKey('raw', unb64url(keyText), 'AES-GCM', false, ['decrypt']);
      return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ciphertext.subarray(0, 12), tagLength: 128 }, key, ciphertext.subarray(12)));
    } catch { throw coded('integrity', 'That file couldn’t be read.'); }
  }

  /** Uploads ciphertext with progress (0–1). Resolves the server's blob id. */
  function upload(ciphertext, onProgress = () => {}, signal) {
    return new Promise((resolve, reject) => {
      const request = new XMLHttpRequest();
      request.open('POST', '/api/blobs');
      request.setRequestHeader('Content-Type', 'application/octet-stream');
      request.responseType = 'json';
      request.upload.onprogress = event => { if (event.lengthComputable) onProgress(event.loaded / event.total); };
      request.onload = () => {
        const id = request.response?.id;
        if (request.status >= 200 && request.status < 300 && typeof id === 'string' && /^[A-Za-z0-9_-]{16,64}$/.test(id)) { onProgress(1); resolve(id); }
        else reject(coded(request.status === 413 ? 'too-large' : request.status === 507 ? 'quota' : 'upload', request.response?.error || (request.status === 413 ? 'That file is too large to send.' : 'Couldn’t upload. Check your connection and try again.')));
      };
      request.onerror = () => reject(coded('upload', 'Couldn’t upload. Check your connection and try again.'));
      request.onabort = () => reject(coded('aborted', 'Upload cancelled.'));
      signal?.addEventListener('abort', () => request.abort(), { once: true });
      request.send(ciphertext);
    });
  }

  /** Downloads, verifies and decrypts an attachment once; later calls share the same in-memory blob: URL. */
  function open(attachment) {
    const id = cacheKey(attachment);
    if (!cache.has(id)) {
      const task = (async () => {
        const response = await fetch(`/api/blobs/${encodeURIComponent(attachment.blob)}`, { credentials: 'same-origin' });
        if (response.status === 404) throw coded('missing', 'This file is no longer on the server. Files are kept for 30 days.');
        if (!response.ok) throw coded('network', 'Couldn’t load.');
        const plaintext = await decrypt(new Uint8Array(await response.arrayBuffer()), attachment.key, attachment.sha256);
        const blob = new Blob([plaintext], { type: attachment.mime.split(';')[0] });
        return { blob, url: URL.createObjectURL(blob) };
      })();
      cache.set(id, task);
      task.catch(() => cache.delete(id)); // A failed load can be retried.
    }
    return cache.get(id);
  }
  /** Our own upload: its plaintext is already here, so showing it never downloads it back. */
  function remember(attachment, blob, url) { const id = cacheKey(attachment); if (!cache.has(id)) cache.set(id, Promise.resolve({ blob, url: url || URL.createObjectURL(blob) })); }
  const loaded = attachment => cache.has(cacheKey(attachment));
  /** Images and voice messages under 2 MiB load as soon as they are shown; everything else waits for a tap. */
  const eager = attachment => ['image', 'voice'].includes(attachment.kind) && attachment.size < EAGER;

  // ---------- Thumbnails ----------
  /** A tiny blurry JPEG placeholder of at most 4 KB (as a data: URL) from anything drawable. */
  function thumbFrom(source, width, height) {
    if (!width || !height) return undefined;
    const canvas = document.createElement('canvas'), context = canvas.getContext('2d');
    for (const [side, quality] of [[40, .6], [32, .5], [24, .45], [16, .4]]) {
      const scale = side / Math.max(width, height);
      canvas.width = Math.max(1, Math.round(width * scale)); canvas.height = Math.max(1, Math.round(height * scale));
      context.drawImage(source, 0, 0, canvas.width, canvas.height);
      const url = canvas.toDataURL('image/jpeg', quality);
      if (url.startsWith('data:image/jpeg;base64,') && url.length <= THUMB_MAX) return url;
    }
    return undefined;
  }
  /** The page's CSP allows blob: images but not data: ones, so placeholders are shown through a blob: URL. */
  function dataUrlToObjectUrl(dataUrl) {
    try {
      const [head, body] = dataUrl.split(',');
      return URL.createObjectURL(new Blob([Uint8Array.from(atob(body), character => character.charCodeAt(0))], { type: head.slice(5, head.indexOf(';')) }));
    } catch { return ''; }
  }
  function videoInfo(url) {
    return new Promise(resolve => {
      const video = document.createElement('video'), done = value => { clearTimeout(timer); video.removeAttribute('src'); video.load(); resolve(value); };
      const timer = setTimeout(() => done({}), 6000);
      video.muted = true; video.preload = 'metadata'; video.playsInline = true;
      video.onloadedmetadata = () => { video.currentTime = Math.min(0.1, (video.duration || 0) / 2); };
      video.onseeked = () => done({ width: video.videoWidth || undefined, height: video.videoHeight || undefined, duration: Number.isFinite(video.duration) ? Math.round(video.duration * 10) / 10 : undefined, thumb: thumbFrom(video, video.videoWidth, video.videoHeight) });
      video.onerror = () => done({});
      video.src = url;
    });
  }
  function audioInfo(url) {
    return new Promise(resolve => {
      const audio = document.createElement('audio'), done = value => { clearTimeout(timer); resolve(value); };
      const timer = setTimeout(() => done({}), 4000);
      audio.preload = 'metadata';
      audio.onloadedmetadata = () => done(Number.isFinite(audio.duration) ? { duration: Math.round(audio.duration * 10) / 10 } : {});
      audio.onerror = () => done({});
      audio.src = url;
    });
  }
  /** What a picked, dropped or pasted file becomes: kind, dimensions, duration and placeholder. */
  async function describe(file) {
    const mime = (file.type || 'application/octet-stream').toLowerCase(), name = outgoingName(file.name).slice(-120);
    const base = { mime: /^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*/.test(mime) ? mime.slice(0, 100) : 'application/octet-stream', name, size: file.size };
    const local = URL.createObjectURL(file);
    try {
      if (mime.startsWith('image/') && mime !== 'image/svg+xml') {
        try {
          const bitmap = await createImageBitmap(file);
          const info = { ...base, kind: 'image', width: bitmap.width, height: bitmap.height, thumb: thumbFrom(bitmap, bitmap.width, bitmap.height) };
          bitmap.close?.();
          return { info, local };
        } catch { /* A format this browser cannot draw (e.g. HEIC) still goes as a file. */ }
      }
      if (mime.startsWith('video/')) { const extra = await videoInfo(local); return { info: { ...base, kind: 'video', ...strip(extra) }, local }; }
      if (mime.startsWith('audio/')) { const extra = await audioInfo(local); return { info: { ...base, kind: 'audio', ...strip(extra) }, local }; }
      return { info: { ...base, kind: 'file' }, local };
    } catch { return { info: { ...base, kind: 'file' }, local }; }
  }
  const strip = value => Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));

  /** A link preview's image, fetched through the server's checked proxy and shrunk to a ≤ 4 KB placeholder. */
  async function linkThumb(imageUrl) {
    try {
      const response = await fetch(`/api/unfurl/image?url=${encodeURIComponent(imageUrl)}`, { credentials: 'same-origin' });
      if (!response.ok) return undefined;
      const bitmap = await createImageBitmap(await response.blob());
      const thumb = thumbFrom(bitmap, bitmap.width, bitmap.height); bitmap.close?.();
      return thumb;
    } catch { return undefined; }
  }

  // ---------- Voice messages ----------
  // AAC in MP4 first: the apps' players on Apple platforms (AVFoundation) cannot play WebM/Opus. Playback takes either.
  const VOICE_TYPES = ['audio/mp4;codecs=mp4a.40.2', 'audio/mp4', 'audio/webm;codecs=opus', 'audio/ogg;codecs=opus'];
  const voiceSupported = () => Boolean(globalThis.MediaRecorder && navigator.mediaDevices?.getUserMedia);
  /** Up to 64 bars of 0–31 from level samples, scaled to the loudest moment. */
  function waveform(samples, bars = 64) {
    if (!samples.length) return [];
    const count = Math.min(bars, samples.length), out = [], peak = Math.max(...samples, 0.02);
    for (let bar = 0; bar < count; bar++) {
      const from = Math.floor(bar * samples.length / count), to = Math.max(from + 1, Math.floor((bar + 1) * samples.length / count));
      const level = Math.max(...samples.slice(from, to));
      out.push(Math.max(0, Math.min(31, Math.round(Math.sqrt(level / peak) * 31))));
    }
    return out;
  }
  /** Starts recording. onLevel(0–1) drives the meter. stop() resolves { blob, mime, duration, waveform }. */
  async function record(onLevel = () => {}) {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true } });
    const mime = VOICE_TYPES.find(type => MediaRecorder.isTypeSupported?.(type)) || '';
    // Chromium's AAC encoder produces nothing at 32 kbps; speech AAC uses 64 kbps, Opus 32 kbps.
    const recorder = new MediaRecorder(stream, mime ? { mimeType: mime, audioBitsPerSecond: mime.startsWith('audio/mp4') ? 64000 : 32000 } : undefined);
    const chunks = [], samples = [], started = performance.now();
    let audio, timer;
    try {
      audio = new AudioContext();
      const analyser = audio.createAnalyser(); analyser.fftSize = 1024;
      audio.createMediaStreamSource(stream).connect(analyser);
      const data = new Float32Array(analyser.fftSize);
      timer = setInterval(() => {
        analyser.getFloatTimeDomainData(data);
        let sum = 0; for (const value of data) sum += value * value;
        const level = Math.min(1, Math.sqrt(sum / data.length) * 4);
        samples.push(level); onLevel(level);
      }, 50);
    } catch { /* No meter: recording still works. */ }
    recorder.ondataavailable = event => { if (event.data.size) chunks.push(event.data); };
    recorder.start(250);
    const release = () => { clearInterval(timer); stream.getTracks().forEach(track => track.stop()); audio?.close().catch(() => {}); };
    return {
      get elapsed() { return (performance.now() - started) / 1000; },
      stop: () => new Promise(resolve => {
        let done = false;
        // An encoder that never reports stopping must not hang the composer: finish with what was recorded.
        const timer = setTimeout(() => recorder.onstop?.(), 3000);
        recorder.onstop = () => {
          if (done) return; done = true; clearTimeout(timer);
          release();
          const type = (recorder.mimeType || mime || 'audio/webm').toLowerCase();
          resolve({ blob: new Blob(chunks, { type }), mime: type, duration: Math.round((performance.now() - started) / 100) / 10, waveform: waveform(samples) });
        };
        if (recorder.state !== 'inactive') recorder.stop(); else recorder.onstop();
      }),
      cancel() { recorder.onstop = null; if (recorder.state !== 'inactive') recorder.stop(); release(); },
    };
  }

  const size = bytes => bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${Math.round(bytes / 1024)} KB` : `${(bytes / 1048576).toFixed(bytes < 10485760 ? 1 : 0)} MB`;
  const duration = seconds => { const total = Math.max(0, Math.round(seconds || 0)); return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, '0')}`; };

  window.Files = Object.freeze({ MAX_SIZE, encrypt, decrypt, upload, open, remember, loaded, cleanName, eager, describe, thumbFrom, dataUrlToObjectUrl, linkThumb, voiceSupported, record, waveform, size, duration, b64url, unb64url });
})();
