'use strict';
// The screens of linking a device (docs/m5-linking.md): a QR code with a code to type instead, a camera scan where the
// browser can read codes, a comparison step ("do both screens show the same numbers?"), and the recovery warning.
// The protocol (keys, server calls) registers itself with Linking.register(); until it does, the entry points stay
// hidden. This file only draws and asks.
(() => {
  const $ = id => document.getElementById(id);
  let flows = null, active = null, scanning = null;

  /** Groups of four digits or letters, easier to read aloud and type: "4821 9930 5512". */
  const spaced = code => String(code).replace(/\s+/g, '').replace(/(.{4})(?=.)/g, '$1 ');

  function reset() {
    stopScan();
    for (const id of ['link-qr-box', 'link-entry', 'link-confirm', 'link-scan-box']) $(id).hidden = true;
    $('link-qr').replaceChildren(); $('link-code').textContent = ''; $('link-status').textContent = ''; $('link-code-input').value = '';
    $('link-cancel').textContent = 'Cancel'; $('link-alt').hidden = true;
    $('link-code-label').textContent = 'Code from your other device'; $('link-code-input').placeholder = '1234 5678 9012'; $('link-code-submit').textContent = 'Link';
  }
  /**
   * Opens the dialog. `qr`: text to show as a QR code (with `code`, the same thing to type instead). `entry`: let the
   * user type (or scan) the other device's code; `onEntry(text)` gets it and may throw to show an error.
   * Without `qr`, `code` alone is shown (the short code, §1.7). `entry` may be `{ label, placeholder, submit }` to ask
   * for something else (a username). `alt`: `{ label, run }`, a second way to do this (e.g. a code instead of a QR).
   * Returns a handle for the next steps; `onCancel` runs if the user closes it.
   */
  function open({ title, hint, qr, code, entry, onEntry, onCancel, alt }) {
    close();
    reset();
    active = { onCancel };
    $('link-title').textContent = title; $('link-hint').textContent = hint || '';
    if (qr) { $('link-qr').append(window.QR.svg(qr, `${title}: QR code`)); $('link-code').textContent = code ? spaced(code) : ''; $('link-code-note').textContent = 'Or type this code on the other device:'; $('link-qr-box').hidden = false; }
    else if (code) { $('link-code').textContent = spaced(code); $('link-code-note').textContent = 'Type this code on your primary device:'; $('link-qr-box').hidden = false; }
    if (alt) { $('link-alt').textContent = alt.label; $('link-alt').hidden = false; $('link-alt').onclick = () => { const { run } = alt; close(); run(); }; }
    if (entry) {
      if (typeof entry === 'object') { $('link-code-label').textContent = entry.label; $('link-code-input').placeholder = entry.placeholder || ''; $('link-code-submit').textContent = entry.submit || 'Next'; }
      $('link-entry').hidden = false;
      const submit = async text => {
        $('link-code-submit').disabled = true; $('link-status').textContent = 'Checking…';
        try { await onEntry(text.replace(/\s+/g, '')); } // Pasted or typed in groups: spaces never matter. catch (error) { $('link-status').textContent = error.message || 'That didn’t work. Check the code and try again.'; }
        finally { $('link-code-submit').disabled = false; }
      };
      $('link-code-form').onsubmit = event => { event.preventDefault(); const text = $('link-code-input').value; if (text.trim()) submit(text); };
      $('link-scan').hidden = typeof window.BarcodeDetector !== 'function';
      $('link-scan').onclick = async () => {
        try {
          $('link-scan-box').hidden = false;
          scanning = await window.QR.scanner($('link-video'));
          if (!scanning) { $('link-scan-box').hidden = true; $('link-status').textContent = 'This browser can’t read codes with the camera. Type the code instead.'; return; }
          const text = await scanning.result; scanning = null; $('link-scan-box').hidden = true;
          if (text) submit(text);
        } catch { stopScan(); $('link-status').textContent = 'Couldn’t use the camera. Type the code instead.'; }
      };
    }
    $('link-dialog').hidden = false;
    (entry ? $('link-code-input') : $('link-cancel')).focus();
    return {
      status: text => { if (active) { $('link-status').textContent = text; $('link-alt').hidden = true; } }, // Under way: no switching now.
      /** Both screens show the 6-digit code (shown "123 456", docs/m5-linking.md §1.2): does it match? Resolves true or false. */
      compare(numbers) {
        stopScan(); $('link-alt').hidden = true;
        for (const id of ['link-qr-box', 'link-entry', 'link-scan-box']) $(id).hidden = true;
        const digits = String(numbers).replace(/\s+/g, '');
        $('link-sas').textContent = /^\d{6}$/.test(digits) ? `${digits.slice(0, 3)} ${digits.slice(3)}` : digits; $('link-confirm').hidden = false; $('link-match').focus();
        return new Promise(resolve => { $('link-match').onclick = () => { $('link-confirm').hidden = true; resolve(true); }; $('link-mismatch').onclick = () => { $('link-confirm').hidden = true; resolve(false); }; });
      },
      done(text) { stopScan(); $('link-alt').hidden = true; for (const id of ['link-qr-box', 'link-entry', 'link-confirm', 'link-scan-box']) $(id).hidden = true; $('link-status').textContent = text; $('link-cancel').textContent = 'Done'; if (active) active.onCancel = null; },
      fail(text) { stopScan(); $('link-alt').hidden = true; $('link-status').textContent = text; $('link-cancel').textContent = 'Close'; },
      close,
    };
  }
  function stopScan() { scanning?.stop(); scanning = null; }
  function close() {
    if (!active) return;
    const { onCancel } = active; active = null;
    stopScan(); $('link-dialog').hidden = true;
    onCancel?.();
  }

  /** The recovery warning (no other device to link from). Resolves true only if the user chooses to start over. */
  function confirmRecovery() {
    $('recovery').hidden = false; $('recovery-cancel').focus();
    return new Promise(resolve => {
      $('recovery-cancel').onclick = () => { $('recovery').hidden = true; resolve(false); };
      $('recovery-yes').onclick = () => { $('recovery').hidden = true; resolve(true); };
    });
  }

  // ---------- The account backup (docs/m6-account-key.md §3.4, §4) ----------
  const nfkc = text => String(text).normalize('NFKC');
  // ponytail: a short list; the 14-character minimum already rules out most common passwords.
  const COMMON = new Set(['passwordpassword', 'password1234567', '12345678901234', 'qwertyuiopasdf', 'iloveyouiloveyou', 'correct horse battery staple', 'letmeinletmein1']);
  /** Copies `text`, and clears the clipboard after 60 s (secrets don't stay there). */
  function copySecret(text, status) {
    navigator.clipboard?.writeText(text).then(() => { status('Copied. The clipboard is cleared in 60 seconds.'); setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 60000); }, () => status('Couldn’t copy. Write it down instead.'));
  }
  /**
   * Unlocking this device with the backup (§4). `kind`: 'pass' or 'words'. `unlock(secret)` resolves the account's
   * safety number, or throws (shown; the user may try again). Resolves true once unlocked, false if cancelled.
   */
  function restore(kind, unlock) {
    const words = kind === 'words';
    $('restore-title').textContent = words ? 'Use your recovery key' : 'Enter your passphrase';
    $('restore-label').textContent = words ? 'Your 24 recovery words' : 'Passphrase';
    $('restore-label').htmlFor = words ? 'restore-words' : 'restore-input';
    $('restore-input').hidden = words; $('restore-words').hidden = !words; $('restore-note').hidden = !words;
    $('restore-input').value = ''; $('restore-words').value = ''; $('restore-status').textContent = '';
    $('restore-form').hidden = false; $('restore-done').hidden = true; $('restore-submit').disabled = false;
    $('restore').hidden = false; (words ? $('restore-words') : $('restore-input')).focus();
    return new Promise(resolve => {
      const finish = value => { $('restore').hidden = true; resolve(value); };
      $('restore-cancel').onclick = () => finish(false);
      $('restore-close').onclick = () => finish(true);
      $('restore-form').onsubmit = async event => {
        event.preventDefault();
        const secret = words ? $('restore-words').value : $('restore-input').value;
        if (!secret.trim()) return;
        $('restore-submit').disabled = true; $('restore-status').textContent = 'Unlocking… this takes a few seconds.';
        try {
          const safety = await unlock(secret);
          $('restore-form').hidden = true; $('restore-safety').textContent = safety || ''; $('restore-done').hidden = false; $('restore-close').focus();
        } catch (error) { $('restore-status').textContent = error.message || 'That didn’t work. Try again.'; $('restore-submit').disabled = false; }
      };
    });
  }
  /**
   * Turning the backup on or changing it (§3.4). `mode`: 'on', 'pass' (new passphrase), 'words' (new recovery
   * key) or 'off'. `ops.generate()` resolves a generated passphrase; `ops.prepare({ passphrase?, current? })` resolves
   * `{ words?, publish() }`: nothing is stored until publish(), after the user has shown they kept the words.
   */
  function backupFlow(mode, ops) {
    const show = step => { for (const name of ['pass', 'words', 'check']) $(`backup-step-${name}`).hidden = name !== step; };
    const status = text => { $('account-backup-status').textContent = text; };
    let custom = false, generated = '', prepared = null, step = 'pass', asked = [];
    $('backup-title').textContent = { on: 'Turn on account backup', pass: 'Change your passphrase', words: 'New recovery key', off: 'Turn off account backup' }[mode];
    $('backup-current-box').hidden = mode === 'on'; $('backup-current').value = '';
    $('backup-pass1').value = ''; $('backup-pass2').value = ''; status('');
    const choosing = mode === 'on' || mode === 'pass';
    $('backup-generated').hidden = !choosing; $('backup-custom').hidden = true;
    const useCustom = value => { custom = value; $('backup-generated').hidden = !choosing || value; $('backup-custom').hidden = !value; };
    $('backup-own').onclick = () => useCustom(true);
    $('backup-use-generated').onclick = () => useCustom(false);
    $('backup-copy-pass').onclick = () => copySecret(generated, status);
    if (choosing) ops.generate().then(value => { generated = value; $('backup-passphrase').textContent = value; }, () => useCustom(true));
    show('pass'); $('backup-next').textContent = 'Next'; $('backup-next').disabled = false;
    $('backup').hidden = false;
    return new Promise(resolve => {
      const finish = value => { $('backup').hidden = true; $('backup-words').replaceChildren(); $('backup-check').replaceChildren(); resolve(value); };
      $('backup-cancel').onclick = () => finish(false);
      $('backup-next').onclick = async () => {
        $('backup-next').disabled = true;
        try {
          if (step === 'pass') {
            let passphrase;
            if (choosing) {
              passphrase = nfkc(custom ? $('backup-pass1').value : generated);
              if (custom) {
                if ([...passphrase].length < 14) throw new Error('Use at least 14 characters, or the generated passphrase.');
                if (passphrase !== nfkc($('backup-pass2').value)) throw new Error('The two passphrases don’t match.');
                if (COMMON.has(passphrase.toLowerCase())) throw new Error('That passphrase is too common. Choose another.');
              }
            }
            const current = mode === 'on' ? undefined : $('backup-current').value;
            if (mode !== 'on' && !current) throw new Error('Enter your current passphrase or recovery key.');
            status('Securing your backup… this takes a few seconds.');
            prepared = await ops.prepare({ passphrase, current });
            status('');
            if (!prepared.words) { await prepared.publish(); finish(true); return; }
            const list = prepared.words.split(' ');
            $('backup-words').replaceChildren(...list.map(word => Object.assign(document.createElement('li'), { textContent: word })));
            $('backup-copy-words').onclick = () => copySecret(prepared.words, status);
            step = 'words'; show('words');
          } else if (step === 'words') {
            // Three positions at random: typing them back shows the words were kept.
            const list = prepared.words.split(' '), picks = new Set();
            const limit = 2 ** 32 - 2 ** 32 % list.length; // Rejection sampling: no modulo bias.
            while (picks.size < 3) { const value = crypto.getRandomValues(new Uint32Array(1))[0]; if (value < limit) picks.add(value % list.length); }
            asked = [...picks].sort((a, b) => a - b);
            $('backup-check').replaceChildren(...asked.flatMap(at => {
              const label = Object.assign(document.createElement('label'), { textContent: `Word ${at + 1}`, htmlFor: `backup-check-${at}` });
              const input = Object.assign(document.createElement('input'), { id: `backup-check-${at}`, autocomplete: 'off', spellcheck: false });
              input.autocapitalize = 'off';
              return [label, input];
            }));
            step = 'check'; show('check'); $('backup-next').textContent = 'Turn on'; status('');
            $(`backup-check-${asked[0]}`).focus();
          } else {
            const list = prepared.words.split(' ');
            const wrong = asked.find(at => { const typed = $(`backup-check-${at}`).value.trim().toLowerCase(); return !typed || (typed !== list[at] && !(typed.length >= 4 && list[at].startsWith(typed))); });
            if (wrong !== undefined) throw new Error(`Word ${wrong + 1} doesn’t match. Check your copy of the words.`);
            status('Saving…');
            await prepared.publish();
            finish(true);
          }
        } catch (error) { status(error.message || 'That didn’t work. Try again.'); }
        finally { $('backup-next').disabled = false; }
      };
    });
  }

  /**
   * Removing a device that could unlock the account (m6 §6.2): confirm, with the passphrase when a backup exists.
   * `run(secret)` does it (it may throw: shown, try again). Resolves `{ changePass }` when done ("Also change your
   * passphrase", §6.3: for when whoever had the device may have seen it), false if cancelled.
   */
  const ROTATE_TEXT = 'The device is signed out and can’t read new messages. Because it could unlock your account, your account gets a new key; your other devices pick it up by themselves and your contacts keep their verification.';
  function confirmRotation({ title, text = ROTATE_TEXT, action = 'Remove and change key', proof, run }) {
    $('keychange-title').textContent = title; $('keychange-text').textContent = text; $('keychange-yes').textContent = action; $('keychange-proof').hidden = !proof; $('keychange-pass').value = ''; $('keychange-status').textContent = '';
    $('keychange-change-pass').checked = false; $('keychange-yes').disabled = false; $('keychange').hidden = false; (proof ? $('keychange-pass') : $('keychange-cancel')).focus();
    return new Promise(resolve => {
      const finish = value => { $('keychange').hidden = true; resolve(value); };
      $('keychange-cancel').onclick = () => finish(false);
      $('keychange-form').onsubmit = async event => {
        event.preventDefault();
        if (proof && !$('keychange-pass').value.trim()) { $('keychange-status').textContent = 'Enter your passphrase or recovery key.'; return; }
        $('keychange-yes').disabled = true; $('keychange-status').textContent = 'Changing your account key…';
        try { await run($('keychange-pass').value); finish({ changePass: Boolean(proof && $('keychange-change-pass').checked) }); }
        catch (error) { $('keychange-status').textContent = error.message || 'That didn’t work. Try again.'; $('keychange-yes').disabled = false; }
      };
    });
  }
  /**
   * The protocol announces what this browser can do: `{ linkNew?, linkThis?, recover?, restorePass?, restoreWords? }`,
   * each a function the matching button runs. Buttons for missing flows stay hidden.
   */
  function register(next) {
    flows = next || null;
    for (const [id, name] of [['device-link-new', 'linkNew'], ['device-link-this', 'linkThis'], ['device-recover', 'recover'], ['device-restore-pass', 'restorePass'], ['device-restore-words', 'restoreWords']]) {
      const button = $(id);
      if (!button) continue;
      button.hidden = !flows?.[name];
      button.onclick = () => flows?.[name]?.();
    }
    window.dispatchEvent(new Event('linking-flows')); // Device rows redraw with the actions now offered.
  }

  const wire = () => {
    $('link-cancel').onclick = close;
    $('link-dialog').addEventListener('keydown', event => { if (event.key === 'Escape') { event.preventDefault(); close(); } });
    register(null);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire); else wire();

  /** Whether the protocol offers a flow (e.g. 'makePrimary' on device rows), and running it. */
  const can = name => typeof flows?.[name] === 'function';
  const run = (name, ...args) => flows?.[name]?.(...args);

  window.Linking = Object.freeze({ open, close, confirmRecovery, register, can, run, spaced, restore, backupFlow, confirmRotation });
})();
