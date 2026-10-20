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
    $('link-cancel').textContent = 'Cancel';
  }
  /**
   * Opens the dialog. `qr`: text to show as a QR code (with `code`, the same thing to type instead). `entry`: let the
   * user type (or scan) the other device's code; `onEntry(text)` gets it and may throw to show an error.
   * Returns a handle for the next steps; `onCancel` runs if the user closes it.
   */
  function open({ title, hint, qr, code, entry, onEntry, onCancel }) {
    close();
    reset();
    active = { onCancel };
    $('link-title').textContent = title; $('link-hint').textContent = hint || '';
    if (qr) { $('link-qr').append(window.QR.svg(qr, `${title}: QR code`)); $('link-code').textContent = code ? spaced(code) : ''; $('link-qr-box').hidden = false; }
    if (entry) {
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
      status: text => { if (active) $('link-status').textContent = text; },
      /** Both screens show the 6-digit code (shown "123 456", docs/m5-linking.md §1.2): does it match? Resolves true or false. */
      compare(numbers) {
        stopScan();
        for (const id of ['link-qr-box', 'link-entry', 'link-scan-box']) $(id).hidden = true;
        const digits = String(numbers).replace(/\s+/g, '');
        $('link-sas').textContent = /^\d{6}$/.test(digits) ? `${digits.slice(0, 3)} ${digits.slice(3)}` : digits; $('link-confirm').hidden = false; $('link-match').focus();
        return new Promise(resolve => { $('link-match').onclick = () => { $('link-confirm').hidden = true; resolve(true); }; $('link-mismatch').onclick = () => { $('link-confirm').hidden = true; resolve(false); }; });
      },
      done(text) { stopScan(); for (const id of ['link-qr-box', 'link-entry', 'link-confirm', 'link-scan-box']) $(id).hidden = true; $('link-status').textContent = text; $('link-cancel').textContent = 'Done'; if (active) active.onCancel = null; },
      fail(text) { stopScan(); $('link-status').textContent = text; $('link-cancel').textContent = 'Close'; },
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

  /**
   * The protocol announces what this browser can do: `{ linkNew?, linkThis?, recover? }`, each a function the
   * matching button runs. Buttons for missing flows stay hidden.
   */
  function register(next) {
    flows = next || null;
    for (const [id, name] of [['device-link-new', 'linkNew'], ['device-link-this', 'linkThis'], ['device-recover', 'recover']]) {
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

  window.Linking = Object.freeze({ open, close, confirmRecovery, register, can, run, spaced });
})();
