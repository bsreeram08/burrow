//! The account key on every device and its encrypted backup (docs/m6-account-key.md): pinned vectors for the ports
//! (computed independently in Python with argon2-cffi and cryptography), the box, the record and the rekey, then the
//! flows through the core and the JSON commands.
#![cfg(feature = "mls")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chatcore::account_key::*;
use chatcore::commands::respond;
use chatcore::core::Core;
use chatcore::store::MemoryStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn core() -> Core { Core::new(Box::new(MemoryStore::default())) }
fn b64(bytes: &[u8]) -> String { URL_SAFE_NO_PAD.encode(bytes) }
fn unb64(text: &str) -> Vec<u8> { URL_SAFE_NO_PAD.decode(text).unwrap() }
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn id() -> String { b64(&rand_core::RngCore::next_u64(&mut rand_core::OsRng).to_be_bytes().repeat(2)) }
fn code_of<T>(result: Result<T, chatcore::ChatError>) -> Option<String> { result.err().and_then(|e| e.code) }
fn arr32(bytes: Vec<u8>) -> [u8; 32] { bytes.try_into().unwrap() }

const USER: &str = "AAECAwQFBgcICQoLDA0ODw";
const DEVICE: &str = "EBESExQVFhcYGRobHB0eHw";
const PASSPHRASE: &str = "correct horse battery staple";

fn seed() -> [u8; 32] { std::array::from_fn(|i| 1 + i as u8) }
fn dh() -> [u8; 32] { std::array::from_fn(|i| 0x40 + i as u8) }
fn salt() -> [u8; 16] { std::array::from_fn(|i| i as u8) }
fn entropy() -> [u8; 32] { std::array::from_fn(|i| i as u8) }

#[test]
fn the_account_key_bytes_are_pinned_and_parsed_strictly() {
    let bytes = account_key_bytes(USER, &seed(), &dh());
    assert_eq!(b64(&bytes), "ABl3ZWJydGMtYnVuLWFjY291bnQta2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f");
    assert_eq!(bytes.len(), 95 + USER.len(), "117 bytes for a 22-character user id");
    assert_eq!(b64(&sign_public(&seed())), "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ");
    assert_eq!(b64(&dh_public(&dh())), "eaYx7t4b-cmPEgMs3q3Q56B5OY_HhriMyEbsia-FpRo");
    let (user, parsed_seed, parsed_dh) = parse_account_key(&bytes).unwrap();
    assert_eq!((user.as_str(), *parsed_seed, *parsed_dh), (USER, seed(), dh()));
    // Exact label, exact lengths, nothing after.
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(parse_account_key(&trailing).is_err());
    assert!(parse_account_key(&bytes[..bytes.len() - 1]).is_err());
    let mut relabeled = bytes.to_vec();
    relabeled[2] ^= 1;
    assert!(parse_account_key(&relabeled).is_err());
    assert!(parse_account_key(&[]).is_err());
}

#[test]
fn the_unlock_keys_and_their_proofs_are_pinned() {
    // Argon2id (m = 64 MiB, t = 3, p = 1), then HKDF-SHA-256 with no salt for the secret and for the proof.
    let seed_bytes = pass_seed(PASSPHRASE, &salt(), KDF_M, KDF_T, KDF_P).unwrap();
    assert_eq!(b64(&*seed_bytes), "DRo8ZSPI8G5OCvnFFapbVEjP69aDjy1Sw9i2743cPC4");
    let secret = pass_secret(&seed_bytes);
    assert_eq!(b64(&*secret), "sF38rvX1P-b5jXCxGiGTZEtpMeCT7AEmPVrYKedalxM");
    assert_eq!(b64(&dh_public(&secret)), "PPCKyg-NB-6w8OEHe2_Z30fvNjIIOXRJwaWn4iSDyxY");
    assert_eq!(b64(&*pass_proof(&seed_bytes)), "C9g-jJrsploDsMuNH52rbLTMfoDU_9vORpUpp-pGYoM");
    assert_ne!(*pass_proof(&seed_bytes), *secret, "the proof is not the secret");
    // The passphrase is NFKC-normalized first: a full-width spelling is the same passphrase.
    let wide = pass_seed("\u{ff43}orrect horse battery staple", &salt(), KDF_M, KDF_T, KDF_P).unwrap();
    assert_eq!(*wide, *seed_bytes);
    assert!(check_new_passphrase("exactly14chars").is_ok());
    assert!(check_new_passphrase("thirteen char").is_err());
    assert!(pass_seed("x", &salt(), 4, 1, 1).is_err(), "parameters below the Argon2 minimum are refused");

    // 24 BIP-39 words, the recovery unlock key and its proof for entropy 00..1f.
    assert_eq!(words_from_entropy(&entropy()).join(" "), "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware");
    assert_eq!(b64(&*recovery_secret(&entropy())), "EMyQf31HUcUQGoNU1fuvAkpzn1dlJ25sNXk6JCHYfhI");
    assert_eq!(b64(&dh_public(&recovery_secret(&entropy()))), "osIiZH2Qf6a3UUY_8wACozHYmpvt3CyQlfpc3Kld6D8");
    assert_eq!(b64(&*recovery_proof(&entropy())), "8M1ElR7RU5dET5kZDE0Tzvw21P49Sot8f0ZCaK68NwI");
    // The hashes the server holds.
    assert_eq!(sha256_b64(&dh_public(&secret)), "JilsP2l9Gs92M24r_r3KSBU2VWN-lXd7IKQM3VyzkjE");
    assert_eq!(sha256_b64(&dh_public(&recovery_secret(&entropy()))), "HgfQNEOC-bkgOdITk7FWHNtgdKuuNMlvxjISyKYnKY4");
    assert_eq!(sha256_b64(&*pass_proof(&seed_bytes)), "mqPAZy0FgljKYg-02W_5gq0OqYSD4DMigMVgfYrmQBc");
    assert_eq!(sha256_b64(&*recovery_proof(&entropy())), "Mu1yfcNQRu2CcoN5m7F4CW4WCrm8WsP66nJxF3hdZps");
}

#[test]
fn a_generated_passphrase_is_six_words_and_new() {
    let (one, two) = (generate_passphrase(), generate_passphrase());
    assert_eq!(one.split(' ').count(), 6);
    assert_ne!(one, two);
    assert!(check_new_passphrase(&one).is_ok(), "always long enough");
    let list = include_str!("../src/account/bip39_english.txt");
    assert!(one.split(' ').all(|word| list.lines().any(|line| line == word)));
}

#[test]
fn recovery_words_are_read_forgivingly_and_checked() {
    let words = words_from_entropy(&entropy()).join(" ");
    assert_eq!(*entropy_from_words(&words).unwrap(), entropy());
    assert_eq!(*entropy_from_words(&format!("  {}\n", words.to_uppercase().replace(' ', "\n\t "))).unwrap(), entropy(), "case and whitespace");
    let four: Vec<String> = words.split(' ').map(|w| w.chars().take(4).collect()).collect();
    assert_eq!(*entropy_from_words(&four.join(" ")).unwrap(), entropy(), "first four letters");
    assert_eq!(*entropy_from_words(&words.replace("abandon", "\u{ff41}bandon")).unwrap(), entropy(), "NFKD folds width forms");
    // Wrong count, an unknown word, a failed checksum (swap two words): all `invalid`.
    for bad in [words.rsplit_once(' ').unwrap().0.to_string(), format!("{words} abandon"), words.replacen("abandon", "zzzz", 1), {
        let mut parts: Vec<&str> = words.split(' ').collect();
        parts.swap(0, 1);
        parts.join(" ")
    }] {
        assert_eq!(code_of(entropy_from_words(&bad)).as_deref(), Some("invalid"), "{bad}");
    }
}

#[test]
fn the_boxes_the_keys_bytes_and_the_rekey_bytes_are_pinned() {
    let pass_secret = pass_secret(&pass_seed(PASSPHRASE, &salt(), KDF_M, KDF_T, KDF_P).unwrap());
    let (pass_pub, recovery_pub) = (dh_public(&pass_secret), dh_public(&recovery_secret(&entropy())));
    let aik_sign = sign_public(&seed());
    let account_key = account_key_bytes(USER, &seed(), &dh());
    let keys = BackupKeys { epoch: 1, pass_pub, recovery_pub };
    let aad = backup_aad(USER, &aik_sign, 1);
    assert_eq!(b64(&aad), "ABR3ZWJydGMtYnVuLWJhY2t1cC12MQAWQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyB5tVYuj-ZU-UB4sRLoqYunkB-FOuaVvtfg45ELrQSWZAAAAAE");
    let plain = backup_plaintext(&account_key, &keys);
    assert_eq!(b64(&plain), "ABl3ZWJydGMtYnVuLWFjY291bnQta2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fIDzwisoPjQfusPDhB3tv2d9H7zYyCDl0ScGlp-Ikg8sWIKLCImR9kH-mt1FGP_MAAqMx2Jqb7dwskJX6XNypXeg_");
    let boxed = seal_box_with(&pass_pub, &plain, &aad, BACKUP_BOX_INFO, &[0x55; 32], &std::array::from_fn(|i| i as u8)).unwrap();
    assert_eq!(boxed, "OKtmS9hvd9fma92a4HkpE6lP2LM6EmACfktGwfSITGcAAQIDBAUGBwgJCgsWLBsD6rpP9DSqKq9_zfes6NqYS-rYllmUb6VBc-zWnp2xWmwVDYR8oR43sicZKrZOtMJQX5KW-E5033Ph7Aape6plluH1rPRY1oKD50zVkgKr9pjUzR8BMka_rNpXVnLzIEeRHbuQ16I3RUFPu7ZrqCCknHufsrl6Tf4TYUYUL-mkRi9mlXFrTctpw25eovjDMU8NpZrkXIZQvzUhB23w5dVSPULAYn09vs-eIjGJBClDGbj3DqoRCeScMqc8TVxiBIYHxQRC");
    assert_eq!(unb64(&boxed).len(), box_length(USER));
    assert_eq!(unb64(&boxed).len(), 32 + 12 + 117 + 66 + 16);
    assert_eq!(*open_box(&pass_secret, &boxed, &aad, BACKUP_BOX_INFO).unwrap(), *plain);
    // Bound to the recipient, the account, the epoch and the purpose.
    assert_eq!(code_of(open_box(&[1u8; 32], &boxed, &aad, BACKUP_BOX_INFO)).as_deref(), Some("auth"));
    assert_eq!(code_of(open_box(&pass_secret, &boxed, &backup_aad("other", &aik_sign, 1), BACKUP_BOX_INFO)).as_deref(), Some("auth"));
    assert_eq!(code_of(open_box(&pass_secret, &boxed, &backup_aad(USER, &aik_sign, 2), BACKUP_BOX_INFO)).as_deref(), Some("auth"), "another epoch");
    assert_eq!(code_of(open_box(&pass_secret, &boxed, &aad, REKEY_BOX_INFO)).as_deref(), Some("auth"));
    let mut tampered = unb64(&boxed);
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(code_of(open_box(&pass_secret, &b64(&tampered), &aad, BACKUP_BOX_INFO)).as_deref(), Some("auth"));
    // A fresh seal differs every time (random ephemeral key and nonce) and still opens.
    let fresh = seal_box(&pass_pub, &plain, &aad, BACKUP_BOX_INFO).unwrap();
    assert_ne!(fresh, boxed);
    assert_eq!(*open_box(&pass_secret, &fresh, &aad, BACKUP_BOX_INFO).unwrap(), *plain);
    let ((owner, opened_seed, _), opened_keys) = parse_backup_plaintext(&plain, 1).unwrap();
    assert_eq!((owner.as_str(), *opened_seed, opened_keys), (USER, seed(), keys.clone()));
    assert!(parse_backup_plaintext(&plain[..plain.len() - 1], 1).is_err());

    let h = |bytes: &[u8]| -> [u8; 32] { Sha256::digest(bytes).into() };
    let pass_proof_hash = h(&*pass_proof(&pass_seed(PASSPHRASE, &salt(), KDF_M, KDF_T, KDF_P).unwrap()));
    let recovery_proof_hash = h(&*recovery_proof(&entropy()));
    let signed = keys_bytes(USER, &aik_sign, 1, &salt(), KDF_M, KDF_T, KDF_P, &h(&pass_pub), &h(&recovery_pub), &pass_proof_hash, &recovery_proof_hash);
    assert_eq!(b64(&signed), "ABl3ZWJydGMtYnVuLWJhY2t1cC1rZXlzLXYyABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IHm1Vi6P5lT5QHixEuipi6eQH4U65pW-1-DjkQutBJZkAAAAARAAAQIDBAUGBwgJCgsMDQ4PAAEAAAAAAAMAAAABICYpbD9pfRrPdjNuK_69ykgVNlVjfpV3eyCkDN1cs5IxIB4H0DRDgvm5IDnSE5OxVhzbYHSrrjTJb8YyEsimJymOIJqjwGctBYJYymIPtNlv-YKtDqmEg-AzIoDFYH2K5kAXIDLtcn3DUEbtgnKDeZuxeAluFgq5vFrD-upycRd4XWab");
    assert_eq!(hex(&Sha256::digest(&signed)), "deccb6a4d30ffe8808cc17a5da29db8cfc47b2665f38bd340d4e1495a861b46c");

    let eph = arr32(unb64("HPV5q6RaELodHvBtkfyiqp7QoRUFFWUxVUBdCxjLmmc"));
    let leaf = arr32(unb64("_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg"));
    let rekey = rekey_bytes(USER, DEVICE, "web", &eph, &leaf, &aik_sign);
    assert_eq!(b64(&rekey), "ABN3ZWJydGMtYnVuLXJla2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3ABZFQkVTRXhRVkZoY1lHUm9iSEIwZUh3AAN3ZWIgHPV5q6RaELodHvBtkfyiqp7QoRUFFWUxVUBdCxjLmmcg_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hggebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ");
    assert_eq!(hex(&Sha256::digest(&rekey)), "e3ca3b897fd9bbcc3b6e3a672dd91964c6457673304c1dd18492c2d0d84c5c1e");
    // The rekey box is bound to the same bytes.
    let rekey_box = seal_box_with(&eph, br#"{"v":1,"accountKey":"ABl3ZWJydGMtYnVuLWFjY291bnQta2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f","cert":"{}","backupKeys":null}"#, &rekey, REKEY_BOX_INFO, &[0x66; 32], &std::array::from_fn(|i| 24 + i as u8)).unwrap();
    assert_eq!(rekey_box, "IZ5NgA2paNKl_LAJx4T0dGxxOO257khEtznoMLBc9CQYGRobHB0eHyAhIiNhSrDjtqoQO1fWdOC4JJd7itHxnenKEJSe_UjMT28l-2L6Sc1Bi_Vi-6hdFFYCtumiIxS3HUoybgEtTOP9lOcJztr_KnfCkQ_DV-ZQIWLtrqyIEZxFgWO8qE68SCYU8P0t6J6_0gt9i-BozrVIp_lJvWoTWalMYfpjw1QhrbUKn1G4FGY-KIz29_VGlg2p2JPyzHo0aT5OITkM67p2jtvg0xcelNhrnrmfqDpQCAIajhDnndAkjH-sugU393r_DmOgAgZsNxv7vl1mx8Sha04YQdMm_PkQ_qFWfqTzgJAcsP8");
    let eph_secret = arr32(unb64("d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c"));
    assert_eq!(open_box(&eph_secret, &rekey_box, &rekey, REKEY_BOX_INFO).unwrap().as_slice(), br#"{"v":1,"accountKey":"ABl3ZWJydGMtYnVuLWFjY291bnQta2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f","cert":"{}","backupKeys":null}"#);
    assert_eq!(code_of(open_box(&eph_secret, &rekey_box, &rekey_bytes(USER, DEVICE, "ios", &eph, &leaf, &aik_sign), REKEY_BOX_INFO)).as_deref(), Some("auth"), "bound to the platform");
}

#[test]
fn a_record_sealed_by_an_independent_implementation_opens_with_the_passphrase_and_with_the_words() {
    let record: Value = serde_json::from_str(r#"{"v": 1, "userId": "AAECAwQFBgcICQoLDA0ODw", "aikSign": "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ", "epoch": 1, "kdf": {"alg": "argon2id", "salt": "AAECAwQFBgcICQoLDA0ODw", "m": 65536, "t": 3, "p": 1}, "passHash": "JilsP2l9Gs92M24r_r3KSBU2VWN-lXd7IKQM3VyzkjE", "recoveryHash": "HgfQNEOC-bkgOdITk7FWHNtgdKuuNMlvxjISyKYnKY4", "pass": "OKtmS9hvd9fma92a4HkpE6lP2LM6EmACfktGwfSITGcAAQIDBAUGBwgJCgsWLBsD6rpP9DSqKq9_zfes6NqYS-rYllmUb6VBc-zWnp2xWmwVDYR8oR43sicZKrZOtMJQX5KW-E5033Ph7Aape6plluH1rPRY1oKD50zVkgKr9pjUzR8BMka_rNpXVnLzIEeRHbuQ16I3RUFPu7ZrqCCknHufsrl6Tf4TYUYUL-mkRi9mlXFrTctpw25eovjDMU8NpZrkXIZQvzUhB23w5dVSPULAYn09vs-eIjGJBClDGbj3DqoRCeScMqc8TVxiBIYHxQRC", "recovery": "3M-fwAGzRcd0dOduECG94E9-oO2O5h9_bxpOR6WvL1QMDQ4PEBESExQVFhfweaNLDNPHOCe15k7dxTP-jZ1gjVFpWxf0lDe9YM0N0D8BHV-qukb2pl3g1neUV-N0lqa3Y_2QSRImvKD0Hgybsfh8lXJsf_Ja4Vs1i-6krmBr7wJ0PFKcKUbu7pzgrDne8wJf0AfFuy5C69CxVnd0PlTaMNI1awcZXuXo4FxXQ0v6iDT0JIvJ27vUl8l-MrsWqL3yGkB7SLGZ0_NApRDr5Bi6AKf455LsVT1IaRy-b5oMnT9XJmTScLz8elkEUk6dQ3irW2Qd", "passProofHash": "mqPAZy0FgljKYg-02W_5gq0OqYSD4DMigMVgfYrmQBc", "recoveryProofHash": "Mu1yfcNQRu2CcoN5m7F4CW4WCrm8WsP66nJxF3hdZps", "signature": "EhMwHw3WQmZJsy3qCk_FrdvEeWuUBN-ycTLi1zXFtDn5i9UCND-796tr7N9z9scjUMK3IZbMf2Hfu_dTZvHbBg", "updatedAt": 1700000000000}"#).unwrap();
    let mut blank = core();
    let published = json!({ "dh": "eaYx7t4b-cmPEgMs3q3Q56B5OY_HhriMyEbsia-FpRo", "sign": "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ" });
    for secret in [json!({ "passphrase": PASSPHRASE }), json!({ "words": "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware" })] {
        let mut command = json!({ "cmd": "backupOpen", "userId": USER, "record": record, "published": published });
        command.as_object_mut().unwrap().extend(secret.as_object().unwrap().clone());
        let opened = call(&mut blank, command);
        assert_eq!(opened["accountKey"], json!("ABl3ZWJydGMtYnVuLWFjY291bnQta2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f"));
        assert_eq!(opened["backupKeys"], json!({ "epoch": 1, "passPub": "PPCKyg-NB-6w8OEHe2_Z30fvNjIIOXRJwaWn4iSDyxY", "recoveryPub": "osIiZH2Qf6a3UUY_8wACozHYmpvt3CyQlfpc3Kld6D8" }));
    }
    // The proofs the server has the hashes of.
    assert_eq!(call(&mut blank, json!({ "cmd": "backupProve", "record": record, "passphrase": PASSPHRASE }))["proof"], json!("C9g-jJrsploDsMuNH52rbLTMfoDU_9vORpUpp-pGYoM"));
    assert_eq!(call(&mut blank, json!({ "cmd": "backupProve", "record": record, "words": "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware" }))["proof"], json!("8M1ElR7RU5dET5kZDE0Tzvw21P49Sot8f0ZCaK68NwI"));
    assert_eq!(fails(&mut blank, json!({ "cmd": "backupProve", "record": record, "passphrase": "not the passphrase" })).as_deref(), Some("auth"));
    // Importing it into an empty core gives exactly the pinned identity; exporting returns the same bytes, and the AIK
    // signs the keys bytes to the pinned signature.
    call(&mut blank, json!({ "cmd": "importAccountKey", "userId": USER, "key": "ABl3ZWJydGMtYnVuLWFjY291bnQta2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f", "published": published }));
    assert_eq!(call(&mut blank, json!({ "cmd": "exportAccountKey", "userId": USER })), json!("ABl3ZWJydGMtYnVuLWFjY291bnQta2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f"));
    let mut unsigned = record.clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    unsigned.as_object_mut().unwrap().remove("updatedAt");
    assert_eq!(call(&mut blank, json!({ "cmd": "backupSignKeys", "userId": USER, "record": unsigned })), record["signature"]);
}

// ---------- Through the core ----------

fn call(core: &mut Core, command: Value) -> Value {
    let out = respond(core, &command);
    assert!(out.get("error").is_none(), "{command}: {out}");
    out["ok"].clone()
}
fn fails(core: &mut Core, command: Value) -> Option<String> { respond(core, &command).get("code").and_then(Value::as_str).map(str::to_string) }

/// A full core (account identity, one MLS device) and a companion of the same account holding its public identity.
struct World { alice: Core, companion: Core, user: String, alice_device: String, device: String, identity: chatcore::IdentityPub }

fn world() -> World {
    let (mut alice, mut companion) = (core(), core());
    let (user, alice_device, device) = (id(), id(), id());
    let identity = alice.identity().unwrap().public;
    call(&mut alice, json!({ "cmd": "mlsInitDevice", "userId": user, "deviceId": alice_device, "platform": "linux", "issuedAt": 1 }));
    let leaf = call(&mut companion, json!({ "cmd": "mlsDeviceLeaf" }));
    let mut devices = [alice_device.clone(), device.clone()];
    devices.sort();
    let list = json!({ "v": 1, "userId": user, "version": 1, "prevHash": "", "devices": devices.iter().map(|d| json!({ "deviceId": d, "addedAt": 1, "meta": "" })).collect::<Vec<_>>() });
    call(&mut alice, json!({ "cmd": "signDeviceList", "userId": user, "published": identity.sign, "list": list }));
    let cert = call(&mut alice, json!({ "cmd": "signDeviceCert", "userId": user, "deviceId": device, "platform": "web", "leafSigKey": leaf, "issuedAt": 5, "now": 5 }));
    call(&mut companion, json!({ "cmd": "companionSetup", "userId": user, "identity": identity, "cert": cert }));
    World { alice, companion, user, alice_device, device, identity }
}

fn stranger_identity() -> chatcore::IdentityPub { core().identity().unwrap().public }

#[test]
fn a_full_core_exports_its_key_and_a_companion_or_a_restore_imports_it_against_what_it_pins() {
    let mut w = world();
    let key = call(&mut w.alice, json!({ "cmd": "exportAccountKey", "userId": w.user })).as_str().unwrap().to_string();
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "exportAccountKey", "userId": w.user })).as_deref(), Some("companion"));
    // A key for another account, or for another identity than the one pinned, changes nothing.
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "importAccountKey", "userId": id(), "key": key })).as_deref(), Some("invalid"));
    let mut stranger = core();
    stranger.identity().unwrap();
    let foreign = stranger.export_account_key(&w.user).unwrap();
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "importAccountKey", "userId": w.user, "key": foreign })).as_deref(), Some("invalid"));
    assert!(w.companion.is_companion().unwrap(), "nothing changed");
    // The right one makes the companion full; its MLS certificate and pins stay.
    let held = call(&mut w.companion, json!({ "cmd": "importAccountKey", "userId": w.user, "key": key }));
    assert_eq!(held, json!(w.identity));
    assert!(!w.companion.is_companion().unwrap());
    assert_eq!(call(&mut w.companion, json!({ "cmd": "exportAccountKey", "userId": w.user })).as_str().unwrap(), key);
    assert_eq!(call(&mut w.companion, json!({ "cmd": "identity" })), json!(w.identity));
    // Again is a no-op for the same key.
    call(&mut w.companion, json!({ "cmd": "importAccountKey", "userId": w.user, "key": key }));

    // An empty core (a restore) needs the account's published identity to check against.
    let mut fresh = core();
    assert_eq!(fails(&mut fresh, json!({ "cmd": "importAccountKey", "userId": w.user, "key": key })).as_deref(), Some("invalid"));
    assert_eq!(fails(&mut fresh, json!({ "cmd": "importAccountKey", "userId": w.user, "key": key, "published": stranger.identity().unwrap().public })).as_deref(), Some("invalid"));
    assert!(!fresh.has_identity().unwrap());
    call(&mut fresh, json!({ "cmd": "importAccountKey", "userId": w.user, "key": key, "published": w.identity }));
    assert_eq!(call(&mut fresh, json!({ "cmd": "identity" })), json!(w.identity));
    // A core with its own, different identity does not take another.
    assert_eq!(fails(&mut stranger, json!({ "cmd": "importAccountKey", "userId": w.user, "key": key, "published": w.identity })).as_deref(), Some("invalid"));
}

/// A signed record made on `core` from a passphrase (and its pieces).
fn made(core: &mut Core, user: &str, passphrase: &str) -> (Value, Value) {
    let created = call(core, json!({ "cmd": "backupCreate", "userId": user, "passphrase": passphrase }));
    let mut record = created["record"].clone();
    record["signature"] = call(core, json!({ "cmd": "backupSignKeys", "userId": user, "record": record }));
    (record, created)
}

#[test]
fn a_backup_is_created_signed_opened_proved_changed_and_resealed_to_the_keys_the_device_holds() {
    let mut w = world();
    let (record, created) = made(&mut w.alice, &w.user, PASSPHRASE);
    let words = created["words"].as_str().unwrap().to_string();
    assert_eq!(words.split(' ').count(), 24);
    assert_eq!(record["epoch"], json!(1));
    assert_eq!(record["aikSign"], json!(w.identity.sign));
    // The server holds hashes, never unlock keys: the record has no public unlock key anywhere.
    let text = record.to_string();
    assert!(!text.contains(created["backupKeys"]["passPub"].as_str().unwrap()) && !text.contains(created["backupKeys"]["recoveryPub"].as_str().unwrap()));
    // The proofs hash to what the record holds.
    let hashed = |proof: &Value| sha256_b64(&unb64(proof.as_str().unwrap()));
    assert_eq!(json!(hashed(&created["passProof"])), record["passProofHash"]);
    assert_eq!(json!(hashed(&created["recoveryProof"])), record["recoveryProofHash"]);
    // Only a core that holds the key signs it.
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "backupSignKeys", "userId": w.user, "record": record })).as_deref(), Some("companion"));
    // A custom passphrase is at least 14 characters; a generated one always is.
    assert_eq!(fails(&mut w.alice, json!({ "cmd": "backupCreate", "userId": w.user, "passphrase": "thirteen char" })).as_deref(), Some("invalid"));
    let generated = call(&mut w.alice, json!({ "cmd": "passphraseGenerate" }));
    assert_eq!(generated.as_str().unwrap().split(' ').count(), 6);

    // Restore on a blank core: the passphrase or the words open it and return the AccountKey and the backup keys.
    let mut blank = core();
    let key = call(&mut w.alice, json!({ "cmd": "exportAccountKey", "userId": w.user }));
    let open = |blank: &mut Core, record: &Value, secret: Value| { let mut c = json!({ "cmd": "backupOpen", "userId": w.user, "record": record, "published": w.identity }); c.as_object_mut().unwrap().extend(secret.as_object().unwrap().clone()); respond(blank, &c) };
    let opened = open(&mut blank, &record, json!({ "passphrase": PASSPHRASE }));
    assert_eq!(opened["ok"]["accountKey"], key);
    assert_eq!(opened["ok"]["backupKeys"], created["backupKeys"]);
    assert_eq!(open(&mut blank, &record, json!({ "words": words.to_uppercase() }))["ok"]["accountKey"], key);
    assert_eq!(open(&mut blank, &record, json!({ "passphrase": "correct horse battery stapler" }))["code"], json!("auth"));
    let mut swapped: Vec<&str> = words.split(' ').collect();
    swapped.swap(0, 1);
    assert_eq!(open(&mut blank, &record, json!({ "words": swapped.join(" ") }))["code"], json!("invalid"));
    let other_words = call(&mut core(), json!({ "cmd": "backupCreate", "userId": w.user, "passphrase": "another good passphrase", "accountKey": key }))["words"].as_str().unwrap().to_string();
    assert_eq!(open(&mut blank, &record, json!({ "words": other_words }))["code"], json!("auth"));
    assert_eq!(open(&mut blank, &record, json!({}))["code"], json!("invalid"), "one of the two");
    // The record is checked before any secret is tried: unsigned, another key than published, a tampered hash, a cost out of range.
    let mut unsigned = record.clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    assert_eq!(open(&mut blank, &unsigned, json!({ "passphrase": PASSPHRASE }))["code"], json!("invalid"));
    let wrong_key = json!({ "cmd": "backupOpen", "userId": w.user, "record": record, "passphrase": PASSPHRASE, "published": stranger_identity() });
    assert_eq!(respond(&mut blank, &wrong_key)["code"], json!("auth"));
    let mut forged = record.clone();
    forged["passHash"] = json!(b64(&[9u8; 32]));
    assert_eq!(open(&mut blank, &forged, json!({ "passphrase": PASSPHRASE }))["code"], json!("auth"), "the signature covers the hashes");
    let mut cheap = record.clone();
    cheap["kdf"]["m"] = json!(8);
    assert_eq!(open(&mut blank, &cheap, json!({ "passphrase": PASSPHRASE }))["code"], json!("invalid"));
    let mut dear = record.clone();
    dear["kdf"]["t"] = json!(11);
    assert_eq!(open(&mut blank, &dear, json!({ "passphrase": PASSPHRASE }))["code"], json!("invalid"));
    assert_eq!(fails(&mut blank, json!({ "cmd": "backupOpen", "userId": id(), "record": record, "passphrase": PASSPHRASE })).as_deref(), Some("invalid"));

    // Proofs: the right secret, a wrong one.
    let proof = |core: &mut Core, record: &Value, secret: Value| { let mut c = json!({ "cmd": "backupProve", "record": record }); c.as_object_mut().unwrap().extend(secret.as_object().unwrap().clone()); respond(core, &c) };
    assert_eq!(proof(&mut blank, &record, json!({ "passphrase": PASSPHRASE }))["ok"]["proof"], created["passProof"]);
    assert_eq!(proof(&mut blank, &record, json!({ "words": words }))["ok"]["proof"], created["recoveryProof"]);
    assert_eq!(proof(&mut blank, &record, json!({ "passphrase": "something else entirely" }))["code"], json!("auth"));

    // The device keeps the backup keys; a change seals to those, at epoch + 1, and does not move the other side.
    call(&mut w.alice, json!({ "cmd": "backupKeysSet", "backupKeys": created["backupKeys"] }));
    assert_eq!(call(&mut w.alice, json!({ "cmd": "backupKeys" })), created["backupKeys"]);
    let changed = call(&mut w.alice, json!({ "cmd": "backupReseal", "userId": w.user, "record": record, "passphrase": "a brand new passphrase" }));
    assert!(changed["words"].is_null() && changed["recoveryProof"].is_null());
    let mut next = changed["record"].clone();
    assert_eq!((next["epoch"].clone(), next["recoveryHash"].clone(), next["recoveryProofHash"].clone()), (json!(2), record["recoveryHash"].clone(), record["recoveryProofHash"].clone()));
    assert_ne!(next["kdf"]["salt"], record["kdf"]["salt"]);
    assert_eq!(json!(hashed(&changed["passProof"])), next["passProofHash"]);
    next["signature"] = call(&mut w.alice, json!({ "cmd": "backupSignKeys", "userId": w.user, "record": next }));
    assert_eq!(open(&mut blank, &next, json!({ "passphrase": "a brand new passphrase" }))["ok"]["accountKey"], key);
    assert_eq!(open(&mut blank, &next, json!({ "words": words }))["ok"]["accountKey"], key, "the recovery words keep working");
    assert_eq!(open(&mut blank, &next, json!({ "passphrase": PASSPHRASE }))["code"], json!("auth"));
    call(&mut w.alice, json!({ "cmd": "backupKeysSet", "backupKeys": changed["backupKeys"] }));
    assert_eq!(fails(&mut w.alice, json!({ "cmd": "backupKeysSet", "backupKeys": created["backupKeys"] })).as_deref(), None);
    assert_eq!(call(&mut w.alice, json!({ "cmd": "backupKeys" }))["epoch"], json!(2), "a lower epoch never replaces a higher one");
    // A new recovery key: the old words stop working.
    let renewed = call(&mut w.alice, json!({ "cmd": "backupReseal", "userId": w.user, "record": next, "newRecovery": true }));
    let new_words = renewed["words"].as_str().unwrap().to_string();
    let mut third = renewed["record"].clone();
    assert_eq!((third["epoch"].clone(), third["passHash"].clone()), (json!(3), next["passHash"].clone()));
    third["signature"] = call(&mut w.alice, json!({ "cmd": "backupSignKeys", "userId": w.user, "record": third }));
    assert_eq!(open(&mut blank, &third, json!({ "words": new_words }))["ok"]["accountKey"], key);
    assert_eq!(open(&mut blank, &third, json!({ "words": words }))["code"], json!("auth"));
    // A record older than the keys held, or whose side does not match the local keys, is not resealed.
    assert_eq!(fails(&mut w.alice, json!({ "cmd": "backupReseal", "userId": w.user, "record": record })).as_deref(), Some("auth"), "epoch 1 against keys at epoch 2");
    let stale_keys = json!({ "cmd": "backupReseal", "userId": w.user, "record": third, "backupKeys": created["backupKeys"] });
    assert_eq!(fails(&mut w.alice, stale_keys).as_deref(), Some("auth"), "keys of another epoch do not match the record's hashes");
    // A record signed by a key this account never had is not resealed (a server swapping in a backup of its own).
    let mut mallory = core();
    mallory.identity().unwrap();
    let (theirs, theirs_created) = made(&mut mallory, &w.user, "mallory has a passphrase");
    call(&mut w.alice, json!({ "cmd": "backupKeysSet", "backupKeys": theirs_created["backupKeys"] }));
    assert_eq!(fails(&mut w.alice, json!({ "cmd": "backupReseal", "userId": w.user, "record": theirs })).as_deref(), Some("auth"));
}

#[test]
fn after_a_rotation_the_backup_is_resealed_to_the_keys_the_device_holds_with_the_new_account_key() {
    let mut w = world();
    let (record, created) = made(&mut w.alice, &w.user, PASSPHRASE);
    call(&mut w.alice, json!({ "cmd": "backupKeysSet", "backupKeys": created["backupKeys"] }));
    let old_sign = w.identity.sign.clone();
    // The account rotates (M5 succession, run by this device on itself): a new identity, the old one a predecessor.
    call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user, "at": 9_000, "commit": false }));
    let rotated = call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user }));
    let new_identity: chatcore::IdentityPub = serde_json::from_value(rotated["identity"].clone()).unwrap();
    let new_key = rotated["key"].as_str().unwrap().to_string();
    assert_eq!(w.alice.public_identity().unwrap(), new_identity);
    // No secret is needed: it seals to the backup keys it holds, which the record (signed by the key this core just left) commits to.
    let resealed = call(&mut w.alice, json!({ "cmd": "backupReseal", "userId": w.user, "record": record }));
    let mut updated = resealed["record"].clone();
    assert_eq!(updated["aikSign"], json!(new_identity.sign));
    assert_ne!(updated["aikSign"], json!(old_sign));
    assert_eq!((updated["epoch"].clone(), updated["passHash"].clone(), updated["passProofHash"].clone()), (json!(2), record["passHash"].clone(), record["passProofHash"].clone()));
    assert!(resealed["passProof"].is_null() && resealed["words"].is_null());
    updated["signature"] = call(&mut w.alice, json!({ "cmd": "backupSignKeys", "userId": w.user, "record": updated }));
    let mut blank = core();
    let opened = call(&mut blank, json!({ "cmd": "backupOpen", "userId": w.user, "record": updated, "passphrase": PASSPHRASE, "published": new_identity }));
    assert_eq!(opened["accountKey"].as_str().unwrap(), new_key, "the new account key, not the old one");
    // The old record still opens to the old key (a removed device keeps what it had), but names the old key.
    assert_ne!(call(&mut blank, json!({ "cmd": "backupOpen", "userId": w.user, "record": record, "passphrase": PASSPHRASE }))["accountKey"].as_str().unwrap(), new_key);
}

#[test]
fn a_record_signed_by_an_older_key_is_resealed_only_for_the_rotation_this_core_just_made() {
    let mut w = world();
    let (record, created) = made(&mut w.alice, &w.user, PASSPHRASE);
    call(&mut w.alice, json!({ "cmd": "backupKeysSet", "backupKeys": created["backupKeys"] }));
    let rotate = |w: &mut World, at: u64| { call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user, "at": at, "commit": false })); call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user })) };
    // Two rotations: a record signed two keys back is not the previous key of the rotation just made.
    rotate(&mut w, 1_000);
    rotate(&mut w, 2_000);
    assert_eq!(fails(&mut w.alice, json!({ "cmd": "backupReseal", "userId": w.user, "record": record })).as_deref(), Some("auth"));
    // A core that took the new key by import (a restore, a rekey) did not make a rotation: the previous key is no one's to re-seal for.
    let mut other = world();
    let (other_record, other_created) = made(&mut other.alice, &other.user, PASSPHRASE);
    call(&mut other.alice, json!({ "cmd": "backupKeysSet", "backupKeys": other_created["backupKeys"] }));
    let mut next = core();
    let new_identity = next.identity().unwrap().public;
    let new_key = next.export_account_key(&other.user).unwrap();
    other.alice.retire_identity(&other.user, &new_identity, 9_000).unwrap();
    other.alice.import_account_key(&other.user, &new_key, None).unwrap();
    assert_eq!(fails(&mut other.alice, json!({ "cmd": "backupReseal", "userId": other.user, "record": other_record })).as_deref(), Some("auth"));
}

#[test]
fn a_companion_asks_for_the_account_key_and_only_a_full_device_that_knows_its_leaf_answers() {
    let mut w = world();
    // A group both devices are in: the companion's leaf is then provable.
    let group = id();
    let roles = json!({ "v": 1, "kind": "group", "admins": [w.user], "joinPolicy": "invite" });
    call(&mut w.alice, json!({ "cmd": "mlsCreate", "group": group, "roles": roles }));
    let kps = call(&mut w.companion, json!({ "cmd": "mlsKeyPackages", "count": 1 }));
    let out = call(&mut w.alice, json!({ "cmd": "mlsCommit", "group": group, "adds": [kps[0]] }));
    call(&mut w.alice, json!({ "cmd": "mlsMergeOwn", "group": group }));
    let view = call(&mut w.alice, json!({ "cmd": "mlsView", "group": group }));
    call(&mut w.companion, json!({ "cmd": "mlsJoin", "welcome": out["welcome"], "tree": view["tree"] }));
    // This device keeps the backup keys; the rekey answer carries them.
    let (_, created) = made(&mut w.alice, &w.user, PASSPHRASE);
    call(&mut w.alice, json!({ "cmd": "backupKeysSet", "backupKeys": created["backupKeys"] }));

    assert_eq!(fails(&mut w.alice, json!({ "cmd": "rekeyRequest", "userId": w.user, "deviceId": w.alice_device, "platform": "linux" })).as_deref(), Some("invalid"), "a full device does not ask");
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "rekeyRequest", "userId": w.user, "deviceId": id(), "platform": "web" })).as_deref(), Some("invalid"), "only for itself");
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "rekeyRequest", "userId": w.user, "deviceId": w.device, "platform": "toaster" })).as_deref(), Some("invalid"));
    let request = call(&mut w.companion, json!({ "cmd": "rekeyRequest", "userId": w.user, "deviceId": w.device, "platform": "web" }));
    assert_eq!(call(&mut w.companion, json!({ "cmd": "rekeyRequest", "userId": w.user, "deviceId": w.device, "platform": "web" })), request, "asking again is the same request");
    let leaf = call(&mut w.companion, json!({ "cmd": "mlsDeviceLeaf" }));
    assert_eq!(request["leafSigKey"], leaf);
    // The signature is the leaf key's over the pinned rekey bytes.
    let bytes = rekey_bytes(&w.user, &w.device, "web", &arr32(unb64(request["eph"].as_str().unwrap())), &arr32(unb64(leaf.as_str().unwrap())), &arr32(unb64(&w.identity.sign)));
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&arr32(unb64(request["leafSigKey"].as_str().unwrap()))).unwrap();
    verifying.verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&unb64(request["signature"].as_str().unwrap()).try_into().unwrap())).unwrap();

    let answer = |w: &mut World, patch: &dyn Fn(&mut Value)| -> Value {
        let mut command = json!({ "cmd": "rekeyAnswer", "userId": w.user, "deviceId": w.device, "platform": "web", "eph": request["eph"], "leafSigKey": request["leafSigKey"], "signature": request["signature"], "groups": [group], "now": 77 });
        patch(&mut command);
        respond(&mut w.alice, &command)
    };
    // Refused: a signature that is not the leaf key's, one for another device, platform or key, no group that holds the
    // leaf, a platform that is not a device, and a core that does not hold the key.
    assert_eq!(answer(&mut w, &|c| c["signature"] = json!(b64(&[0u8; 64])))["code"], json!("auth"));
    assert_eq!(answer(&mut w, &|c| c["deviceId"] = json!(id()))["code"], json!("auth"));
    assert_eq!(answer(&mut w, &|c| c["platform"] = json!("ios"))["code"], json!("auth"), "the platform is signed");
    assert_eq!(answer(&mut w, &|c| c["eph"] = json!(b64(&[3u8; 32])))["code"], json!("auth"));
    assert_eq!(answer(&mut w, &|c| c["groups"] = json!([]))["code"], json!("auth"));
    assert_eq!(answer(&mut w, &|c| c["groups"] = json!([id()]))["code"], json!("auth"));
    assert_eq!(answer(&mut w, &|c| c["platform"] = json!("bot"))["code"], json!("invalid"));
    let mut command = json!({ "cmd": "rekeyAnswer", "userId": w.user, "deviceId": w.device, "platform": "web", "eph": request["eph"], "leafSigKey": request["leafSigKey"], "signature": request["signature"], "groups": [group], "now": 77 });
    assert_eq!(respond(&mut w.companion, &command)["code"], json!("companion"));
    // The answer opens only with the pending key, only for this device, platform and request.
    let boxed = call(&mut w.alice, command.take()).as_str().unwrap().to_string();
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "rekeyOpen", "userId": w.user, "deviceId": id(), "platform": "web", "box": boxed })).as_deref(), Some("invalid"));
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "rekeyOpen", "userId": w.user, "deviceId": w.device, "platform": "ios", "box": boxed })).as_deref(), Some("auth"));
    let mut tampered = unb64(&boxed);
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "rekeyOpen", "userId": w.user, "deviceId": w.device, "platform": "web", "box": b64(&tampered) })).as_deref(), Some("auth"));
    assert!(w.companion.is_companion().unwrap(), "nothing changed");
    let opened = call(&mut w.companion, json!({ "cmd": "rekeyOpen", "userId": w.user, "deviceId": w.device, "platform": "web", "box": boxed }));
    assert_eq!(opened["identity"], json!(w.identity));
    assert_eq!(opened["backupKeys"], created["backupKeys"], "the answer carries the backup keys, which the companion now holds");
    assert_eq!(call(&mut w.companion, json!({ "cmd": "backupKeys" })), created["backupKeys"]);
    assert!(!w.companion.is_companion().unwrap());
    assert_eq!(call(&mut w.companion, json!({ "cmd": "exportAccountKey", "userId": w.user })), call(&mut w.alice, json!({ "cmd": "exportAccountKey", "userId": w.user })));
    // The certificate it was sent is installed (issued at `now`) and the group still loads with it.
    assert!(call(&mut w.companion, json!({ "cmd": "mlsMembers", "group": group })).as_array().unwrap().len() == 2);
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "rekeyOpen", "userId": w.user, "deviceId": w.device, "platform": "web", "box": boxed })).as_deref(), Some("invalid"), "once");
}

#[test]
fn a_full_core_rotates_itself_and_another_full_core_follows_the_rotation() {
    let mut w = world();
    let old = w.identity.clone();
    // A contact that pins the old key and trusts it.
    let mut contact = core();
    contact.note_peer(&w.user, &old).unwrap();
    contact.set_verified(&w.user, true).unwrap();
    // A second full device of the account.
    let key = call(&mut w.alice, json!({ "cmd": "exportAccountKey", "userId": w.user }));
    call(&mut w.companion, json!({ "cmd": "importAccountKey", "userId": w.user, "key": key }));
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "rotateIdentity", "userId": id(), "at": 5 })).as_deref(), Some("invalid"));
    assert_eq!(fails(&mut core(), json!({ "cmd": "rotateIdentity", "userId": w.user, "at": 5 })).as_deref(), Some("invalid"), "a core with no identity");

    // The core mints the new key and signs the record itself.
    call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user, "at": 9_000, "commit": false }));
    let rotated = call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user }));
    let new_identity: chatcore::IdentityPub = serde_json::from_value(rotated["identity"].clone()).unwrap();
    assert_ne!(new_identity, old);
    assert_eq!(call(&mut w.alice, json!({ "cmd": "identity" })), rotated["identity"]);
    assert_eq!(rotated["record"]["oldSign"], json!(old.sign));
    assert_eq!(rotated["record"]["newSign"], json!(new_identity.sign));
    // The record is the M5 succession record: a contact follows it and keeps the verification.
    let mut record = rotated["record"].clone();
    let signature = record.as_object_mut().unwrap().remove("signature").unwrap();
    contact.accept_succession(&w.user, &[rotated["record"].clone()]).unwrap();
    assert!(contact.peer(&w.user).unwrap().unwrap().verified);
    assert_eq!(contact.peer(&w.user).unwrap().unwrap().identity, new_identity);
    // The other full device follows the rotation: it becomes a companion of the new key and cannot export any more.
    assert_eq!(call(&mut w.companion, json!({ "cmd": "adoptSuccession", "userId": w.user, "record": record, "signature": signature })), rotated["identity"]);
    assert!(w.companion.is_companion().unwrap());
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "exportAccountKey", "userId": w.user })).as_deref(), Some("companion"));
    assert_eq!(call(&mut w.companion, json!({ "cmd": "identity" })), rotated["identity"]);
    // The same record cannot be applied twice, and not by a core whose key it does not continue from.
    assert_eq!(fails(&mut w.companion, json!({ "cmd": "adoptSuccession", "userId": w.user, "record": record, "signature": signature })).as_deref(), Some("invalid"));
    assert_eq!(fails(&mut w.alice, json!({ "cmd": "adoptSuccession", "userId": w.user, "record": record, "signature": signature })).as_deref(), Some("invalid"));
}

#[test]
fn a_full_core_rotates_to_a_key_minted_elsewhere_with_a_record_signed_elsewhere() {
    let mut w = world();
    // The web mints the new key and signs the hand-over with the old one in WebCrypto: here, another core plays both.
    let mut signer = core();
    signer.import_account_key(&w.user, &call(&mut w.alice, json!({ "cmd": "exportAccountKey", "userId": w.user })).as_str().unwrap().to_string(), Some(&w.identity)).unwrap();
    let mut next = core();
    let new_identity = next.identity().unwrap().public;
    let new_key = next.export_account_key(&w.user).unwrap();
    let signed = signer.sign_succession(&w.user, &w.identity.sign, &new_identity.sign, &new_identity.dh, 7_000).unwrap();
    let mut record = signed.clone();
    let signature = record.as_object_mut().unwrap().remove("signature").unwrap();
    let rotate = |w: &mut World, patch: &dyn Fn(&mut Value)| -> Option<String> {
        let mut command = json!({ "cmd": "rotateIdentity", "userId": w.user, "key": new_key, "record": record, "signature": signature });
        patch(&mut command);
        respond(&mut w.alice, &command).get("code").and_then(Value::as_str).map(str::to_string)
    };
    // Refused: a signature that is not the old key's, a record for another key, another account, one without the other.
    assert_eq!(rotate(&mut w, &|c| c["signature"] = json!(b64(&[0u8; 64]))).as_deref(), Some("auth"));
    assert_eq!(rotate(&mut w, &|c| { c.as_object_mut().unwrap().remove("signature"); }).as_deref(), Some("invalid"));
    assert_eq!(rotate(&mut w, &|c| c["key"] = json!(stranger_key(&w_user()))).as_deref(), Some("invalid"));
    assert_eq!(w.alice.public_identity().unwrap(), w.identity, "nothing changed");
    assert_eq!(rotate(&mut w, &|_| {}), None);
    assert_eq!(w.alice.public_identity().unwrap(), new_identity);
    assert_eq!(call(&mut w.alice, json!({ "cmd": "exportAccountKey", "userId": w.user })), json!(new_key));
    let previous = w.alice.store_mut().get("own-previous").unwrap().unwrap();
    assert_eq!(previous, json!([{ "sign": w.identity.sign, "until": 7_000 }]));
}

fn w_user() -> String { "x".repeat(22) }
fn stranger_key(user: &str) -> String { let mut c = core(); c.identity().unwrap(); c.export_account_key(user).unwrap() }

/// A core reopened over the rows another left behind: the process died and started again.
fn reopen(core: &mut Core) -> Core {
    let mut store = chatcore::store::MemoryStore::default();
    for (key, value) in core.store_mut().scan("").unwrap() { store.map.insert(key, value); }
    Core::new(Box::new(store))
}

#[test]
fn a_rotation_can_be_prepared_sent_to_the_server_and_committed_only_once_it_was_taken() {
    let mut w = world();
    let prepared = call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user, "at": 4_000, "commit": false }));
    assert_eq!(w.alice.public_identity().unwrap(), w.identity, "nothing changed");
    assert!(w.alice.store_mut().get("own-previous").unwrap().is_none());
    // The server refuses (a wrong proof, another device rotated first, no network): drop it and prepare again, a new key.
    assert_eq!(fails(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user, "at": 4_000, "commit": false })).as_deref(), Some("pending"), "one at a time");
    call(&mut w.alice, json!({ "cmd": "rotationDrop" }));
    assert!(call(&mut w.alice, json!({ "cmd": "rotationPending" })).is_null());
    let again = call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user, "at": 4_000, "commit": false }));
    assert_ne!(again["identity"], prepared["identity"], "a new key each time unless one is given");
    call(&mut w.alice, json!({ "cmd": "rotationDrop" }));
    // The server took the record: commit with the key, record and signature that were prepared.
    let prepared = call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user, "at": 4_000, "commit": false }));
    let mut record = prepared["record"].clone();
    let signature = record.as_object_mut().unwrap().remove("signature").unwrap();
    let committed = call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user, "at": 4_000, "key": prepared["key"], "record": record, "signature": signature }));
    assert_eq!(committed["identity"], prepared["identity"]);
    assert_eq!(committed["key"], prepared["key"]);
    assert_eq!(call(&mut w.alice, json!({ "cmd": "exportAccountKey", "userId": w.user })), prepared["key"]);
    assert!(call(&mut w.alice, json!({ "cmd": "rotationPending" })).is_null(), "committing ends it");
    assert_eq!(w.alice.store_mut().get("own-previous").unwrap().unwrap(), json!([{ "sign": w.identity.sign, "until": 4_000 }]));
    // A prepare that would be refused is refused without side effects too.
    assert_eq!(fails(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": id(), "at": 1, "commit": false })).as_deref(), Some("invalid"));
    assert!(call(&mut w.alice, json!({ "cmd": "rotationPending" })).is_null());
}

#[test]
fn a_rotation_the_server_took_survives_the_app_dying_before_the_commit() {
    let mut w = world();
    let prepared = call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user, "at": 6_000, "commit": false }));
    // The process dies after `PUT /api/devices/succession` was accepted and before the commit: the new key is only in the rows.
    let mut restarted = reopen(&mut w.alice);
    assert_eq!(restarted.public_identity().unwrap(), w.identity, "still the old key");
    let pending = call(&mut restarted, json!({ "cmd": "rotationPending" }));
    assert_eq!(pending["identity"], prepared["identity"]);
    assert_eq!(pending["record"], prepared["record"], "the same signed record, for a retry of the PUT");
    // The server publishes the pending identity: commit with nothing but the user id; the old key is kept as a predecessor.
    let committed = call(&mut restarted, json!({ "cmd": "rotateIdentity", "userId": w.user }));
    assert_eq!(committed["identity"], prepared["identity"]);
    assert_eq!(call(&mut restarted, json!({ "cmd": "exportAccountKey", "userId": w.user })), prepared["key"]);
    assert_eq!(restarted.store_mut().get("own-previous").unwrap().unwrap(), json!([{ "sign": w.identity.sign, "until": 6_000 }]));
    assert!(call(&mut restarted, json!({ "cmd": "rotationPending" })).is_null());
    assert_eq!(fails(&mut restarted, json!({ "cmd": "rotateIdentity", "userId": w.user })).as_deref(), Some("invalid"), "nothing waits any more");

    // The server still publishes the old key (it never took the record): drop it.
    let mut other = world();
    call(&mut other.alice, json!({ "cmd": "rotateIdentity", "userId": other.user, "at": 6_000, "commit": false }));
    let mut again = reopen(&mut other.alice);
    call(&mut again, json!({ "cmd": "rotationDrop" }));
    assert!(call(&mut again, json!({ "cmd": "rotationPending" })).is_null());
    assert_eq!(again.public_identity().unwrap(), other.identity);
    assert_eq!(fails(&mut again, json!({ "cmd": "rotateIdentity", "userId": other.user })).as_deref(), Some("invalid"));
}

#[test]
fn a_prepared_rotation_is_dropped_when_this_core_follows_someone_elses() {
    let mut w = world();
    call(&mut w.alice, json!({ "cmd": "rotateIdentity", "userId": w.user, "at": 6_000, "commit": false }));
    // Another full device of the account rotated first and the server took it: this core adopts that record instead.
    let key = call(&mut w.alice, json!({ "cmd": "exportAccountKey", "userId": w.user })).as_str().unwrap().to_string();
    let mut first = core();
    first.import_account_key(&w.user, &key, Some(&w.identity)).unwrap();
    first.rotate_identity(&w.user, None, None, 5_000, false).unwrap();
    let mut rotated = first.rotate_identity(&w.user, None, None, 0, true).unwrap();
    let signature = rotated.1.as_object_mut().unwrap().remove("signature").unwrap();
    let adopted = call(&mut w.alice, json!({ "cmd": "adoptSuccession", "userId": w.user, "record": rotated.1, "signature": signature }));
    assert_eq!(adopted, json!(rotated.0));
    assert!(call(&mut w.alice, json!({ "cmd": "rotationPending" })).is_null(), "the prepared key is for an identity that was never published");
}
