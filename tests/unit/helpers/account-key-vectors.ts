// Pinned vectors of docs/m6-account-key.md §10, computed independently of chatcore (Python: argon2-cffi, cryptography).
// crates/chatcore/tests/account_key.rs pins the same values; ports (the web client, the app) check theirs against these.
// Inputs: user id = bytes 0..15, sign seed = bytes 1..32, dh secret = bytes 0x40..0x5f, salt = bytes 0..15, recovery
// entropy = bytes 0..31, backup epoch 1; the backup box uses ephemeral secret 0x55*32 and nonce 0..11; the rekey case is
// device bytes 16..31, platform "web", companion ephemeral secret 0x77*32, leaf seed 0x09*32, rekey box ephemeral 0x66*32 and nonce 24..35.
export const vectors = {
  "user": "AAECAwQFBgcICQoLDA0ODw",
  "deviceId": "EBESExQVFhcYGRobHB0eHw",
  "accountKey": "ABl3ZWJydGMtYnVuLWFjY291bnQta2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f",
  "aikSign": "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
  "dhPub": "eaYx7t4b-cmPEgMs3q3Q56B5OY_HhriMyEbsia-FpRo",
  "passSeed": "DRo8ZSPI8G5OCvnFFapbVEjP69aDjy1Sw9i2743cPC4",
  "passSecret": "sF38rvX1P-b5jXCxGiGTZEtpMeCT7AEmPVrYKedalxM",
  "passPub": "PPCKyg-NB-6w8OEHe2_Z30fvNjIIOXRJwaWn4iSDyxY",
  "passProof": "C9g-jJrsploDsMuNH52rbLTMfoDU_9vORpUpp-pGYoM",
  "words": "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware",
  "recoverySecret": "EMyQf31HUcUQGoNU1fuvAkpzn1dlJ25sNXk6JCHYfhI",
  "recoveryPub": "osIiZH2Qf6a3UUY_8wACozHYmpvt3CyQlfpc3Kld6D8",
  "recoveryProof": "8M1ElR7RU5dET5kZDE0Tzvw21P49Sot8f0ZCaK68NwI",
  "passHash": "JilsP2l9Gs92M24r_r3KSBU2VWN-lXd7IKQM3VyzkjE",
  "recoveryHash": "HgfQNEOC-bkgOdITk7FWHNtgdKuuNMlvxjISyKYnKY4",
  "passProofHash": "mqPAZy0FgljKYg-02W_5gq0OqYSD4DMigMVgfYrmQBc",
  "recoveryProofHash": "Mu1yfcNQRu2CcoN5m7F4CW4WCrm8WsP66nJxF3hdZps",
  "aad": "ABR3ZWJydGMtYnVuLWJhY2t1cC12MQAWQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyB5tVYuj-ZU-UB4sRLoqYunkB-FOuaVvtfg45ELrQSWZAAAAAE",
  "backupPlain": "ABl3ZWJydGMtYnVuLWFjY291bnQta2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fIDzwisoPjQfusPDhB3tv2d9H7zYyCDl0ScGlp-Ikg8sWIKLCImR9kH-mt1FGP_MAAqMx2Jqb7dwskJX6XNypXeg_",
  "box": "OKtmS9hvd9fma92a4HkpE6lP2LM6EmACfktGwfSITGcAAQIDBAUGBwgJCgsWLBsD6rpP9DSqKq9_zfes6NqYS-rYllmUb6VBc-zWnp2xWmwVDYR8oR43sicZKrZOtMJQX5KW-E5033Ph7Aape6plluH1rPRY1oKD50zVkgKr9pjUzR8BMka_rNpXVnLzIEeRHbuQ16I3RUFPu7ZrqCCknHufsrl6Tf4TYUYUL-mkRi9mlXFrTctpw25eovjDMU8NpZrkXIZQvzUhB23w5dVSPULAYn09vs-eIjGJBClDGbj3DqoRCeScMqc8TVxiBIYHxQRC",
  "boxLen": 243,
  "keysBytes": "ABl3ZWJydGMtYnVuLWJhY2t1cC1rZXlzLXYyABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IHm1Vi6P5lT5QHixEuipi6eQH4U65pW-1-DjkQutBJZkAAAAARAAAQIDBAUGBwgJCgsMDQ4PAAEAAAAAAAMAAAABICYpbD9pfRrPdjNuK_69ykgVNlVjfpV3eyCkDN1cs5IxIB4H0DRDgvm5IDnSE5OxVhzbYHSrrjTJb8YyEsimJymOIJqjwGctBYJYymIPtNlv-YKtDqmEg-AzIoDFYH2K5kAXIDLtcn3DUEbtgnKDeZuxeAluFgq5vFrD-upycRd4XWab",
  "keysSha": "deccb6a4d30ffe8808cc17a5da29db8cfc47b2665f38bd340d4e1495a861b46c",
  "rekeyEph": "HPV5q6RaELodHvBtkfyiqp7QoRUFFWUxVUBdCxjLmmc",
  "rekeyEphSecret": "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c",
  "rekeyLeaf": "_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg",
  "rekeyBytes": "ABN3ZWJydGMtYnVuLXJla2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3ABZFQkVTRXhRVkZoY1lHUm9iSEIwZUh3AAN3ZWIgHPV5q6RaELodHvBtkfyiqp7QoRUFFWUxVUBdCxjLmmcg_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hggebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
  "rekeySha": "e3ca3b897fd9bbcc3b6e3a672dd91964c6457673304c1dd18492c2d0d84c5c1e",
  "rekeyPlain": "{\"v\":1,\"accountKey\":\"ABl3ZWJydGMtYnVuLWFjY291bnQta2V5LXYxABZBQUVDQXdRRkJnY0lDUW9MREEwT0R3IAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\",\"cert\":\"{}\",\"backupKeys\":null}",
  "rekeyBox": "IZ5NgA2paNKl_LAJx4T0dGxxOO257khEtznoMLBc9CQYGRobHB0eHyAhIiNhSrDjtqoQO1fWdOC4JJd7itHxnenKEJSe_UjMT28l-2L6Sc1Bi_Vi-6hdFFYCtumiIxS3HUoybgEtTOP9lOcJztr_KnfCkQ_DV-ZQIWLtrqyIEZxFgWO8qE68SCYU8P0t6J6_0gt9i-BozrVIp_lJvWoTWalMYfpjw1QhrbUKn1G4FGY-KIz29_VGlg2p2JPyzHo0aT5OITkM67p2jtvg0xcelNhrnrmfqDpQCAIajhDnndAkjH-sugU393r_DmOgAgZsNxv7vl1mx8Sha04YQdMm_PkQ_qFWfqTzgJAcsP8"
} as const;

/** A complete, signed backup record sealed from these inputs (passphrase "correct horse battery staple"). */
export const record = {
  "v": 1,
  "userId": "AAECAwQFBgcICQoLDA0ODw",
  "aikSign": "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
  "epoch": 1,
  "kdf": {
    "alg": "argon2id",
    "salt": "AAECAwQFBgcICQoLDA0ODw",
    "m": 65536,
    "t": 3,
    "p": 1
  },
  "passHash": "JilsP2l9Gs92M24r_r3KSBU2VWN-lXd7IKQM3VyzkjE",
  "recoveryHash": "HgfQNEOC-bkgOdITk7FWHNtgdKuuNMlvxjISyKYnKY4",
  "pass": "OKtmS9hvd9fma92a4HkpE6lP2LM6EmACfktGwfSITGcAAQIDBAUGBwgJCgsWLBsD6rpP9DSqKq9_zfes6NqYS-rYllmUb6VBc-zWnp2xWmwVDYR8oR43sicZKrZOtMJQX5KW-E5033Ph7Aape6plluH1rPRY1oKD50zVkgKr9pjUzR8BMka_rNpXVnLzIEeRHbuQ16I3RUFPu7ZrqCCknHufsrl6Tf4TYUYUL-mkRi9mlXFrTctpw25eovjDMU8NpZrkXIZQvzUhB23w5dVSPULAYn09vs-eIjGJBClDGbj3DqoRCeScMqc8TVxiBIYHxQRC",
  "recovery": "3M-fwAGzRcd0dOduECG94E9-oO2O5h9_bxpOR6WvL1QMDQ4PEBESExQVFhfweaNLDNPHOCe15k7dxTP-jZ1gjVFpWxf0lDe9YM0N0D8BHV-qukb2pl3g1neUV-N0lqa3Y_2QSRImvKD0Hgybsfh8lXJsf_Ja4Vs1i-6krmBr7wJ0PFKcKUbu7pzgrDne8wJf0AfFuy5C69CxVnd0PlTaMNI1awcZXuXo4FxXQ0v6iDT0JIvJ27vUl8l-MrsWqL3yGkB7SLGZ0_NApRDr5Bi6AKf455LsVT1IaRy-b5oMnT9XJmTScLz8elkEUk6dQ3irW2Qd",
  "passProofHash": "mqPAZy0FgljKYg-02W_5gq0OqYSD4DMigMVgfYrmQBc",
  "recoveryProofHash": "Mu1yfcNQRu2CcoN5m7F4CW4WCrm8WsP66nJxF3hdZps",
  "signature": "EhMwHw3WQmZJsy3qCk_FrdvEeWuUBN-ycTLi1zXFtDn5i9UCND-796tr7N9z9scjUMK3IZbMf2Hfu_dTZvHbBg",
  "updatedAt": 1700000000000
} as const;
export const passphrase = 'correct horse battery staple';
