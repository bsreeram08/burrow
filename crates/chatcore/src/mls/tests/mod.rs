//! MLS engine tests. `harness` builds accounts, devices and a delivery service; the other modules hold the
//! scenarios the spike proved, every policy gap row of FINDINGS.md, limits and canonical encoding, and persistence.
mod harness;
mod persistence;
mod policy;
mod scenarios;
mod units;
