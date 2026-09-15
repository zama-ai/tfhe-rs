//! The database, as seen from a page: not reachable.
//!
//! A browser opens HTTP, WebSocket and WebRTC, never a raw TCP socket, and
//! PostgreSQL speaks its own protocol over TCP. Reaching it from here would
//! take an HTTP service in front of the database, which is a deployment and an
//! authentication problem rather than a missing library.
//!
//! So the web build reads snapshots, and `Db` exists only to say so in the one
//! place the interface already shows it: the status line.

use std::path::PathBuf;
use std::sync::mpsc::Sender;

use eframe::egui;

use super::Store;

pub struct Db;

impl Db {
    pub fn new(_config_file: Option<PathBuf>) -> anyhow::Result<Self> {
        anyhow::bail!("no database from a browser, drop a .data.json snapshot on the window")
    }

    /// Never called: `new` never hands one out.
    pub fn fetch(&self, _days: i32, _tx: Sender<Result<Store, String>>, _ctx: egui::Context) {}
}
