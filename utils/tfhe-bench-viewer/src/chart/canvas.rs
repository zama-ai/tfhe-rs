//! What a plot is made of.
//!
//! The indirection exists so that the window and the exported file share a
//! single layout: [`draw`](super::draw) knows where everything goes, a canvas
//! knows how to write it down, and neither knows about the other.

use eframe::egui::{Color32, Pos2, Rect};

pub enum Anchor {
    LeftCenter,
    RightCenter,
    CenterTop,
}

pub trait Canvas {
    fn rect(&mut self, rect: Rect, color: Color32);
    fn line(&mut self, from: Pos2, to: Pos2, width: f32, color: Color32);
    fn polyline(&mut self, points: &[Pos2], width: f32, color: Color32);
    /// A filled disc with a ring around it, drawn in the surface colour: what
    /// keeps overlapping markers legible.
    fn marker(&mut self, at: Pos2, radius: f32, fill: Color32, ring: Color32);
    fn text(&mut self, at: Pos2, anchor: Anchor, text: &str, size: f32, color: Color32);
}
