pub(crate) struct Instant {
    start: f64,
}

impl Instant {
    /// This function only has a millisecond resolution on some platforms like the chrome browser
    pub fn now() -> Self {
        let now = js_sys::Date::new_0().get_time();
        Self { start: now }
    }

    /// This function only has a millisecond resolution on some platforms like the chrome browser,
    /// which means it can easily return 0 when called on quick code
    pub fn elapsed(&self) -> core::time::Duration {
        let now = js_sys::Date::new_0().get_time();
        core::time::Duration::from_millis((now - self.start) as u64)
    }
}
