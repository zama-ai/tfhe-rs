use std::time::Instant;

pub struct Time {
    begin: Instant,
    cpu_begin: Instant,
    cpu_end: Instant,
    end: Instant,
}

impl Time {
    pub fn begin() -> Self {
        let now = Instant::now();
        Self {
            begin: now.clone(),
            cpu_begin: now.clone(),
            cpu_end: now.clone(),
            end: now.clone(),
        }
    }
    pub fn cpu_begin(&mut self) {
        self.cpu_begin = Instant::now();
    }
    pub fn cpu_end(&mut self) {
        self.cpu_end = Instant::now();
    }
    pub fn end(&mut self) {
        self.end = Instant::now();
    }
}

impl std::fmt::Display for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let load = self.cpu_begin.duration_since(self.begin);
        let cpu_comp = self.cpu_end.duration_since(self.cpu_begin);
        let unload = self.end.duration_since(self.cpu_end);

        write!(
            f,
            "{{ load: {load:?}, cpu {cpu_comp:?}, unload: {unload:?} }}"
        )
    }
}
