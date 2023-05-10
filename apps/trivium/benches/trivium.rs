use criterion::{criterion_group, criterion_main};

mod trivium_bool;
criterion_group!(
    trivium_bool,
    trivium_bool::trivium_bool_gen,
    trivium_bool::trivium_bool_warmup
);
mod kreyvium_bool;
criterion_group!(
    kreyvium_bool,
    kreyvium_bool::kreyvium_bool_gen,
    kreyvium_bool::kreyvium_bool_warmup
);

mod trivium_shortint;
criterion_group!(
    trivium_shortint,
    trivium_shortint::trivium_shortint_gen,
    trivium_shortint::trivium_shortint_warmup,
    trivium_shortint::trivium_shortint_trans
);
mod kreyvium_shortint;
criterion_group!(
    kreyvium_shortint,
    kreyvium_shortint::kreyvium_shortint_gen,
    kreyvium_shortint::kreyvium_shortint_warmup,
    kreyvium_shortint::kreyvium_shortint_trans
);

mod trivium_byte;
criterion_group!(
    trivium_byte,
    trivium_byte::trivium_byte_gen,
    trivium_byte::trivium_byte_trans,
    trivium_byte::trivium_byte_warmup
);
mod kreyvium_byte;
criterion_group!(
    kreyvium_byte,
    kreyvium_byte::kreyvium_byte_gen,
    kreyvium_byte::kreyvium_byte_trans,
    kreyvium_byte::kreyvium_byte_warmup
);

criterion_main!(
    trivium_bool,
    trivium_shortint,
    trivium_byte,
    kreyvium_bool,
    kreyvium_shortint,
    kreyvium_byte,
);
