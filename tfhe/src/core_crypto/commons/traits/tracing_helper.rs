use crate::core_crypto::commons::tracing_helper::EntityMemoryTracer;

pub trait AsMemoryTracer {
    fn as_memory_tracer(&self, with_metadata: bool) -> EntityMemoryTracer;
}
