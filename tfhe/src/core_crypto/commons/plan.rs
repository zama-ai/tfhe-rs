use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, RwLock};

pub struct GenericPlanMap<Key, Value>(pub RwLock<HashMap<Key, Arc<Value>>>);

impl<Key: Eq + Hash + Copy, Value> GenericPlanMap<Key, Value> {
    pub fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    pub fn get_or_init(&self, key: Key, new_value: impl Fn(Key) -> Value) -> Arc<Value> {
        let values = self.0.read().unwrap();

        let value = values.get(&key).cloned();
        drop(values);

        value.unwrap_or_else(|| {
            // If we don't find a plan for the given polynomial size and modulus, we insert a
            // new one (if we still don't find it after getting a write lock)

            let new_value = Arc::new(new_value(key));

            let mut values = self.0.write().unwrap();

            let value = Arc::clone(values.entry(key).or_insert(new_value));

            drop(values);

            value
        })
    }
}

impl<Key: Eq + Hash + Copy, Value> Default for GenericPlanMap<Key, Value> {
    fn default() -> Self {
        Self::new()
    }
}
