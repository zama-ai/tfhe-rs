use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, RwLock};

pub type PlanMap<Key, Value> = RwLock<HashMap<Key, Arc<Value>>>;

pub fn new_from_plan_map<Key: Eq + Hash + Copy, Value>(
    values_map: &PlanMap<Key, Value>,
    key: Key,
    new_value: impl Fn(Key) -> Value,
) -> Arc<Value> {
    let values = values_map.read().unwrap();

    let value = values.get(&key).cloned();
    drop(values);

    value.unwrap_or_else(|| {
        // If we don't find a plan for the given polynomial size and modulus, we insert a
        // new one (if we still don't find it after getting a write lock)

        let new_value = Arc::new(new_value(key));

        let mut values = values_map.write().unwrap();

        let value = Arc::clone(values.entry(key).or_insert(new_value));

        drop(values);

        value
    })
}
