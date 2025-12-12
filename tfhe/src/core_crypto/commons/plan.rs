use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, OnceLock, RwLock};

pub type PlanMap<Key, Value> = RwLock<HashMap<Key, Arc<OnceLock<Arc<Value>>>>>;

pub fn new_from_plan_map<Key: Eq + Hash + Copy, Value>(
    values_map: &PlanMap<Key, Value>,
    key: Key,
    new_value: impl Fn(Key) -> Value,
) -> Arc<Value> {
    let get_plan = || {
        let plans = values_map.read().unwrap();
        let plan = plans.get(&key).cloned();
        drop(plans);

        plan.map(|p| p.get_or_init(|| Arc::new(new_value(key))).clone())
    };

    get_plan().unwrap_or_else(|| {
        // If we don't find a plan for the given size, we insert a new OnceLock,
        // drop the write lock on the map and then let get_plan() initialize the OnceLock
        // (without holding the write lock on the map).
        let mut plans = values_map.write().unwrap();
        if let Entry::Vacant(v) = plans.entry(key) {
            v.insert(Arc::new(OnceLock::new()));
        }
        drop(plans);

        get_plan().unwrap()
    })
}
