use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, OnceLock, RwLock};

pub struct GenericPlanMap<Key, Value>(pub RwLock<HashMap<Key, Arc<OnceLock<Arc<Value>>>>>);

impl<Key: Eq + Hash + Copy, Value> GenericPlanMap<Key, Value> {
    pub fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    pub fn get_or_init(&self, key: Key, new_value: impl Fn(Key) -> Value) -> Arc<Value> {
        let get_plan = || {
            let plans = self.0.read().unwrap();
            let plan = plans.get(&key).cloned();
            drop(plans);

            plan.map(|p| p.get_or_init(|| Arc::new(new_value(key))).clone())
        };

        get_plan().unwrap_or_else(|| {
            // If we don't find a plan for the given size, we insert a new OnceLock,
            // drop the write lock on the map and then let get_plan() initialize the OnceLock
            // (without holding the write lock on the map).
            let mut plans = self.0.write().unwrap();
            if let Entry::Vacant(v) = plans.entry(key) {
                v.insert(Arc::new(OnceLock::new()));
            }
            drop(plans);

            get_plan().unwrap()
        })
    }
}

impl<Key: Eq + Hash + Copy, Value> Default for GenericPlanMap<Key, Value> {
    fn default() -> Self {
        Self::new()
    }
}
