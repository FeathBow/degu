// A value computed from browser state, refreshed when its key changes. A new
// derivation cannot be declared without saying what it reads.
pub struct Derived<T, K: PartialEq> {
    key: K,
    value: T,
}

impl<T, K: PartialEq> Derived<T, K> {
    pub fn new(key: K, compute: impl FnOnce() -> T) -> Self {
        Self {
            value: compute(),
            key,
        }
    }

    pub fn refresh(&mut self, key: K, compute: impl FnOnce() -> T) {
        if self.key != key {
            self.value = compute();
            self.key = key;
        }
    }

    pub fn get(&self) -> &T {
        &self.value
    }

    // Scroll position belongs to the reader; moving it does not change the key.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }
}
