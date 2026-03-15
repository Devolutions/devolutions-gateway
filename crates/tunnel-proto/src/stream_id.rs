use std::sync::{Arc, Mutex};

use bit_vec::BitVec;

use crate::error::{Error, Result};

/// Stream ID allocator with ID reuse
///
/// Uses a BitVec to track allocated IDs. When an ID is freed, it's marked
/// as available for reuse. This prevents ID exhaustion in long-lived connections.
#[derive(Debug, Clone)]
pub struct StreamIdAllocator {
    inner: Arc<Mutex<StreamIdAllocatorInner>>,
}

#[derive(Debug)]
struct StreamIdAllocatorInner {
    /// Bit vector tracking allocated IDs (true = allocated, false = free)
    allocated: BitVec,
    /// Next ID to try allocating (stream ID 0 is reserved for control messages)
    next_id: u32,
    /// Maximum number of concurrent streams
    max_streams: u32,
}

impl StreamIdAllocator {
    /// Create a new stream ID allocator
    ///
    /// # Arguments
    /// * `max_streams` - Maximum number of concurrent streams (default: 65536)
    pub fn new(max_streams: u32) -> Self {
        assert!(max_streams > 1, "stream ID 0 is reserved for control messages");
        Self {
            inner: Arc::new(Mutex::new(StreamIdAllocatorInner {
                allocated: BitVec::from_elem(max_streams as usize, false),
                next_id: 1,
                max_streams,
            })),
        }
    }

    /// Allocate a new stream ID
    ///
    /// Returns the allocated ID, or an error if all IDs are in use.
    /// Reuses freed IDs before allocating new ones.
    pub fn allocate(&self) -> Result<u32> {
        let mut inner = self.inner.lock().expect("stream ID allocator mutex poisoned");

        // Try to find a free ID starting from next_id. Stream ID 0 is reserved.
        let start = usize::try_from(inner.next_id).expect("stream ID should fit into usize");
        let max = usize::try_from(inner.max_streams).expect("max stream count should fit into usize");

        // Search from next_id to end
        for i in start..max {
            if !inner.allocated[i] {
                inner.allocated.set(i, true);
                inner.next_id = next_candidate(i + 1, max);
                return Ok(u32::try_from(i).expect("stream ID index should fit into u32"));
            }
        }

        // Wrap around and search from 1 to next_id
        for i in 1..start {
            if !inner.allocated[i] {
                inner.allocated.set(i, true);
                inner.next_id = next_candidate(i + 1, max);
                return Ok(u32::try_from(i).expect("stream ID index should fit into u32"));
            }
        }

        // All IDs are allocated
        Err(Error::StreamIdPoolExhausted(max))
    }

    /// Free a stream ID for reuse
    ///
    /// # Arguments
    /// * `id` - The stream ID to free
    pub fn free(&self, id: u32) {
        if id == 0 {
            return;
        }

        let mut inner = self.inner.lock().expect("stream ID allocator mutex poisoned");

        let id = usize::try_from(id).expect("stream ID should fit into usize");

        if id < inner.allocated.len() {
            inner.allocated.set(id, false);

            // Optimization: if freed ID is before next_id, update next_id
            // to favor reusing lower IDs (better locality)
            let id = u32::try_from(id).expect("stream ID index should fit into u32");
            if id < inner.next_id {
                inner.next_id = id;
            }
        }
    }

    /// Get the number of currently allocated IDs
    pub fn allocated_count(&self) -> usize {
        let inner = self.inner.lock().expect("stream ID allocator mutex poisoned");
        inner.allocated.iter().filter(|&b| b).count()
    }

    /// Get the maximum number of streams
    pub fn max_streams(&self) -> u32 {
        let inner = self.inner.lock().expect("stream ID allocator mutex poisoned");
        inner.max_streams
    }

    /// Check if a specific ID is currently allocated
    pub fn is_allocated(&self, id: u32) -> bool {
        let inner = self.inner.lock().expect("stream ID allocator mutex poisoned");
        let id = usize::try_from(id).expect("stream ID should fit into usize");

        if id < inner.allocated.len() {
            inner.allocated[id]
        } else {
            false
        }
    }
}

impl Default for StreamIdAllocator {
    fn default() -> Self {
        Self::new(65536) // Default: 64K concurrent streams
    }
}

fn next_candidate(candidate: usize, max: usize) -> u32 {
    let wrapped = candidate % max;
    if wrapped == 0 {
        1
    } else {
        u32::try_from(wrapped).expect("stream ID index should fit into u32")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_sequential() {
        let allocator = StreamIdAllocator::new(10);

        let id1 = allocator.allocate().expect("first stream ID should allocate");
        let id2 = allocator.allocate().expect("second stream ID should allocate");
        let id3 = allocator.allocate().expect("third stream ID should allocate");

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
        assert_eq!(allocator.allocated_count(), 3);
    }

    #[test]
    fn test_free_and_reuse() {
        let allocator = StreamIdAllocator::new(10);

        let id1 = allocator.allocate().expect("first stream ID should allocate");
        let id2 = allocator.allocate().expect("second stream ID should allocate");
        let id3 = allocator.allocate().expect("third stream ID should allocate");

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);

        // Free the middle ID
        allocator.free(id2);
        assert_eq!(allocator.allocated_count(), 2);

        // Next allocation should reuse the freed ID
        let id4 = allocator.allocate().expect("freed stream ID should be reused");
        assert_eq!(id4, 2); // Reused id2
        assert_eq!(allocator.allocated_count(), 3);
    }

    #[test]
    fn test_pool_exhaustion() {
        let allocator = StreamIdAllocator::new(4);

        let _id1 = allocator.allocate().expect("first stream ID should allocate");
        let _id2 = allocator.allocate().expect("second stream ID should allocate");
        let _id3 = allocator.allocate().expect("third stream ID should allocate");

        // Pool is now exhausted
        let result = allocator.allocate();
        assert!(matches!(result, Err(Error::StreamIdPoolExhausted(4))));
    }

    #[test]
    fn test_wrap_around() {
        let allocator = StreamIdAllocator::new(5);

        assert!(!allocator.is_allocated(0));

        // Allocate all
        let ids: Vec<u32> = (0..4)
            .map(|_| {
                allocator
                    .allocate()
                    .expect("stream ID should allocate during wrap-around test")
            })
            .collect();

        // Free first two
        allocator.free(ids[0]);
        allocator.free(ids[1]);

        // Allocate again - should wrap around and reuse
        let new_id1 = allocator.allocate().expect("first wrapped stream ID should allocate");
        let new_id2 = allocator.allocate().expect("second wrapped stream ID should allocate");

        assert!(new_id1 <= 2 && new_id2 <= 2);
        assert_ne!(new_id1, new_id2);
    }

    #[test]
    fn test_is_allocated() {
        let allocator = StreamIdAllocator::new(10);

        let id = allocator.allocate().expect("stream ID should allocate");
        assert!(allocator.is_allocated(id));
        assert!(!allocator.is_allocated(id + 1));

        allocator.free(id);
        assert!(!allocator.is_allocated(id));
    }

    #[test]
    fn test_concurrent_allocations() {
        use std::sync::Arc;
        use std::thread;

        let allocator = Arc::new(StreamIdAllocator::new(1000));
        let mut handles = vec![];

        // Spawn multiple threads allocating IDs
        for _ in 0..10 {
            let allocator_clone = Arc::clone(&allocator);
            let handle = thread::spawn(move || {
                let mut ids = vec![];
                for _ in 0..50 {
                    if let Ok(id) = allocator_clone.allocate() {
                        ids.push(id);
                    }
                }
                ids
            });
            handles.push(handle);
        }

        // Collect all allocated IDs
        let mut all_ids = vec![];
        for handle in handles {
            all_ids.extend(handle.join().expect("allocation thread should not panic"));
        }

        // Verify no duplicates
        all_ids.sort_unstable();
        for window in all_ids.windows(2) {
            assert_ne!(window[0], window[1], "Duplicate ID allocated");
        }

        assert_eq!(allocator.allocated_count(), all_ids.len());
    }
}
