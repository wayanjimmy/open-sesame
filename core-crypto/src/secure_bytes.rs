//! Heap-allocated byte buffer with mlock, MADV_DONTDUMP, and zeroize-on-drop.

use zeroize::Zeroize;

/// A heap-allocated byte buffer that is:
/// - `mlock`'d to prevent swapping to disk (Unix)
/// - `MADV_DONTDUMP` to exclude from core dumps (Linux)
/// - Zeroed on drop via `zeroize`
/// - Redacted in `Debug` output
pub struct SecureBytes {
    inner: Vec<u8>,
}

impl SecureBytes {
    /// Create a new `SecureBytes` from raw data.
    ///
    /// On Unix, the backing memory is immediately `mlock`'d and marked
    /// `MADV_DONTDUMP`. Failure to mlock is logged but not fatal (the
    /// process may lack `CAP_IPC_LOCK` or hit `RLIMIT_MEMLOCK`).
    pub fn new(data: Vec<u8>) -> Self {
        let sb = Self { inner: data };
        #[cfg(unix)]
        {
            // SAFETY: mlock and madvise operate on the Vec's backing allocation.
            // The pointer and length are valid for the lifetime of `sb.inner`.
            // mlock prevents the OS from swapping these pages to disk.
            // MADV_DONTDUMP excludes pages from core dumps.
            unsafe {
                let ptr = sb.inner.as_ptr().cast::<libc::c_void>();
                let len = sb.inner.len();
                if libc::mlock(ptr, len) != 0 {
                    tracing::warn!(
                        len,
                        "mlock failed (process may lack CAP_IPC_LOCK or hit RLIMIT_MEMLOCK)"
                    );
                }
                // MADV_DONTDUMP is Linux-specific (value 16).
                #[cfg(target_os = "linux")]
                {
                    libc::madvise(ptr.cast_mut(), len, libc::MADV_DONTDUMP);
                }
            }
        }
        sb
    }

    /// View the secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        // Zero the memory before releasing
        self.inner.zeroize();

        #[cfg(unix)]
        {
            // SAFETY: munlock the previously mlock'd region.
            // The Vec is still alive (we're in Drop, before dealloc).
            unsafe {
                libc::munlock(
                    self.inner.as_ptr().cast::<libc::c_void>(),
                    self.inner.len(),
                );
            }
        }
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([REDACTED; {} bytes])", self.inner.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_contents() {
        let sb = SecureBytes::new(b"super_secret_password".to_vec());
        let debug = format!("{sb:?}");
        assert!(!debug.contains("super_secret"));
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("21 bytes"));
    }

    #[test]
    fn as_bytes_returns_original_data() {
        let data = vec![1, 2, 3, 4, 5];
        let sb = SecureBytes::new(data.clone());
        assert_eq!(sb.as_bytes(), &data);
    }

    #[test]
    fn empty_secure_bytes() {
        let sb = SecureBytes::new(Vec::new());
        assert!(sb.is_empty());
        assert_eq!(sb.len(), 0);
    }
}
