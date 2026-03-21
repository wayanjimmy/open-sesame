//! IPC keyboard event deduplication and keysym mapping.

use crate::controller::Event;

/// Tracks recently processed key events to deduplicate overlay and IPC sources.
///
/// When compositor keyboard focus is working, both the SCTK keyboard handler
/// and the IPC `InputKeyEvent` will fire for the same physical keystroke. This
/// ring buffer ensures only the first arrival is processed.
pub struct KeyDeduplicator {
    recent: [(u32, bool, std::time::Instant); 8],
    idx: usize,
}

impl Default for KeyDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyDeduplicator {
    pub fn new() -> Self {
        let epoch = std::time::Instant::now();
        Self {
            recent: [(0, false, epoch); 8],
            idx: 0,
        }
    }

    /// Returns true if this event should be processed (not a duplicate).
    ///
    /// An event is a duplicate if an event with the same keyval and pressed
    /// state was processed within the last 50ms.
    pub fn accept(&mut self, keyval: u32, pressed: bool) -> bool {
        let now = std::time::Instant::now();

        for &(kv, pr, ts) in &self.recent {
            if kv == keyval && pr == pressed && now.duration_since(ts).as_millis() < 50 {
                return false;
            }
        }

        self.recent[self.idx] = (keyval, pressed, now);
        self.idx = (self.idx + 1) % self.recent.len();
        true
    }
}

/// Map an IPC keyboard event (XKB keysym) to a controller Event.
///
/// Uses X11 keysym values which are identical to GDK key constants.
/// Returns None for keys that the overlay does not handle (space, modifiers, etc.).
pub fn map_ipc_key_to_event(keyval: u32, _modifiers: u32, unicode: Option<char>) -> Option<Event> {
    const ESCAPE: u32 = 0xFF1B;
    const RETURN: u32 = 0xFF0D;
    const KP_ENTER: u32 = 0xFF8D;
    const TAB: u32 = 0xFF09;
    const DOWN: u32 = 0xFF54;
    const UP: u32 = 0xFF52;
    const BACKSPACE: u32 = 0xFF08;
    const SPACE: u32 = 0x0020;
    match keyval {
        ESCAPE => Some(Event::Escape),
        RETURN | KP_ENTER => Some(Event::Confirm),
        TAB => {
            // Tab-based cycling is handled entirely by IPC re-activation
            // (WmActivateOverlay / WmActivateOverlayBackward). The compositor
            // intercepts Alt+Tab and spawns a new sesame process. Suppress
            // Tab here to prevent double-advancement. Arrow keys remain
            // available for non-Alt navigation.
            None
        }
        DOWN => Some(Event::SelectionDown),
        UP => Some(Event::SelectionUp),
        BACKSPACE => Some(Event::Backspace),
        SPACE => Some(Event::Char(' ')),
        _ => unicode
            .filter(|ch| ch.is_ascii_graphic() || *ch == ' ')
            .map(Event::Char),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // map_ipc_key_to_event
    // ============================================================================

    #[test]
    fn map_escape() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF1B, 0, None),
            Some(Event::Escape)
        ));
    }

    #[test]
    fn map_return() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF0D, 0, None),
            Some(Event::Confirm)
        ));
    }

    #[test]
    fn map_kp_enter() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF8D, 0, None),
            Some(Event::Confirm)
        ));
    }

    #[test]
    fn map_tab_suppressed() {
        // Tab is suppressed — cycling is handled by IPC re-activation.
        assert!(map_ipc_key_to_event(0xFF09, 0, None).is_none());
    }

    #[test]
    fn map_tab_with_shift_suppressed() {
        // Shift+Tab is also suppressed — backward cycling via IPC.
        assert!(map_ipc_key_to_event(0xFF09, 1, None).is_none());
    }

    #[test]
    fn map_down_arrow() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF54, 0, None),
            Some(Event::SelectionDown)
        ));
    }

    #[test]
    fn map_up_arrow() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF52, 0, None),
            Some(Event::SelectionUp)
        ));
    }

    #[test]
    fn map_backspace() {
        assert!(matches!(
            map_ipc_key_to_event(0xFF08, 0, None),
            Some(Event::Backspace)
        ));
    }

    #[test]
    fn map_space_is_char() {
        assert!(matches!(
            map_ipc_key_to_event(0x0020, 0, Some(' ')),
            Some(Event::Char(' '))
        ));
    }

    #[test]
    fn map_alphanumeric_char() {
        assert!(matches!(
            map_ipc_key_to_event(0x0067, 0, Some('g')),
            Some(Event::Char('g'))
        ));
    }

    #[test]
    fn map_printable_non_alphanumeric_accepted() {
        // Printable ASCII like '/' should now pass through to controller.
        assert!(matches!(
            map_ipc_key_to_event(0x002F, 0, Some('/')),
            Some(Event::Char('/'))
        ));
    }

    #[test]
    fn map_modifier_key_ignored() {
        // Alt_L keysym — no unicode, should be None.
        assert!(map_ipc_key_to_event(0xFFE9, 0, None).is_none());
    }

    // ============================================================================
    // KeyDeduplicator
    // ============================================================================

    #[test]
    fn dedup_accepts_first() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
    }

    #[test]
    fn dedup_rejects_immediate_duplicate() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        assert!(!dedup.accept(0x67, true));
    }

    #[test]
    fn dedup_accepts_different_key() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        assert!(dedup.accept(0x68, true));
    }

    #[test]
    fn dedup_accepts_same_key_different_direction() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        assert!(dedup.accept(0x67, false));
    }

    #[test]
    fn dedup_accepts_after_window_expires() {
        let mut dedup = KeyDeduplicator::new();
        assert!(dedup.accept(0x67, true));
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert!(dedup.accept(0x67, true));
    }

    #[test]
    fn dedup_ring_buffer_wraps() {
        let mut dedup = KeyDeduplicator::new();
        // Fill the ring buffer (8 entries).
        for i in 0..8 {
            assert!(dedup.accept(i, true));
        }
        // 9th entry wraps — still accepted because it's a different key.
        assert!(dedup.accept(8, true));
    }
}
