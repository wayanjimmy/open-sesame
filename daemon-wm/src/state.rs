//! Window switcher state machine.
//!
//! Four operational states controlling the overlay lifecycle:
//!
//! - `Idle`: No overlay visible. Transitions to `BorderOnly` on activation key.
//! - `BorderOnly`: Focused window border highlight shown. After `overlay_delay_ms`
//!   AND >= 2 rendered frames, transitions to `FullOverlay`. Alt-release during
//!   this state triggers quick-switch to previous window.
//! - `FullOverlay`: Window list with hint labels and input buffer. Hint matching,
//!   selection movement, search, Enter to confirm, Escape to cancel.
//! - `PendingActivation`: Target window selected, waiting `activation_delay_ms`
//!   before activating. Continued typing can change the target. Backspace
//!   returns to `FullOverlay`.

use std::time::Instant;

/// Overlay state machine states.
#[derive(Debug, Clone)]
pub enum WmState {
    Idle,
    BorderOnly {
        entered_at: Instant,
        frame_count: u32,
    },
    FullOverlay {
        input_buffer: String,
        selection: usize,
        window_count: usize,
    },
    PendingActivation {
        target: usize,
        pending_key: Option<char>,
        entered_at: Instant,
    },
}

/// Actions produced by state machine transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Show border-only indicator on the focused window.
    ShowBorder,
    /// Show the full overlay with window list and hints.
    ShowOverlay,
    /// Activate the window at the given index.
    ActivateWindow(usize),
    /// Quick-switch to the previous MRU window.
    QuickSwitch,
    /// Dismiss the overlay and return to idle.
    Dismiss,
    /// Redraw the overlay (input or selection changed).
    Redraw,
    /// No action needed.
    None,
}

impl WmState {
    /// Create a new idle state machine.
    #[must_use]
    pub fn new() -> Self {
        Self::Idle
    }

    /// Activation key pressed — begin the overlay sequence.
    pub fn on_activate(&mut self) -> Action {
        match self {
            Self::Idle => {
                *self = Self::BorderOnly {
                    entered_at: Instant::now(),
                    frame_count: 0,
                };
                Action::ShowBorder
            }
            _ => Action::None,
        }
    }

    /// Frame rendered in border-only mode.
    /// Increments frame counter and checks transition to full overlay.
    pub fn on_frame(&mut self, overlay_delay_ms: u32) -> Action {
        match self {
            Self::BorderOnly {
                entered_at,
                frame_count,
            } => {
                *frame_count += 1;
                let elapsed = entered_at.elapsed().as_millis() as u32;
                if elapsed >= overlay_delay_ms && *frame_count >= 2 {
                    *self = Self::FullOverlay {
                        input_buffer: String::new(),
                        selection: 0,
                        window_count: 0,
                    };
                    Action::ShowOverlay
                } else {
                    Action::None
                }
            }
            _ => Action::None,
        }
    }

    /// Set the window count when entering full overlay.
    pub fn set_window_count(&mut self, count: usize) {
        if let Self::FullOverlay { window_count, .. } = self {
            *window_count = count;
        }
    }

    /// Alt key released — quick-switch if still in border-only mode.
    pub fn on_modifier_release(&mut self, overlay_delay_ms: u32) -> Action {
        match self {
            Self::BorderOnly { entered_at, .. } => {
                let elapsed = entered_at.elapsed().as_millis() as u32;
                if elapsed < overlay_delay_ms {
                    // Quick switch — user tapped and released quickly.
                    *self = Self::Idle;
                    Action::QuickSwitch
                } else {
                    // Past overlay delay but not enough frames yet — force overlay.
                    *self = Self::FullOverlay {
                        input_buffer: String::new(),
                        selection: 0,
                        window_count: 0,
                    };
                    Action::ShowOverlay
                }
            }
            _ => Action::None,
        }
    }

    /// Character input in full overlay mode.
    pub fn on_char(&mut self, ch: char) -> Action {
        match self {
            Self::FullOverlay { input_buffer, .. } => {
                input_buffer.push(ch);
                Action::Redraw
            }
            Self::PendingActivation { pending_key, .. } => {
                *pending_key = Some(ch);
                Action::Redraw
            }
            _ => Action::None,
        }
    }

    /// Backspace in full overlay or pending activation.
    pub fn on_backspace(&mut self) -> Action {
        match self {
            Self::FullOverlay { input_buffer, .. } => {
                input_buffer.pop();
                Action::Redraw
            }
            Self::PendingActivation { .. } => {
                // Return to overlay.
                *self = Self::FullOverlay {
                    input_buffer: String::new(),
                    selection: 0,
                    window_count: 0,
                };
                Action::ShowOverlay
            }
            _ => Action::None,
        }
    }

    /// Move selection down (Tab / Down arrow). Wraps around.
    pub fn on_selection_down(&mut self) -> Action {
        if let Self::FullOverlay {
            selection,
            window_count,
            ..
        } = self
        {
            if *window_count > 0 {
                *selection = (*selection + 1) % *window_count;
            }
            Action::Redraw
        } else {
            Action::None
        }
    }

    /// Move selection up (Shift+Tab / Up arrow). Wraps around.
    pub fn on_selection_up(&mut self) -> Action {
        if let Self::FullOverlay {
            selection,
            window_count,
            ..
        } = self
        {
            if *window_count > 0 {
                *selection = selection.checked_sub(1).unwrap_or(*window_count - 1);
            }
            Action::Redraw
        } else {
            Action::None
        }
    }

    /// Confirm selection (Enter key).
    pub fn on_confirm(&mut self) -> Action {
        match self {
            Self::FullOverlay {
                selection,
                window_count,
                ..
            } => {
                if *window_count == 0 {
                    return Action::None;
                }
                let target = *selection;
                *self = Self::PendingActivation {
                    target,
                    pending_key: None,
                    entered_at: Instant::now(),
                };
                Action::ActivateWindow(target)
            }
            Self::PendingActivation { target, .. } => Action::ActivateWindow(*target),
            _ => Action::None,
        }
    }

    /// Set target from hint match (exact match found).
    pub fn on_hint_match(&mut self, index: usize) -> Action {
        match self {
            Self::FullOverlay { .. } => {
                *self = Self::PendingActivation {
                    target: index,
                    pending_key: None,
                    entered_at: Instant::now(),
                };
                Action::ActivateWindow(index)
            }
            _ => Action::None,
        }
    }

    /// Escape key — cancel and dismiss.
    pub fn on_escape(&mut self) -> Action {
        match self {
            Self::Idle => Action::None,
            _ => {
                *self = Self::Idle;
                Action::Dismiss
            }
        }
    }

    /// Check pending activation timeout.
    pub fn check_activation_timeout(&mut self, activation_delay_ms: u32) -> Action {
        if let Self::PendingActivation {
            target, entered_at, ..
        } = self
            && entered_at.elapsed().as_millis() as u32 >= activation_delay_ms
        {
            let target = *target;
            *self = Self::Idle;
            return Action::ActivateWindow(target);
        }
        Action::None
    }

    /// Current input buffer contents (if in overlay mode).
    #[must_use]
    pub fn input_buffer(&self) -> Option<&str> {
        match self {
            Self::FullOverlay { input_buffer, .. } => Some(input_buffer),
            _ => None,
        }
    }

    /// Current selection index (if in overlay mode).
    #[must_use]
    pub fn selection(&self) -> Option<usize> {
        match self {
            Self::FullOverlay { selection, .. } => Some(*selection),
            _ => None,
        }
    }

    /// Whether the overlay should be visible.
    #[must_use]
    pub fn is_overlay_visible(&self) -> bool {
        matches!(
            self,
            Self::BorderOnly { .. } | Self::FullOverlay { .. } | Self::PendingActivation { .. }
        )
    }

    /// Whether we are in idle state.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }
}

impl Default for WmState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn idle_to_border_on_activate() {
        let mut state = WmState::new();
        let action = state.on_activate();
        assert_eq!(action, Action::ShowBorder);
        assert!(matches!(state, WmState::BorderOnly { .. }));
    }

    #[test]
    fn border_to_overlay_after_delay_and_frames() {
        let mut state = WmState::new();
        state.on_activate();

        // Not enough frames yet.
        assert_eq!(state.on_frame(0), Action::None);

        // Second frame with 0ms delay — should transition.
        let action = state.on_frame(0);
        assert_eq!(action, Action::ShowOverlay);
        assert!(matches!(state, WmState::FullOverlay { .. }));
    }

    #[test]
    fn quick_switch_on_fast_release() {
        let mut state = WmState::new();
        state.on_activate();
        // Release immediately — overlay_delay_ms is 500 (way longer than elapsed).
        let action = state.on_modifier_release(500);
        assert_eq!(action, Action::QuickSwitch);
        assert!(state.is_idle());
    }

    #[test]
    fn escape_from_overlay_returns_to_idle() {
        let mut state = WmState::new();
        state.on_activate();
        state.on_frame(0);
        state.on_frame(0);
        let action = state.on_escape();
        assert_eq!(action, Action::Dismiss);
        assert!(state.is_idle());
    }

    #[test]
    fn selection_wraps_around() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 2,
            window_count: 3,
        };
        state.on_selection_down();
        assert_eq!(state.selection(), Some(0));

        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 3,
        };
        state.on_selection_up();
        assert_eq!(state.selection(), Some(2));
    }

    #[test]
    fn confirm_in_empty_overlay_is_noop() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 0,
        };
        assert_eq!(state.on_confirm(), Action::None);
    }

    #[test]
    fn char_input_and_backspace() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 3,
        };
        state.on_char('a');
        assert_eq!(state.input_buffer(), Some("a"));
        state.on_char('b');
        assert_eq!(state.input_buffer(), Some("ab"));
        state.on_backspace();
        assert_eq!(state.input_buffer(), Some("a"));
    }

    #[test]
    fn backspace_from_pending_returns_to_overlay() {
        let mut state = WmState::PendingActivation {
            target: 0,
            pending_key: None,
            entered_at: Instant::now(),
        };
        let action = state.on_backspace();
        assert_eq!(action, Action::ShowOverlay);
        assert!(matches!(state, WmState::FullOverlay { .. }));
    }

    #[test]
    fn hint_match_transitions_to_pending() {
        let mut state = WmState::FullOverlay {
            input_buffer: String::new(),
            selection: 0,
            window_count: 5,
        };
        let action = state.on_hint_match(3);
        assert_eq!(action, Action::ActivateWindow(3));
        assert!(matches!(state, WmState::PendingActivation { target: 3, .. }));
    }

    #[test]
    fn activation_timeout() {
        let mut state = WmState::PendingActivation {
            target: 2,
            pending_key: None,
            entered_at: Instant::now() - Duration::from_millis(300),
        };
        let action = state.check_activation_timeout(200);
        assert_eq!(action, Action::ActivateWindow(2));
        assert!(state.is_idle());
    }
}
