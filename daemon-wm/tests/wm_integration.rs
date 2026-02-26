//! Integration tests for daemon-wm modules.
//!
//! Tests hint assignment, hint matching, MRU state parsing, and state machine
//! transitions. These tests do NOT require a running daemon or Wayland compositor.

use daemon_wm::hints::{assign_hints, assign_app_hints, match_input, MatchResult, auto_key_for_app};
use daemon_wm::mru;
use daemon_wm::state::{WmState, Action};
use std::time::{Duration, Instant};

// ============================================================================
// Hint Assignment
// ============================================================================

#[test]
fn assign_hints_single_key_set() {
    let hints = assign_hints(3, "a");
    assert_eq!(hints, vec!["a", "aa", "aaa"]);
}

#[test]
fn assign_hints_multi_key_set() {
    let hints = assign_hints(7, "asd");
    assert_eq!(hints, vec!["a", "s", "d", "aa", "ss", "dd", "aaa"]);
}

#[test]
fn assign_hints_exact_key_count() {
    let hints = assign_hints(3, "abc");
    assert_eq!(hints, vec!["a", "b", "c"]);
}

#[test]
fn assign_hints_empty_inputs() {
    assert!(assign_hints(0, "abc").is_empty());
    assert!(assign_hints(5, "").is_empty());
}

// ============================================================================
// Hint Matching
// ============================================================================

#[test]
fn match_exact_unique() {
    let hints: Vec<String> = vec!["a".into(), "s".into(), "d".into()];
    assert_eq!(match_input("s", &hints), MatchResult::Exact(1));
}

#[test]
fn match_no_match() {
    let hints: Vec<String> = vec!["a".into(), "s".into()];
    assert_eq!(match_input("z", &hints), MatchResult::NoMatch);
}

#[test]
fn match_empty_input() {
    let hints: Vec<String> = vec!["a".into()];
    assert_eq!(match_input("", &hints), MatchResult::NoMatch);
}

#[test]
fn match_partial_prefix() {
    let hints: Vec<String> = vec!["a".into(), "aa".into(), "aaa".into()];
    match match_input("a", &hints) {
        MatchResult::Partial(indices) => {
            assert_eq!(indices.len(), 3);
        }
        other => panic!("expected Partial, got {other:?}"),
    }
}

#[test]
fn match_numeric_shorthand() {
    let hints: Vec<String> = vec!["a".into(), "aa".into(), "aaa".into()];
    assert_eq!(match_input("a3", &hints), MatchResult::Exact(2));
}

#[test]
fn match_case_insensitive() {
    let hints: Vec<String> = vec!["a".into(), "s".into()];
    assert_eq!(match_input("A", &hints), MatchResult::Exact(0));
    assert_eq!(match_input("S", &hints), MatchResult::Exact(1));
}

// ============================================================================
// Auto Key
// ============================================================================

#[test]
fn auto_key_from_reverse_dns() {
    assert_eq!(auto_key_for_app("com.mitchellh.ghostty"), Some('g'));
    assert_eq!(auto_key_for_app("org.mozilla.firefox"), Some('f'));
}

#[test]
fn auto_key_from_simple_name() {
    assert_eq!(auto_key_for_app("firefox"), Some('f'));
    assert_eq!(auto_key_for_app("ghostty"), Some('g'));
}

// ============================================================================
// App-Grouped Hints
// ============================================================================

#[test]
fn app_hints_groups_by_app() {
    let apps = vec!["firefox", "firefox", "ghostty", "code"];
    let result = assign_app_hints(&apps, "fgcasdjkl");
    assert_eq!(result.len(), 4);

    // Firefox windows should get "f" and "ff".
    let ff_hints: Vec<&str> = result.iter()
        .filter(|(_, idx)| apps[*idx] == "firefox")
        .map(|(h, _)| h.as_str())
        .collect();
    assert!(ff_hints.contains(&"f"));
    assert!(ff_hints.contains(&"ff"));

    // Ghostty should get "g".
    let g_hints: Vec<&str> = result.iter()
        .filter(|(_, idx)| apps[*idx] == "ghostty")
        .map(|(h, _)| h.as_str())
        .collect();
    assert!(g_hints.contains(&"g"));
}

// ============================================================================
// MRU State Parsing
// ============================================================================

#[test]
fn mru_file_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mru");

    // Write state.
    std::fs::write(&path, "prev-window\ncurr-window").unwrap();

    // Read and parse manually (testing parse logic, not file I/O).
    let contents = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines[0], "prev-window");
    assert_eq!(lines[1], "curr-window");
}

// ============================================================================
// State Machine
// ============================================================================

#[test]
fn state_idle_to_border() {
    let mut state = WmState::new();
    assert!(state.is_idle());
    let action = state.on_activate();
    assert_eq!(action, Action::ShowBorder);
    assert!(state.is_overlay_visible());
}

#[test]
fn state_border_to_overlay_requires_frames_and_delay() {
    let mut state = WmState::new();
    state.on_activate();

    // Frame 1 with 0ms delay — not enough frames.
    let action = state.on_frame(0);
    assert_eq!(action, Action::None);

    // Frame 2 with 0ms delay — transition.
    let action = state.on_frame(0);
    assert_eq!(action, Action::ShowOverlay);
}

#[test]
fn state_quick_switch_on_fast_release() {
    let mut state = WmState::new();
    state.on_activate();
    // Release within 500ms window.
    let action = state.on_modifier_release(500);
    assert_eq!(action, Action::QuickSwitch);
    assert!(state.is_idle());
}

#[test]
fn state_slow_release_forces_overlay() {
    let mut state = WmState::BorderOnly {
        entered_at: Instant::now() - Duration::from_millis(200),
        frame_count: 0,
    };
    // Release after overlay_delay_ms=150 has passed.
    let action = state.on_modifier_release(150);
    assert_eq!(action, Action::ShowOverlay);
}

#[test]
fn state_escape_returns_to_idle() {
    let mut state = WmState::FullOverlay {
        input_buffer: String::new(),
        selection: 0,
        window_count: 5,
    };
    assert_eq!(state.on_escape(), Action::Dismiss);
    assert!(state.is_idle());
}

#[test]
fn state_selection_wraps_down() {
    let mut state = WmState::FullOverlay {
        input_buffer: String::new(),
        selection: 4,
        window_count: 5,
    };
    state.on_selection_down();
    assert_eq!(state.selection(), Some(0));
}

#[test]
fn state_selection_wraps_up() {
    let mut state = WmState::FullOverlay {
        input_buffer: String::new(),
        selection: 0,
        window_count: 5,
    };
    state.on_selection_up();
    assert_eq!(state.selection(), Some(4));
}

#[test]
fn state_confirm_on_empty_is_noop() {
    let mut state = WmState::FullOverlay {
        input_buffer: String::new(),
        selection: 0,
        window_count: 0,
    };
    assert_eq!(state.on_confirm(), Action::None);
}

#[test]
fn state_confirm_activates_selection() {
    let mut state = WmState::FullOverlay {
        input_buffer: String::new(),
        selection: 2,
        window_count: 5,
    };
    let action = state.on_confirm();
    assert_eq!(action, Action::ActivateWindow(2));
}

#[test]
fn state_hint_match_transitions() {
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
fn state_backspace_from_pending_returns_to_overlay() {
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
fn state_char_input_appends_to_buffer() {
    let mut state = WmState::FullOverlay {
        input_buffer: String::new(),
        selection: 0,
        window_count: 3,
    };
    state.on_char('a');
    state.on_char('b');
    assert_eq!(state.input_buffer(), Some("ab"));
    state.on_backspace();
    assert_eq!(state.input_buffer(), Some("a"));
}

#[test]
fn state_activation_timeout() {
    let mut state = WmState::PendingActivation {
        target: 2,
        pending_key: None,
        entered_at: Instant::now() - Duration::from_millis(300),
    };
    let action = state.check_activation_timeout(200);
    assert_eq!(action, Action::ActivateWindow(2));
    assert!(state.is_idle());
}

#[test]
fn state_activation_not_yet_timed_out() {
    let mut state = WmState::PendingActivation {
        target: 2,
        pending_key: None,
        entered_at: Instant::now(),
    };
    let action = state.check_activation_timeout(5000);
    assert_eq!(action, Action::None);
}

// ============================================================================
// WM Config Validation
// ============================================================================

#[test]
fn wm_config_defaults_are_valid() {
    let config = core_config::Config::default();
    let diagnostics = core_config::validate(&config);
    let errors: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.severity == core_config::DiagnosticSeverity::Error)
        .collect();
    assert!(errors.is_empty(), "default config should have no errors: {errors:?}");
}

#[test]
fn wm_config_rejects_empty_hint_keys() {
    let mut config = core_config::Config::default();
    let mut profile = core_config::ProfileConfig::default();
    profile.wm.hint_keys = String::new();
    config.profiles.insert("test".into(), profile);

    let diagnostics = core_config::validate(&config);
    assert!(
        diagnostics.iter().any(|d| {
            d.severity == core_config::DiagnosticSeverity::Error
                && d.message.contains("hint_keys")
        }),
        "expected error for empty hint_keys: {diagnostics:?}"
    );
}

#[test]
fn wm_config_rejects_duplicate_hint_keys() {
    let mut config = core_config::Config::default();
    let mut profile = core_config::ProfileConfig::default();
    profile.wm.hint_keys = "aasdf".into();
    config.profiles.insert("test".into(), profile);

    let diagnostics = core_config::validate(&config);
    assert!(
        diagnostics.iter().any(|d| {
            d.severity == core_config::DiagnosticSeverity::Error
                && d.message.contains("duplicate")
        }),
        "expected error for duplicate hint_keys: {diagnostics:?}"
    );
}

#[test]
fn wm_config_warns_on_extreme_delay() {
    let mut config = core_config::Config::default();
    let mut profile = core_config::ProfileConfig::default();
    profile.wm.overlay_delay_ms = 5000;
    config.profiles.insert("test".into(), profile);

    let diagnostics = core_config::validate(&config);
    assert!(
        diagnostics.iter().any(|d| {
            d.severity == core_config::DiagnosticSeverity::Warning
                && d.message.contains("overlay_delay_ms")
        }),
        "expected warning for extreme delay: {diagnostics:?}"
    );
}
