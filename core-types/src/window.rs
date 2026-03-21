use serde::{Deserialize, Serialize};

use crate::ids::{AppId, CompositorWorkspaceId, MonitorId, ProfileId, WindowId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Window {
    pub id: WindowId,
    pub app_id: AppId,
    pub title: String,
    pub workspace_id: CompositorWorkspaceId,
    pub monitor_id: MonitorId,
    pub geometry: Geometry,
    pub is_focused: bool,
    pub is_minimized: bool,
    pub is_fullscreen: bool,
    pub profile_id: ProfileId,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Geometry {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Padding {
    pub top: u32,
    pub right: u32,
    pub bottom: u32,
    pub left: u32,
}
