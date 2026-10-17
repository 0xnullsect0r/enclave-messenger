//! StatusNotifierItem (the freedesktop draft KDE and the AppIndicator
//! extension implement) with a two-item `com.canonical.dbusmenu`.

use super::{Icon, Labels, TrayEvent, fire};
use std::collections::HashMap;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Structure, Value};

/// ARGB32 in network byte order, as `IconPixmap` wants it.
type Pixmap = (i32, i32, Vec<u8>);

struct Item {
    tooltip: String,
    pixmap: Vec<Pixmap>,
}

#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl Item {
    #[zbus(property)]
    fn category(&self) -> String {
        "Communications".into()
    }
    #[zbus(property)]
    fn id(&self) -> String {
        "com.aricummings.Enclave".into()
    }
    #[zbus(property)]
    fn title(&self) -> String {
        self.tooltip.clone()
    }
    #[zbus(property)]
    fn status(&self) -> String {
        "Active".into()
    }
    #[zbus(property)]
    fn icon_name(&self) -> String {
        String::new()
    }
    #[zbus(property)]
    fn icon_pixmap(&self) -> Vec<Pixmap> {
        self.pixmap.clone()
    }
    #[zbus(property)]
    fn tool_tip(&self) -> (String, Vec<Pixmap>, String, String) {
        (
            String::new(),
            Vec::new(),
            self.tooltip.clone(),
            String::new(),
        )
    }
    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        false
    }
    #[zbus(property)]
    fn menu(&self) -> OwnedObjectPath {
        OwnedObjectPath::try_from("/MenuBar").unwrap_or_default()
    }
    fn activate(&self, _x: i32, _y: i32) {
        fire(TrayEvent::Open);
    }
    fn secondary_activate(&self, _x: i32, _y: i32) {
        fire(TrayEvent::Open);
    }
    fn context_menu(&self, _x: i32, _y: i32) {}
    fn scroll(&self, _delta: i32, _orientation: &str) {}
}

/// Menu ids: 0 is the root.
const OPEN: i32 = 1;
const QUIT: i32 = 2;

struct Menu {
    open: String,
    quit: String,
}

type Props = HashMap<String, OwnedValue>;
type Layout = (i32, Props, Vec<OwnedValue>);

fn owned(v: Value<'_>) -> OwnedValue {
    v.try_to_owned().unwrap_or_else(|_| OwnedValue::from(0u8))
}

impl Menu {
    fn props(&self, id: i32) -> Props {
        let mut p = Props::new();
        match id {
            OPEN => {
                p.insert("label".into(), owned(Value::from(self.open.as_str())));
            }
            QUIT => {
                p.insert("label".into(), owned(Value::from(self.quit.as_str())));
            }
            _ => {
                p.insert("children-display".into(), owned(Value::from("submenu")));
            }
        }
        p
    }

    fn node(&self, id: i32) -> Layout {
        let children = if id == 0 {
            [OPEN, QUIT]
                .into_iter()
                .map(|c| {
                    let (i, p, k) = self.node(c);
                    owned(Value::from(Structure::from((i, p, k))))
                })
                .collect()
        } else {
            Vec::new()
        };
        (id, self.props(id), children)
    }
}

#[zbus::interface(name = "com.canonical.dbusmenu")]
impl Menu {
    #[zbus(property)]
    fn version(&self) -> u32 {
        3
    }
    #[zbus(property)]
    fn status(&self) -> String {
        "normal".into()
    }
    fn get_layout(
        &self,
        parent_id: i32,
        _recursion_depth: i32,
        _property_names: Vec<String>,
    ) -> (u32, Layout) {
        (1, self.node(parent_id))
    }
    fn get_group_properties(
        &self,
        ids: Vec<i32>,
        _property_names: Vec<String>,
    ) -> Vec<(i32, Props)> {
        ids.into_iter().map(|i| (i, self.props(i))).collect()
    }
    fn get_property(&self, id: i32, name: String) -> OwnedValue {
        self.props(id)
            .remove(&name)
            .unwrap_or_else(|| owned(Value::from("")))
    }
    fn event(&self, id: i32, event_id: String, _data: OwnedValue, _timestamp: u32) {
        if event_id == "clicked" {
            match id {
                OPEN => fire(TrayEvent::Open),
                QUIT => fire(TrayEvent::Quit),
                _ => {}
            }
        }
    }
    fn event_group(&self, events: Vec<(i32, String, OwnedValue, u32)>) -> Vec<i32> {
        for (id, e, d, t) in events {
            self.event(id, e, d, t);
        }
        Vec::new()
    }
    fn about_to_show(&self, _id: i32) -> bool {
        false
    }
    fn about_to_show_group(&self, _ids: Vec<i32>) -> (Vec<i32>, Vec<i32>) {
        (Vec::new(), Vec::new())
    }
}

/// The icon while shown: the bus connection that serves it.
pub(super) struct Inner {
    _conn: zbus::blocking::Connection,
}

fn argb(icon: &Icon) -> Pixmap {
    let px = icon
        .rgba
        .chunks_exact(4)
        .flat_map(|p| [p[3], p[0], p[1], p[2]])
        .collect();
    (icon.width as i32, icon.height as i32, px)
}

pub(super) fn show(icon: &Icon, labels: &Labels) -> Option<Inner> {
    // Registered under the connection's unique name (the spec allows it),
    // so no well-known name is owned: a Flatpak needs only to talk to the
    // watcher.
    let conn = zbus::blocking::connection::Builder::session()
        .ok()?
        .serve_at(
            "/StatusNotifierItem",
            Item {
                tooltip: labels.tooltip.clone(),
                pixmap: vec![argb(icon)],
            },
        )
        .ok()?
        .serve_at(
            "/MenuBar",
            Menu {
                open: labels.open.clone(),
                quit: labels.quit.clone(),
            },
        )
        .ok()?
        .build()
        .ok()?;
    let watcher = zbus::blocking::Proxy::new(
        &conn,
        "org.kde.StatusNotifierWatcher",
        "/StatusNotifierWatcher",
        "org.kde.StatusNotifierWatcher",
    )
    .ok()?;
    // A watcher with no host showing the icons (an extension switched
    // off): no icon either.
    if !watcher
        .get_property::<bool>("IsStatusNotifierHostRegistered")
        .unwrap_or(false)
    {
        return None;
    }
    let name = conn.unique_name()?.to_string();
    // No watcher (a desktop without a status area): no icon.
    watcher
        .call_method("RegisterStatusNotifierItem", &(name.as_str(),))
        .ok()?;
    Some(Inner { _conn: conn })
}
