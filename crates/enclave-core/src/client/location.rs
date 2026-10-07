//! Sharing a location (`docs/16-features.md`: coordinates only).
//!
//! A location is a latitude and longitude in millionths of a degree (about
//! 11 cm) with an optional label, sent inside the session like any message.
//! Nothing is looked up: no map tiles, no place names, no network request
//! of any kind, so neither side's app reveals the place to a third party.
//! The app shows the coordinates and lets the person copy them. The place
//! lives in the message record, so a disappearing location is shredded
//! with its message.

use super::{Client, ContactState, Event, Message};
use crate::content::{Content, MsgId};
use crate::{CoreError, Result};
use enclave_proto::codec::{Reader, Writer};

/// Longest label, in bytes.
pub const MAX_LOCATION_LABEL: usize = 200;

/// A shared place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    /// Latitude in millionths of a degree (−90° to 90°).
    pub lat_e6: i32,
    /// Longitude in millionths of a degree (−180° to 180°).
    pub lon_e6: i32,
    /// What the sender called it (may be empty).
    pub label: String,
}

impl Location {
    /// Whether the coordinates are on Earth and the label fits.
    pub fn is_valid(&self) -> bool {
        (-90_000_000..=90_000_000).contains(&self.lat_e6)
            && (-180_000_000..=180_000_000).contains(&self.lon_e6)
            && self.label.len() <= MAX_LOCATION_LABEL
    }

    /// From degrees, as typed (rounded to millionths).
    pub fn from_degrees(lat: f64, lon: f64, label: &str) -> Option<Self> {
        if !lat.is_finite() || !lon.is_finite() {
            return None;
        }
        let l = Self {
            lat_e6: (lat * 1e6).round() as i32,
            lon_e6: (lon * 1e6).round() as i32,
            label: label.trim().to_string(),
        };
        l.is_valid().then_some(l)
    }

    /// `52.520008, 13.404954`.
    pub fn coordinates(&self) -> String {
        let f = |v: i32| {
            let sign = if v < 0 { "-" } else { "" };
            let a = v.unsigned_abs();
            format!("{sign}{}.{:06}", a / 1_000_000, a % 1_000_000)
        };
        format!("{}, {}", f(self.lat_e6), f(self.lon_e6))
    }

    /// `u32 lat ‖ u32 lon ‖ bytes(label)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.lat_e6 as u32)
            .u32(self.lon_e6 as u32)
            .bytes(self.label.as_bytes());
        w.finish()
    }

    /// Decode (strict; coordinates must be on the Earth).
    pub fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        let l = Self {
            lat_e6: r.u32()? as i32,
            lon_e6: r.u32()? as i32,
            label: String::from_utf8(r.bytes(MAX_LOCATION_LABEL)?.to_vec())
                .map_err(|_| enclave_proto::ProtoError::Decode)?,
        };
        r.end()?;
        if !l.is_valid() {
            return Err(enclave_proto::ProtoError::Decode);
        }
        Ok(l)
    }
}

impl Client {
    /// Send a location to `root` (it disappears with the conversation's
    /// timer like any message).
    pub async fn share_location(&mut self, root: &[u8; 64], loc: &Location) -> Result<Message> {
        if !loc.is_valid() {
            return Err(CoreError::TooLong);
        }
        let c = self.contacts.get(root).ok_or(CoreError::NotFound)?;
        if c.state != ContactState::Accepted {
            return Err(CoreError::NotAccepted);
        }
        let timer = c.timer;
        let now = self.now();
        let id: MsgId = self.rng.array("core/msg-id")?;
        let mut m = self.new_message(root, id, true, "", timer, now)?;
        m.location = Some(loc.clone());
        self.put_message(root, &m)?;
        let content = Content::Location {
            id,
            location: loc.encode(),
            expires: timer,
        };
        let sent = self.send_tracked(root, id, &content, now).await?;
        self.send_self_copy(root, &content, now).await?;
        m.sent = sent;
        self.put_message(root, &m)?;
        Ok(m)
    }

    /// A location that arrived (theirs, or ours from another device).
    pub(crate) fn on_location(
        &mut self,
        root: &[u8; 64],
        id: MsgId,
        location: &[u8],
        expires: u32,
        outgoing: bool,
        now: u64,
    ) -> Result<Option<Event>> {
        if self.find(root, &id).is_ok() {
            return Ok(None);
        }
        let Ok(loc) = Location::decode(location) else {
            return Ok(None);
        };
        let mut m = self.new_message(root, id, outgoing, "", expires, now)?;
        m.location = Some(loc);
        m.sent = outgoing;
        self.put_message(root, &m)?;
        Ok(Some(Event::Message {
            root: *root,
            message: m,
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn codec_and_limits() {
        let l = Location::from_degrees(-33.856784, 151.215297, " Opera House ").unwrap();
        assert_eq!(l.label, "Opera House");
        assert_eq!(l.coordinates(), "-33.856784, 151.215297");
        assert_eq!(Location::decode(&l.encode()).unwrap(), l);
        assert!(Location::from_degrees(91.0, 0.0, "").is_none());
        assert!(Location::from_degrees(0.0, -180.5, "").is_none());
        assert!(Location::from_degrees(f64::NAN, 0.0, "").is_none());
        let bad = Location {
            lat_e6: 95_000_000,
            lon_e6: 0,
            label: String::new(),
        };
        assert!(Location::decode(&bad.encode()).is_err());
        assert_eq!(
            Location::from_degrees(0.0000004, -0.5, "")
                .unwrap()
                .coordinates(),
            "0.000000, -0.500000"
        );
    }
}
