//! Chat folders (`docs/16-features.md`): named lists of conversations,
//! local to the account and kept the same on all its devices (a synced
//! setting, `own_sync.rs`). Nothing about them leaves the account.
//!
//! Stored as the setting `folders`: `u8 n ‖ n × (bytes name ‖ u16 count ‖
//! count × bytes place)`, a place being a conversation's preference key
//! (`"c" ‖ root` or `"g" ‖ group id`).

use super::Client;
use super::search::Place;
use crate::{CoreError, Result};
use enclave_proto::codec::{Reader, Writer};

/// The setting the folders are kept under.
pub(crate) const SETTING: &str = "folders";
/// Most folders.
pub const MAX_FOLDERS: usize = 10;
/// Longest folder name, in characters.
pub const MAX_FOLDER_NAME: usize = 32;
/// Most conversations in one folder.
pub const MAX_FOLDER_SIZE: usize = 1000;

/// A folder: its name and its conversations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Folder {
    /// What it's called.
    pub name: String,
    /// What's in it.
    pub places: Vec<Place>,
}

fn place_bytes(p: &Place) -> Vec<u8> {
    match p {
        Place::Contact(r) => [&b"c"[..], &r[..]].concat(),
        Place::Group(g) => [&b"g"[..], &g[..]].concat(),
    }
}

fn place_from(b: &[u8]) -> Option<Place> {
    match b.split_first()? {
        (b'c', r) => Some(Place::Contact(r.try_into().ok()?)),
        (b'g', g) => Some(Place::Group(g.try_into().ok()?)),
        _ => None,
    }
}

fn encode(folders: &[Folder]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(folders.len() as u8);
    for f in folders {
        w.bytes(f.name.as_bytes()).u16(f.places.len() as u16);
        for p in &f.places {
            w.bytes(&place_bytes(p));
        }
    }
    w.finish()
}

fn decode(b: &[u8]) -> Option<Vec<Folder>> {
    let mut r = Reader::new(b);
    let n = usize::from(r.u8().ok()?);
    if n > MAX_FOLDERS {
        return None;
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let name = String::from_utf8(r.bytes(4 * MAX_FOLDER_NAME).ok()?.to_vec()).ok()?;
        let count = usize::from(r.u16().ok()?);
        if count > MAX_FOLDER_SIZE {
            return None;
        }
        let mut places = Vec::with_capacity(count);
        for _ in 0..count {
            places.push(place_from(r.bytes(65).ok()?)?);
        }
        out.push(Folder { name, places });
    }
    r.end().ok()?;
    Some(out)
}

impl Client {
    /// The account's folders, in their order.
    pub fn folders(&self) -> Vec<Folder> {
        match self.setting(SETTING) {
            Ok(Some(b)) => decode(&b).unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    fn save_folders(&mut self, folders: &[Folder]) -> Result<()> {
        self.set_setting(SETTING, &encode(folders))
    }

    /// A new, empty folder. Names are trimmed, unique and at most
    /// [`MAX_FOLDER_NAME`] characters; at most [`MAX_FOLDERS`] folders.
    pub fn new_folder(&mut self, name: &str) -> Result<()> {
        let name = super::sanitize_name(name.trim());
        if name.is_empty() || name.chars().count() > MAX_FOLDER_NAME {
            return Err(CoreError::TooLong);
        }
        let mut all = self.folders();
        if all.iter().any(|f| f.name == name) {
            return Err(CoreError::NotAccepted);
        }
        if all.len() >= MAX_FOLDERS {
            return Err(CoreError::TooLong);
        }
        all.push(Folder {
            name,
            places: Vec::new(),
        });
        self.save_folders(&all)
    }

    /// Delete a folder (its conversations stay where they are).
    pub fn delete_folder(&mut self, name: &str) -> Result<()> {
        let mut all = self.folders();
        all.retain(|f| f.name != name);
        self.save_folders(&all)
    }

    /// Put a conversation in a folder, or take it out.
    pub fn set_in_folder(&mut self, name: &str, place: &Place, on: bool) -> Result<()> {
        let mut all = self.folders();
        let f = all
            .iter_mut()
            .find(|f| f.name == name)
            .ok_or(CoreError::NotFound)?;
        let had = f.places.contains(place);
        if on && !had {
            if f.places.len() >= MAX_FOLDER_SIZE {
                return Err(CoreError::TooLong);
            }
            f.places.push(*place);
        } else if !on && had {
            f.places.retain(|p| p != place);
        } else {
            return Ok(());
        }
        self.save_folders(&all)
    }

    /// The folders `place` is in.
    pub fn folders_of(&self, place: &Place) -> Vec<String> {
        self.folders()
            .into_iter()
            .filter(|f| f.places.contains(place))
            .map(|f| f.name)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn folders_round_trip() {
        let f = vec![
            Folder {
                name: "Work".into(),
                places: vec![Place::Contact([1; 64]), Place::Group([2; 32])],
            },
            Folder::default(),
        ];
        assert_eq!(decode(&encode(&f)).unwrap(), f);
        assert!(decode(&[11]).is_none(), "too many");
        assert!(decode(&encode(&f)[..5]).is_none());
    }
}
