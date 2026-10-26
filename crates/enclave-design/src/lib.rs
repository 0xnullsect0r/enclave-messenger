//! Design tokens (`docs/17-design.md`).
//!
//! `design/tokens.toml` is the single source of truth. This crate parses it,
//! verifies every declared contrast pair against the WCAG 2.x formula in both
//! color modes, and generates the `Tokens` Slint global that the app imports.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use toml::Value;

/// Errors reading tokens.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The file is not valid TOML.
    #[error("parse: {0}")]
    Parse(String),
    /// A required key is missing or has the wrong type.
    #[error("missing or invalid: {0}")]
    Missing(String),
    /// A color is not `#RRGGBB`.
    #[error("bad color {0}")]
    Color(String),
}

/// An sRGB color.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    /// Parse `#RRGGBB`.
    pub fn parse(s: &str) -> Result<Self, TokenError> {
        let h = s
            .strip_prefix('#')
            .filter(|h| h.len() == 6)
            .ok_or_else(|| TokenError::Color(s.into()))?;
        let p = |i: usize| {
            u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| TokenError::Color(s.into()))
        };
        Ok(Self(p(0)?, p(2)?, p(4)?))
    }

    /// WCAG relative luminance.
    pub fn luminance(self) -> f64 {
        let lin = |c: u8| {
            let c = f64::from(c) / 255.0;
            if c <= 0.04045 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(self.0) + 0.7152 * lin(self.1) + 0.0722 * lin(self.2)
    }

    /// `#rrggbb`.
    pub fn hex(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.0, self.1, self.2)
    }
}

/// WCAG contrast ratio between two colors.
pub fn contrast(a: Rgb, b: Rgb) -> f64 {
    let (la, lb) = (a.luminance(), b.luminance());
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// Parsed tokens.
pub struct Tokens {
    /// Light-mode colors by name.
    pub light: BTreeMap<String, Rgb>,
    /// Dark-mode colors by name.
    pub dark: BTreeMap<String, Rgb>,
    /// `(foreground, background, minimum)` pairs.
    pub pairs: Vec<(String, String, f64)>,
    /// Numeric tokens flattened as `section-key` (type, space, radius, motion).
    pub numbers: BTreeMap<String, f64>,
}

/// A contrast pair that fails.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    /// "light" or "dark".
    pub mode: &'static str,
    /// Foreground token.
    pub fg: String,
    /// Background token.
    pub bg: String,
    /// Measured ratio.
    pub ratio: f64,
    /// Required ratio.
    pub min: f64,
}

fn colors(v: &Value, mode: &str) -> Result<BTreeMap<String, Rgb>, TokenError> {
    let t = v
        .get("color")
        .and_then(|c| c.get(mode))
        .and_then(Value::as_table)
        .ok_or_else(|| TokenError::Missing(format!("color.{mode}")))?;
    t.iter()
        .map(|(k, v)| {
            let s = v
                .as_str()
                .ok_or_else(|| TokenError::Missing(format!("color.{mode}.{k}")))?;
            Ok((k.clone(), Rgb::parse(s)?))
        })
        .collect()
}

impl Tokens {
    /// Parse `tokens.toml` text.
    pub fn parse(text: &str) -> Result<Self, TokenError> {
        let v: Value = text
            .parse()
            .map_err(|e: toml::de::Error| TokenError::Parse(e.to_string()))?;
        let light = colors(&v, "light")?;
        let dark = colors(&v, "dark")?;
        let pairs = v
            .get("contrast")
            .and_then(|c| c.get("pairs"))
            .and_then(Value::as_array)
            .ok_or_else(|| TokenError::Missing("contrast.pairs".into()))?
            .iter()
            .map(|p| {
                let a = p
                    .as_array()
                    .filter(|a| a.len() == 3)
                    .ok_or_else(|| TokenError::Missing("pair".into()))?;
                let s = |i: usize| {
                    a[i].as_str()
                        .map(str::to_string)
                        .ok_or_else(|| TokenError::Missing("pair".into()))
                };
                let min = a[2]
                    .as_float()
                    .or_else(|| a[2].as_integer().map(|i| i as f64));
                Ok((
                    s(0)?,
                    s(1)?,
                    min.ok_or_else(|| TokenError::Missing("pair min".into()))?,
                ))
            })
            .collect::<Result<Vec<_>, TokenError>>()?;
        let mut numbers = BTreeMap::new();
        for section in ["type", "space", "radius", "motion", "icon"] {
            if let Some(t) = v.get(section).and_then(Value::as_table) {
                for (k, x) in t {
                    let n = x.as_float().or_else(|| x.as_integer().map(|i| i as f64));
                    if let Some(n) = n {
                        numbers.insert(format!("{section}-{}", k.replace('_', "-")), n);
                    }
                }
            }
        }
        Ok(Self {
            light,
            dark,
            pairs,
            numbers,
        })
    }

    /// Check every declared pair in both modes.
    pub fn check(&self) -> Result<Vec<Failure>, TokenError> {
        let mut out = Vec::new();
        for (mode, map) in [("light", &self.light), ("dark", &self.dark)] {
            for (fg, bg, min) in &self.pairs {
                let f = *map
                    .get(fg)
                    .ok_or_else(|| TokenError::Missing(format!("{mode}.{fg}")))?;
                let b = *map
                    .get(bg)
                    .ok_or_else(|| TokenError::Missing(format!("{mode}.{bg}")))?;
                let ratio = contrast(f, b);
                if ratio + 1e-9 < *min {
                    out.push(Failure {
                        mode,
                        fg: fg.clone(),
                        bg: bg.clone(),
                        ratio,
                        min: *min,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Generate the `Tokens` Slint global. Colors switch on `dark`; lengths
    /// and font sizes scale with `text-scale` where they are type.
    pub fn to_slint(&self) -> Result<String, TokenError> {
        let mut s = String::from(
            "// Generated from design/tokens.toml by enclave-design. Do not edit.\n\
             export global Tokens {\n    in-out property <bool> dark: true;\n    in-out property <float> text-scale: 1.0;\n    in-out property <bool> reduce-motion: false;\n",
        );
        for (name, light) in &self.light {
            let dark = self
                .dark
                .get(name)
                .ok_or_else(|| TokenError::Missing(format!("dark.{name}")))?;
            let _ = writeln!(
                s,
                "    out property <color> {}: dark ? {} : {};",
                name.replace('_', "-"),
                dark.hex(),
                light.hex()
            );
        }
        for (name, n) in &self.numbers {
            let (kind, value) = if name.starts_with("type-")
                && !name.contains("line-height")
                && !name.contains("tracking")
                && !name.contains("scale")
            {
                ("length", format!("{n}px * text-scale"))
            } else if name.starts_with("type-") {
                ("float", format!("{n}"))
            } else if name.starts_with("motion-") {
                ("duration", format!("{n}ms"))
            } else {
                ("length", format!("{n}px"))
            };
            let _ = writeln!(s, "    out property <{kind}> {name}: {value};");
        }
        s.push_str("}\n");
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const TOKENS: &str = include_str!("../../../design/tokens.toml");

    #[test]
    fn wcag_formula_matches_known_values() {
        let white = Rgb(255, 255, 255);
        let black = Rgb(0, 0, 0);
        assert!((contrast(white, black) - 21.0).abs() < 1e-9);
        // Paper on Pine, as documented in docs/17-design.md.
        let r = contrast(
            Rgb::parse("#F6F3EC").unwrap(),
            Rgb::parse("#1D5646").unwrap(),
        );
        assert!((r - 7.67).abs() < 0.01, "{r}");
    }

    #[test]
    fn every_declared_pair_passes_in_both_modes() {
        let t = Tokens::parse(TOKENS).unwrap();
        let failures = t.check().unwrap();
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn generates_slint() {
        let s = Tokens::parse(TOKENS).unwrap().to_slint().unwrap();
        assert!(s.contains("out property <color> pine: dark ? #7cc4a8 : #1d5646;"));
        assert!(s.contains("out property <length> type-body: 17px * text-scale;"));
        // Dark by default; the app turns it off for the light theme.
        assert!(s.contains("in-out property <bool> dark: true;"));
    }
}
