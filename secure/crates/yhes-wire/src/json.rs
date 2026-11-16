//! Strict JSON reading: bounded size and depth, no duplicate object keys, no
//! floats or negative numbers, and typed field extraction that rejects
//! unknown fields. Tokenizing is done by `serde_json`.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};

use crate::error::Error;
use crate::{MAX_ID_BYTES, MAX_JSON_DEPTH, MAX_TIMESTAMP};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Int(u64),
    Str(String),
    Arr(Vec<Value>),
    Obj(BTreeMap<String, Value>),
}

const DUPLICATE: &str = "yhes:duplicate-key";
const DEPTH: &str = "yhes:depth";
const NUMBER: &str = "yhes:number";

struct Seed(usize);

impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E: DeError>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_u64<E: DeError>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Int(v))
    }
    fn visit_i64<E: DeError>(self, _: i64) -> Result<Value, E> {
        Err(E::custom(NUMBER))
    }
    fn visit_f64<E: DeError>(self, _: f64) -> Result<Value, E> {
        Err(E::custom(NUMBER))
    }
    fn visit_str<E: DeError>(self, v: &str) -> Result<Value, E> {
        Ok(Value::Str(v.to_owned()))
    }
    fn visit_string<E: DeError>(self, v: String) -> Result<Value, E> {
        Ok(Value::Str(v))
    }
    fn visit_unit<E: DeError>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.0 == 0 {
            return Err(A::Error::custom(DEPTH));
        }
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(Seed(self.0 - 1))? {
            out.push(v);
        }
        Ok(Value::Arr(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.0 == 0 {
            return Err(A::Error::custom(DEPTH));
        }
        let mut out = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(Seed(self.0 - 1))?;
            if out.insert(key, value).is_some() {
                return Err(A::Error::custom(DUPLICATE));
            }
        }
        Ok(Value::Obj(out))
    }
}

/// Parses one complete JSON document of at most `max_bytes`.
pub(crate) fn parse(bytes: &[u8], max_bytes: usize) -> Result<Value, Error> {
    if bytes.len() > max_bytes {
        return Err(Error::TooLarge);
    }
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = Seed(MAX_JSON_DEPTH)
        .deserialize(&mut de)
        .map_err(classify)?;
    de.end().map_err(|_| Error::Malformed("trailing data"))?;
    Ok(value)
}

fn classify(e: serde_json::Error) -> Error {
    let text = e.to_string();
    if text.contains(DUPLICATE) {
        Error::Malformed("duplicate object key")
    } else if text.contains(DEPTH) || text.contains("recursion limit") {
        Error::Malformed("nesting too deep")
    } else if text.contains(NUMBER) {
        Error::Malformed("number is not a non-negative integer")
    } else {
        Error::Malformed("invalid JSON")
    }
}

/// An object whose fields must all be consumed.
pub(crate) struct Fields {
    map: BTreeMap<String, Value>,
}

impl Fields {
    pub(crate) fn new(value: Value) -> Result<Fields, Error> {
        match value {
            Value::Obj(map) => Ok(Fields { map }),
            _ => Err(Error::Schema("expected an object")),
        }
    }

    pub(crate) fn take(&mut self, name: &'static str) -> Result<Value, Error> {
        self.map.remove(name).ok_or(Error::Schema("missing field"))
    }

    pub(crate) fn string(&mut self, name: &'static str) -> Result<String, Error> {
        match self.take(name)? {
            Value::Str(s) => Ok(s),
            _ => Err(Error::Schema("expected a string")),
        }
    }

    pub(crate) fn opt_string(&mut self, name: &'static str) -> Result<Option<String>, Error> {
        match self.take(name)? {
            Value::Null => Ok(None),
            Value::Str(s) => Ok(Some(s)),
            _ => Err(Error::Schema("expected a string or null")),
        }
    }

    pub(crate) fn int(&mut self, name: &'static str) -> Result<u64, Error> {
        match self.take(name)? {
            Value::Int(n) => Ok(n),
            _ => Err(Error::Schema("expected an integer")),
        }
    }

    pub(crate) fn opt_int(&mut self, name: &'static str) -> Result<Option<u64>, Error> {
        match self.take(name)? {
            Value::Null => Ok(None),
            Value::Int(n) => Ok(Some(n)),
            _ => Err(Error::Schema("expected an integer or null")),
        }
    }

    pub(crate) fn timestamp(&mut self, name: &'static str) -> Result<u64, Error> {
        let n = self.int(name)?;
        if n > MAX_TIMESTAMP {
            return Err(Error::Schema("timestamp out of range"));
        }
        Ok(n)
    }

    pub(crate) fn array(&mut self, name: &'static str) -> Result<Vec<Value>, Error> {
        match self.take(name)? {
            Value::Arr(a) => Ok(a),
            _ => Err(Error::Schema("expected an array")),
        }
    }

    pub(crate) fn id(&mut self, name: &'static str) -> Result<String, Error> {
        let s = self.string(name)?;
        check_id(&s, name)?;
        Ok(s)
    }

    pub(crate) fn opt_id(&mut self, name: &'static str) -> Result<Option<String>, Error> {
        let s = self.opt_string(name)?;
        if let Some(s) = &s {
            check_id(s, name)?;
        }
        Ok(s)
    }

    pub(crate) fn finish(self) -> Result<(), Error> {
        if self.map.is_empty() {
            Ok(())
        } else {
            Err(Error::Schema("unknown field"))
        }
    }
}

/// Bounded, path-safe identifier: `[A-Za-z0-9][A-Za-z0-9._-]*`, no `..`.
pub(crate) fn check_id(s: &str, what: &'static str) -> Result<(), Error> {
    let b = s.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= MAX_ID_BYTES
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        && !s.contains("..");
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidId(what))
    }
}

/// A list of identifiers in strictly ascending byte order.
pub(crate) fn sorted_ids(values: Vec<Value>, what: &'static str) -> Result<Vec<String>, Error> {
    let mut out: Vec<String> = Vec::with_capacity(values.len());
    for v in values {
        let Value::Str(s) = v else {
            return Err(Error::Schema("expected a string"));
        };
        check_id(&s, what)?;
        if out.last().is_some_and(|prev| prev.as_str() >= s.as_str()) {
            return Err(Error::Schema("list is not sorted and unique"));
        }
        out.push(s);
    }
    Ok(out)
}
