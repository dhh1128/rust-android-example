use std::error;
use std::fmt;
use std::error::Error;

/// Hold a set of bits that can be set, unset, and tested by index.
/// Basically behave like an array of bits.
#[derive(Debug)]
pub struct Bitmap {
    items: Vec<u32>
}

#[derive(Debug, Clone)]
pub enum BitmapError {
    BadIndex { actual: usize, size: usize },
    BadJson(String)
}

impl fmt::Display for BitmapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BitmapError::BadIndex{ actual, size} => {
                write!(f, "Bad bitmap index {}. Expected 0 <= n < {}.", actual, size)?;
            },
            BitmapError::BadJson(msg) => {
                write!(f, "Bad JSON. {}", msg)?;
            }
        }
        write!(f, "invalid first item to double")
    }
}

impl error::Error for BitmapError {
    fn description(&self) -> &str {
        match self {
            BitmapError::BadIndex{actual: _, size: _} => "Bad bitmap index",
            BitmapError::BadJson(_) => "Bad JSON"
        }
    }
}

impl Bitmap {
    pub fn new(bit_count: usize) -> Result<Bitmap, Box<dyn Error>> {
        let mut item_count = bit_count / 32;
        if bit_count % 32 > 0 {
            item_count += 1;
        }
        Ok(Bitmap { items: vec!(0u32; item_count) })
    }

    fn get_index_and_shift(i: usize) -> (usize, usize) {
        let index = i / 32;
        let shift = 31 - (i % 32);
        return (index, shift)
    }

    pub fn set_bit(&mut self, i: usize) {
        let (index, shift) = Bitmap::get_index_and_shift(i);
        self.items[index] = self.items[index] | (1u32 << shift);
    }

    pub fn unset_bit(&mut self, i: usize) {
        let (index, shift) = Bitmap::get_index_and_shift(i);
        self.items[index] = self.items[index] & !(1u32 << shift);
    }

    pub fn get_bit(&self, i: usize) -> bool {
        let (index, shift) = Bitmap::get_index_and_shift(i);
        let item = &self.items[index];
        (item >> shift) & 1u32 == 1u32
    }

    pub fn get_byte_for_bit(&self, i: usize) -> u8 {
        let (index, shift) = Bitmap::get_index_and_shift(i);
        let item = &self.items[index];
        ((item >> ((shift / 8) * 8)) as u8) & 0xFFu8
    }

    #[cfg(__notyet__)]
    pub fn from_revlist2020<R>(reader: R) -> Result<Bitmap, Box<dyn Error>>
        where R: io::Read {
        // Serde has a method that will read directly from a reader. However,
        // its own documentation says this method is less efficient than
        // reading a full file into a string and then calling ::from_str.
        // Hence, I'm doing taking more performant path.
        let mut buffered = BufReader::new(reader);
        let mut txt = String::new();
        buffered.read_to_string(&mut txt)?;
        match txt.find('{') {
            Some(open_brace_idx) => {
                let revlist_cred = serde_json::from_str(&txt[open_brace_idx..])?;
                let context = revlist_cred["@context"];
                if context.eq(serde_json::Value::Null) {
                    return Err(Box::from(BitmapError::BadJson("No @context.".to_string())));
                }
                if context.eq(serde_json::Value::Null) {}
                Bitmap::new(25)
            },
            None => {
                return Err(Box::from(BitmapError::BadJson("No open brace in supposed JSON text.".to_string())));
            }
        }
    }

    pub fn len(&self) -> usize {
        32 * self.items.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctor_all_zeros() {
        let b = Bitmap::new(256).unwrap();
        assert_eq!(b.get_bit(0), false);
        assert_eq!(b.get_bit(255), false);
    }

    #[test]
    fn ctor_misaligned() {
        let b = Bitmap::new(25).unwrap();
        assert_eq!(b.get_bit(0), false);
        assert_eq!(b.get_bit(25), false);
    }

    #[test]
    fn one_set() {
        let mut b = Bitmap::new(256).unwrap();
        b.set_bit(18);
        assert_eq!(b.get_bit(0), false);
        assert_eq!(b.get_bit(18), true);
    }

    #[test]
    fn get_byte_for_bit() {
        let mut b = Bitmap::new(256).unwrap();
        b.set_bit(18);
        assert_eq!(b.get_byte_for_bit(0), 0u8);
        let n = b.get_byte_for_bit(18);
        assert_eq!(n, 1u8 << 5);
    }

    #[test]
    #[cfg(__notyet__)]
    fn load_bad_revlist_not_json() {
        assert!(Bitmap::from_revlist2020("not json".as_bytes()).is_err());
    }

    #[test]
    #[cfg(__notyet__)]
    fn load_bad_revlist_empty() {
        assert!(Bitmap::from_revlist2020("".as_bytes()).is_err());
    }


    #[cfg(__notyet__)]
    const SAMPLE: &str = r#"\
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc-revocation-list-2020/v1"
  ],
  "id": "https://example.com/credentials/status/3",
  "type": ["VerifiableCredential", "RevocationList2020Credential"],
  "issuer": "did:example:12345",
  "issued": "2020-04-05T14:27:40Z",
  "credentialSubject": {
    "id": "https://example.com/status/3#list",
    "type": "RevocationList2020",
    "encodedList": "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQsvoAAAAAAAAAAAAAAAAP4GcwM92tQwAAA"
  },
  "proof": { ... }
}"#;

    #[test]
    #[cfg(__notyet__)]
    fn load_bad_revlist_no_context() {
        match Bitmap::from_revlist2020(SAMPLE.replace("@", "~").as_bytes()) {
            Ok(_) => panic!("Expected complaint about missing context."),
            Err(e) => {
                e.to_string().find("@context").expect("should complain about missing @context");
            }
        }
    }

    #[test]
    #[cfg(__notyet__)]
    fn load_valid_revlist() {
        let b = Bitmap::from_revlist2020(SAMPLE.as_bytes()).unwrap();
    }
}
