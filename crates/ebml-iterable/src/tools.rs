//!
//! Contains a number of tools that are useful when working with EBML encoded files.
//!

use std::convert::TryInto;

use super::errors::tool::ToolError;

///
/// Trait to enable easy serialization to a vint.
///
/// This is only available for types that can be cast as `u64`.
///
pub trait Vint: Into<u64> + Copy {
    ///
    /// Returns a representation of the current value as a vint array.
    ///
    /// # Errors
    ///
    /// This can return an error if the value is too large to be representable as a vint.
    ///
    fn as_vint(self) -> Result<Vec<u8>, ToolError> {
        let val: u64 = self.into();
        check_size_u64(val, 8)?;

        if val < (1 << 7) {
            Ok(as_vint_no_check_u64::<1>(val).to_vec())
        } else if val < (1 << (7 * 2)) {
            Ok(as_vint_no_check_u64::<2>(val).to_vec())
        } else if val < (1 << (7 * 3)) {
            Ok(as_vint_no_check_u64::<3>(val).to_vec())
        } else if val < (1 << (7 * 4)) {
            Ok(as_vint_no_check_u64::<4>(val).to_vec())
        } else if val < (1 << (7 * 5)) {
            Ok(as_vint_no_check_u64::<5>(val).to_vec())
        } else if val < (1 << (7 * 6)) {
            Ok(as_vint_no_check_u64::<6>(val).to_vec())
        } else if val < (1 << (7 * 7)) {
            Ok(as_vint_no_check_u64::<7>(val).to_vec())
        } else {
            Ok(as_vint_no_check_u64::<8>(val).to_vec())
        }
    }

    ///
    /// Returns a representation of the current value as a vint array with a specified length.
    ///
    /// # Errors
    ///
    /// This can return an error if the value is too large to be representable as a vint.
    ///
    fn as_vint_with_length<const LENGTH: usize>(&self) -> Result<[u8; LENGTH], ToolError> {
        let val: u64 = (*self).into();
        check_size_u64(val, LENGTH)?;
        Ok(as_vint_no_check_u64::<LENGTH>(val))
    }
}

impl Vint for u64 {}
impl Vint for u32 {}
impl Vint for u16 {}
impl Vint for u8 {}

#[inline]
fn check_size_u64(val: u64, max_length: usize) -> Result<(), ToolError> {
    if val >= 1 << (max_length * 7) {
        Err(ToolError::WriteVintOverflow(val))
    } else {
        Ok(())
    }
}

#[inline]
fn as_vint_no_check_u64<const LENGTH: usize>(val: u64) -> [u8; LENGTH] {
    let mut bytes: [u8; 8] = val.to_be_bytes();
    bytes[8 - LENGTH] |= 1 << (8 - LENGTH);
    bytes[8 - LENGTH..].try_into().expect("8 - (8-length) != length !?!?")
}

///
/// Reads a vint from the beginning of the input array slice.
///
/// This method returns an option with the `None` variant used to indicate there was not enough data in the buffer to completely read a vint.
///
/// The returned tuple contains the value of the vint (`u64`) and the length of the vint (`usize`).  The length will be less than or equal to the length of the input slice.
///
/// # Errors
///
/// This method can return a `ToolError` if the input array cannot be read as a vint.
///
pub fn read_vint(buffer: &[u8]) -> Result<Option<(u64, usize)>, ToolError> {
    if buffer.is_empty() {
        return Ok(None);
    }

    if buffer[0] == 0 {
        return Err(ToolError::ReadVintOverflow);
    }

    let length = 8 - buffer[0].ilog2() as usize;

    if length > buffer.len() {
        // Not enough data in the buffer to read out the vint value
        return Ok(None);
    }

    let mut value = buffer[0] as u64;
    value -= 1 << (8 - length);

    for item in buffer.iter().take(length).skip(1) {
        value <<= 8;
        value += *item as u64;
    }

    Ok(Some((value, length)))
}

pub fn is_vint(val: u64) -> bool {
    if val == 0 {
        return false;
    }

    val.ilog2().is_multiple_of(7)
}

///
/// Trait to enable easy serialization to a signed vint.
///
/// This is only available for types that can be cast as `i64`.  A signed vint can be written as a variable number of bytes just like a regular vint, but the value portion of the vint is expressed in two's complement notation.
///
/// For example, the decimal number "-33" would be written as [0xDF = 1101 1111].  This value is determined by first taking the two's complement of 33 [0x21 = 0010 0001] **but only using the bits available for the vint value**.  In this case, that is 7 bits (because the vint marker takes up the 8th bit).  The two's complement is [101 1111]. A handy calculator for two's complement can be found [here](https://www.omnicalculator.com/math/twos-complement).  Once the two's complement has been found, simply prepend the vint marker as usual to get [1101 1111 = 0xDF].
///
/// Some more examples:
/// ```
/// use ebml_iterable::tools::SignedVint;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// assert_eq!(vec![0xDF], (-33i64).as_signed_vint().unwrap());
/// assert_eq!(vec![0x40, 0xC8], (200i64).as_signed_vint().unwrap());
/// assert_eq!(vec![0x7F, 0x38], (-200i64).as_signed_vint().unwrap());
/// assert_eq!(vec![0xFF], (-1i64).as_signed_vint().unwrap());
/// # Ok(())
/// # }
/// ```
pub trait SignedVint: Into<i64> + Copy {
    ///
    /// Returns a representation of the current value as a vint array.
    ///
    /// # Errors
    ///
    /// This can return an error if the value is outside of the range that can be represented as a vint.
    ///
    fn as_signed_vint(&self) -> Result<Vec<u8>, ToolError> {
        let val: i64 = (*self).into();
        check_size_i64(val, 8)?;
        let mut length = 1;
        while length <= 8 {
            if val >= -(1 << (7 * length - 1)) && val < (1 << (7 * length - 1)) {
                break;
            }
            length += 1;
        }

        Ok(as_vint_no_check_i64(val, length))
    }

    ///
    /// Returns a representation of the current value as a vint array with a specified length.
    ///
    /// # Errors
    ///
    /// This can return an error if the value is outside of the range that can be represented as a vint.
    ///
    fn as_signed_vint_with_length(&self, length: usize) -> Result<Vec<u8>, ToolError> {
        let val: i64 = (*self).into();
        check_size_i64(val, length)?;
        Ok(as_vint_no_check_i64(val, length))
    }
}

impl SignedVint for i64 {}
impl SignedVint for i32 {}
impl SignedVint for i16 {}
impl SignedVint for i8 {}

#[inline]
fn check_size_i64(val: i64, max_length: usize) -> Result<(), ToolError> {
    if val <= -(1 << (max_length * 7 - 1)) || val >= (1 << (max_length * 7 - 1)) {
        Err(ToolError::WriteSignedVintOverflow(val))
    } else {
        Ok(())
    }
}

#[inline]
fn as_vint_no_check_i64(val: i64, length: usize) -> Vec<u8> {
    let bytes: [u8; 8] = val.to_be_bytes();
    let mut result: Vec<u8> = Vec::from(&bytes[(8 - length)..]);
    if val < 0 {
        result[0] &= 0xFF >> (length - 1);
    } else {
        result[0] |= 1 << (8 - length);
    }
    result
}

///
/// Reads a signed vint from the beginning of the input array slice.
///
/// This method returns an option with the `None` variant used to indicate there was not enough data in the buffer to completely read a vint.
///
/// The returned tuple contains the value of the vint (`i64`) and the length of the vint (`usize`).  The length will be less than or equal to the length of the input slice.
///
/// # Errors
///
/// This method can return a `ToolError` if the input array cannot be read as a vint.
///
pub fn read_signed_vint(buffer: &[u8]) -> Result<Option<(i64, usize)>, ToolError> {
    if buffer.is_empty() {
        return Ok(None);
    }

    if buffer[0] == 0 {
        return Err(ToolError::ReadVintOverflow);
    }

    let length = 8 - buffer[0].ilog2() as usize;

    if length > buffer.len() {
        // Not enough data in the buffer to read out the vint value
        return Ok(None);
    }

    let is_negative = if length == 8 {
        buffer[1] & 0x80
    } else {
        buffer[0] & (0x80 >> length)
    } > 0;

    let mut value = if is_negative {
        (buffer[0] as i64) | (!0i64 << (8 - length))
    } else {
        (buffer[0] & (0xFF >> length)) as i64
    };

    for item in buffer.iter().take(length).skip(1) {
        value <<= 8;
        value += *item as i64;
    }

    Ok(Some((value, length)))
}

///
/// Reads a `u64` value from any length array slice.
///
/// Rather than forcing the input to be a `[u8; 8]` like standard library methods, this can interpret a `u64` from a slice of any length < 8.  Bytes are assumed to be least significant when reading the value - i.e. an array of `[4, 0]` would return a value of `1024`.
///
/// # Errors
///
/// This method will return an error if the input slice has a length > 8.
///
/// ## Example
///
/// ```
/// # use ebml_iterable::tools::arr_to_u64;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let result = arr_to_u64(&[16,0])?;
/// assert_eq!(result, 4096);
/// # Ok(())
/// # }
/// ```
///
pub fn arr_to_u64(arr: &[u8]) -> Result<u64, ToolError> {
    if arr.len() > 8 {
        return Err(ToolError::ReadU64Overflow(Vec::from(arr)));
    }

    let mut val = 0u64;
    for byte in arr {
        val *= 256;
        val += *byte as u64;
    }
    Ok(val)
}

///
/// Reads an `i64` value from any length array slice.
///
/// Rather than forcing the input to be a `[u8; 8]` like standard library methods, this can interpret an `i64` from a slice of any length < 8.  Bytes are assumed to be least significant when reading the value - i.e. an array of `[4, 0]` would return a value of `1024`.
///
/// # Errors
///
/// This method will return an error if the input slice has a length > 8.
///
/// ## Example
///
/// ```
/// # use ebml_iterable::tools::arr_to_i64;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let result = arr_to_i64(&[4,0])?;
/// assert_eq!(result, 1024);
/// # Ok(())
/// # }
/// ```
///
pub fn arr_to_i64(arr: &[u8]) -> Result<i64, ToolError> {
    if arr.len() > 8 {
        return Err(ToolError::ReadI64Overflow(Vec::from(arr)));
    }

    if arr[0] > 127 {
        if arr.len() == 8 {
            Ok(i64::from_be_bytes(
                arr.try_into().expect("[u8;8] should be convertible to i64"),
            ))
        } else {
            Ok(-((1 << (arr.len() * 8))
                - (arr_to_u64(arr).expect("arr_to_u64 shouldn't error if length is <= 8") as i64)))
        }
    } else {
        Ok(arr_to_u64(arr).expect("arr_to_u64 shouldn't error if length is <= 8") as i64)
    }
}

///
/// Reads an `f64` value from an array slice of length 4 or 8.
///
/// This method wraps `f32` and `f64` conversions from big endian byte arrays and casts the result as an `f64`.
///
/// # Errors
///
/// This method will throw an error if the input slice length is not 4 or 8.
///
pub fn arr_to_f64(arr: &[u8]) -> Result<f64, ToolError> {
    if arr.len() == 4 {
        Ok(f32::from_be_bytes(arr.try_into().expect("arr should be [u8;4]")) as f64)
    } else if arr.len() == 8 {
        Ok(f64::from_be_bytes(arr.try_into().expect("arr should be [u8;8]")))
    } else {
        Err(ToolError::ReadF64Mismatch(Vec::from(arr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_vint_sixteen() {
        let buffer = [144];
        let result = read_vint(&buffer).unwrap().expect("Reading vint failed");

        assert_eq!(16, result.0);
        assert_eq!(1, result.1);
    }

    #[test]
    fn write_vint_sixteen() {
        let result = 16u64.as_vint().expect("Writing vint failed");
        assert_eq!(vec![144u8], result);
    }

    #[test]
    fn read_vint_one_twenty_seven() {
        let buffer = [255u8];
        let result = read_vint(&buffer).unwrap().expect("Reading vint failed");

        assert_eq!(127, result.0);
        assert_eq!(1, result.1);
    }

    #[test]
    fn write_vint_one_twenty_seven() {
        let result = 127u64.as_vint().expect("Writing vint failed");
        assert_eq!(vec![255u8], result);
    }

    #[test]
    fn read_vint_two_hundred() {
        let buffer = [64, 200];
        let result = read_vint(&buffer).unwrap().expect("Reading vint failed");

        assert_eq!(200, result.0);
        assert_eq!(2, result.1);
    }

    #[test]
    fn write_vint_two_hundred() {
        let result = 200u64.as_vint().expect("Writing vint failed");
        assert_eq!(vec![64u8, 200u8], result);
    }

    #[test]
    fn read_vint_for_ebml_tag() {
        let buffer = [0x1a, 0x45, 0xdf, 0xa3];
        let result = read_vint(&buffer).unwrap().expect("Reading vint failed");

        assert_eq!(0x0a45dfa3, result.0);
        assert_eq!(4, result.1);
    }

    #[test]
    fn read_vint_very_long() {
        let buffer = [1, 0, 0, 0, 0, 0, 0, 1];
        let result = read_vint(&buffer).unwrap().expect("Reading vint failed");

        assert_eq!(1, result.0);
        assert_eq!(8, result.1);
    }

    #[test]
    fn write_vint_very_long() {
        let result = 1u64.as_vint_with_length::<8>().expect("Writing vint failed");
        assert_eq!(vec![1, 0, 0, 0, 0, 0, 0, 1], result);
    }

    #[test]
    fn read_vint_overflow() {
        let buffer = [1, 0, 0, 0];
        let result = read_vint(&buffer).expect("Reading vint failed");

        assert_eq!(true, result.is_none());
    }

    #[test]
    #[should_panic]
    fn too_big_for_vint() {
        (1u64 << 56).as_vint().expect("Writing vint failed");
    }

    #[test]
    fn vint_encode_decode_range() {
        for val in 0..500_000 {
            let bytes = val.as_vint().unwrap();
            let result = read_vint(bytes.as_slice()).unwrap().unwrap().0;
            assert_eq!(val, result);
        }
    }

    #[test]
    fn signed_vint_encode_decode_range() {
        for val in -500_000..500_000 {
            let bytes = val.as_signed_vint().unwrap();
            let result = read_signed_vint(bytes.as_slice()).unwrap().unwrap().0;
            assert_eq!(val, result);
        }
    }

    #[test]
    fn read_u64_values() {
        let mut buffer = vec![];
        let mut expected = 0;
        for _ in 0..8 {
            buffer.push(0x25);
            expected = (expected << 8) + 0x25;

            let result = arr_to_u64(&buffer).unwrap();
            assert_eq!(expected, result);
        }
    }

    #[test]
    fn read_i64_values() {
        let mut buffer = vec![];
        let mut expected = 0;
        for _ in 0..8 {
            buffer.push(0x0a);
            expected = (expected << 8) + 0x0a;

            let result = arr_to_i64(&buffer).unwrap();
            assert_eq!(expected, result);

            let neg_result = arr_to_i64(&(buffer.iter().map(|b| !b).collect::<Vec<u8>>())).unwrap() + 1;
            assert_eq!(-expected, neg_result);
        }
    }

    #[test]
    fn valid_vints() {
        assert!(is_vint(0x1F43B675));
        assert!(is_vint(0xA0));
        assert!(is_vint(0xA1));
        assert!(is_vint(0x75A1));
        assert!(is_vint(0xA6));
        assert!(is_vint(0xEE));
        assert!(is_vint(0xA5));
        assert!(is_vint(0x9B));
        assert!(is_vint(0xA2));
        assert!(is_vint(0xA4));
        assert!(is_vint(0x75A2));
        assert!(is_vint(0xFB));
        assert!(is_vint(0xC8));
        assert!(is_vint(0xC9));
        assert!(is_vint(0xCA));
        assert!(is_vint(0xFA));
        assert!(is_vint(0xFD));
        assert!(is_vint(0x8E));
        assert!(is_vint(0xE8));
        assert!(is_vint(0xCB));
        assert!(is_vint(0xCE));
        assert!(is_vint(0xCD));
        assert!(is_vint(0xCC));
        assert!(is_vint(0xCF));
        assert!(is_vint(0xAF));
        assert!(is_vint(0xA7));
        assert!(is_vint(0xAB));
        assert!(is_vint(0x5854));
        assert!(is_vint(0x58D7));
        assert!(is_vint(0xA3));
        assert!(is_vint(0xE7));
        assert!(is_vint(0x3E83BB));
        assert!(is_vint(0x3EB923));
        assert!(is_vint(0x3C83AB));
        assert!(is_vint(0x3CB923));

        assert!(!is_vint(1234));
        assert!(!is_vint(0x11));
        assert!(!is_vint(0x7a));
        assert!(!is_vint(0xfa4c));
        assert!(!is_vint(0x1a5d));
    }
}
