[EBML][EBML] stands for Extensible Binary Meta-Language and is somewhat of a
binary version of XML. It's used for container formats like [WebM][webm] or
[MKV][mkv].

# Devolutions fork

Devolutions Gateway vendors this crate from Austin Blake's [`ebml-iterable`](https://github.com/austinleroy/ebml-iterable) commit `25303fa5a9107d8d28fa8458b0b982946c319135`.
The original work and this fork use the MIT license in [`LICENSE`](LICENSE).
This fork adds `TagDecoder`, which keeps incomplete EBML elements pending while a recording grows.

> IMPORTANT: The iterator contained in this crate is spec-agnostic and requires a specification implementing the `EbmlSpecification` and `EbmlTag` traits to read files.  Typically, you would only use this crate to implement a custom specification - most often you would prefer a crate providing an existing specification, like [webm-iterable][webm-iterable].

```Cargo.toml
[dependencies]
ebml-iterable = "0.6.3"
```

# Usage

The `TagIterator` struct implements Rust's standard [Iterator][rust-iterator] trait.
This struct can be created with the `new` function on any source that implements the standard [Read][rust-read] trait. The iterator outputs `TSpec` objects based on the defined specification and the tag data.

> Note: The `with_capacity` method can be used to construct a `TagIterator` with a specified default buffer size.  This is only useful as a microoptimization to memory management if you know the maximum tag size of the file you're reading.

The data in the tag can then be modified as desired (encryption, compression, etc.) and reencoded using the `TagWriter` struct. This struct can be created with the `new` function on any source that implements the standard [Write][rust-write] trait. Once created, this struct can encode EBML using the `write` method on any objects that implement `EbmlSpecification` and `EbmlTag` regardless of whether they came from a `TagIterator`.  This will emit binary EBML to the underlying `Write` destination.

## Master Enum

Most tag types contain their data directly, but there is a category of tag in EBML called `Master` which contains other tags. This crate contains an enumeration of three different classifications of master tags:

  * `Start` is a marker for the beginning of a "master" tag.
  * `End` is a marker for the end of a "master" tag.
  * `Full(children)` is a complete tag that includes all child tags of the `Master` tag.  This is only emitted by the `TagIterator` for tag types passed in via `tags_to_buffer`.

## TagDataType

```rs
pub enum TagDataType {
    Master,
    UnsignedInt,
    Integer,
    Utf8,
    Binary,
    Float,
}
```

TagDataType is an enum containing the possible data types stored within a tag.  The relationship between the tag variant and the type of data contained in the tag directly corresponds is defined by whichever specification is in use.  Because EBML is binary, the correct specification is required to parse tag content.  

  * Master: A complete master tag containing any number of child tags.
  * UnsignedInt: An unsigned integer.
  * Integer: A signed integer.
  * Utf8: A Unicode text string.  Note that the [EBML spec][rfc8794] includes a separate element type for ASCII.  Given that ASCII is a subset of Utf8, this library currently parses and encodes both types using the same Utf8 logic.
  * Binary: Binary data, otherwise uninterpreted.
  * Float: IEEE-754 floating point number.

> Note: This library made a conscious decision to not parse "Date" elements from EBML due to lack of built-in support for dates in Rust. Specification implementations should treat Date elements as Binary so that consumers have the option of parsing the unaltered data using their library of choice, if needed.

# Specification Implementation

Any specification based on EBML can use this library to parse or write binary data.  Writing needs nothing special (if you use the `write_raw()` method), but parsing requires a struct implementing the `EbmlSpecification` and `EbmlTag` traits.  These traits currently have a large number of methods to implement and need consistent implementations to avoid errors, so any implementation attempt is recommended to use the `"derive-spec"` feature flag in this crate and using the provided macro.  Custom specification implementations can refer to [webm-iterable][webm-iterable] as an example.

# Features
 
There is currently only one optional feature in this crate, but that may change over time as needs arise.
 
* **derive-spec** -
    When enabled, this provides a macro to simplify implementations of the `EbmlSpecification` and `EbmlTag` traits.  This introduces dependencies on [`syn`](https://crates.io/crates/syn), [`quote`](https://crates.io/crates/quote), and [`proc-macro2`](https://crates.io/crates/proc-macro2), so expect compile times to increase a little.


# State of this project

Parsing and writing complete files should both work.  Streaming (using tags of unknown size) should now also be supported, as of version 0.4.0. If something is broken, please create [an issue][new-issue].

Any additional feature requests can also be submitted as [an issue][new-issue].

# Author

[Austin Blake](https://github.com/austinleroy)

[EBML]: http://ebml.sourceforge.net/
[webm]: https://www.webmproject.org/
[mkv]: http://www.matroska.org/technical/specs/index.html
[rfc8794]: https://datatracker.ietf.org/doc/rfc8794/
[rust-iterator]: https://doc.rust-lang.org/std/iter/trait.Iterator.html
[rust-read]: https://doc.rust-lang.org/std/io/trait.Read.html
[rust-write]: https://doc.rust-lang.org/std/io/trait.Write.html
[new-issue]: https://github.com/austinleroy/ebml-iterable/issues
[webm-iterable]: https://github.com/austinleroy/webm-iterable
