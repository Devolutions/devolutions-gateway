extern crate proc_macro;

mod ast;
mod attr;
mod easy_ebml;
mod pathing;

use proc_macro::TokenStream;
use syn::{Error, ItemEnum};

use crate::easy_ebml::EasyEBML;

///
/// Attribute that derives implementations of [`EbmlSpecification`][spec] and [`EbmlTag`][tag] for an enum.
///
/// This macro is intended to make implementing the traits in ebml-iterable-specification easier to manage.  Rather than requiring handwritten implementations for [`EbmlSpecification`][spec] and [`EbmlTag`][tag] methods, this macro understands attributes assigned to enum members and generates an implementation accordingly.
///
/// When deriving `EbmlSpecification` for an enum, the following attributes are required for each variant:
///   * __#[id(`u64`)]__ - This attribute specifies the "id" of the tag. e.g. `0x1a45dfa3`
///   * __#[data_type(`TagDataType`)]__ - This attribute specifies the type of data contained in the tag. e.g. `TagDataType::UnsignedInt`
///
/// The following attribute is optional for each variant:
///   * __#[doc_path(Path/To/Element)]__ - This attribute specifies the document path of the current element.  If this attribute is not present, the variant is treated as a Root element.  Global elements can be defined with wildcard paths, e.g. #[doc_path(Segment/(1-)/)].
///
/// # Note
///
/// This attribute modifies the variants in the enumeration by adding fields to them.  It also will add the following variants to the enum:
/// - `Crc32(Vec<u8>)` - global tag defined in the EBML spec
/// - `Void(Vec<u8>)` - global tag defined in the EBML spec
/// - `RawTag(u64, Vec<u8>)` - used to support reading "unknown" tags that aren't in the spec
///
/// [spec]: ebml_iterable_specification::EbmlSpecification
/// [tag]: ebml_iterable_specification::EbmlTag

#[proc_macro_attribute]
pub fn ebml_specification(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut input = match syn::parse::<ItemEnum>(input) {
        Ok(syntax_tree) => syntax_tree,
        Err(err) => {
            return TokenStream::from(
                Error::new(
                    err.span(),
                    "#[ebml_specification] attribute can only be applied to enums",
                )
                .to_compile_error(),
            )
        }
    };

    attr::impl_ebml_specification(&mut input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

///
/// Macro that makes writing an EBML spec easy.
///
/// This provides an even easier alternative to create implementations of the [`EbmlSpecification`][spec] and [`EbmlTag`][tag] traits than using the [`[#ebml_specification]`][macro] attribute.  As a bonus, your spec will be more legible and maintainable!
///
/// As an example, compare the following equivalent definitions:
/// ```
/// # use ebml_iterable_specification_derive::ebml_specification;
/// # use ebml_iterable_specification::TagDataType::{Master, UnsignedInt};
/// # pub mod ebml_iterable { pub mod specs {
/// #    pub use ebml_iterable_specification_derive::ebml_specification as ebml_specification;
/// #    pub use ebml_iterable_specification::EbmlSpecification as EbmlSpecification;
/// #    pub use ebml_iterable_specification::EbmlTag as EbmlTag;
/// #    pub use ebml_iterable_specification::TagDataType as TagDataType;
/// #    pub use ebml_iterable_specification::Master as Master;
/// #    pub use ebml_iterable_specification::PathPart as PathPart;
/// # }}
/// #[ebml_specification]
/// #[derive(Clone)]
/// enum Example {
///   #[id(0x01)]
///   #[data_type(Master)]
///   Root,
///
///   #[id(0x02)]
///   #[data_type(Master)]
///   #[doc_path(Root)]
///   Parent,
///
///   #[id(0x100)]
///   #[data_type(UnsignedInt)]
///   #[doc_path(Root/Parent)]
///   Data,
/// }
/// ```
/// vs
/// ```
/// # use ebml_iterable_specification_derive::easy_ebml;
/// # use ebml_iterable_specification::TagDataType;
/// # use ebml_iterable_specification::TagDataType::{Master, UnsignedInt};
/// # pub mod ebml_iterable { pub mod specs {
/// #    pub use ebml_iterable_specification_derive::ebml_specification as ebml_specification;
/// #    pub use ebml_iterable_specification::EbmlSpecification as EbmlSpecification;
/// #    pub use ebml_iterable_specification::EbmlTag as EbmlTag;
/// #    pub use ebml_iterable_specification::TagDataType as TagDataType;
/// #    pub use ebml_iterable_specification::Master as Master;
/// #    pub use ebml_iterable_specification::PathPart as PathPart;
/// # }}
/// easy_ebml! {
///   #[derive(Clone)]
///   enum Example {
///     Root                : Master = 0x01,
///     Root/Parent         : Master = 0x02,
///     Root/Parent/Data    : UnsignedInt = 0x100,
///   }
/// }
/// ```
///
/// Behind the scenes `easy_ebml!` still uses the existing [`[#ebml_specification]`][macro] attribute macro, so the final output of this macro will remain identical.
///
/// [spec]: ebml_iterable_specification::EbmlSpecification
/// [tag]: ebml_iterable_specification::EbmlTag
/// [macro]: macro@crate::ebml_specification

#[proc_macro]
pub fn easy_ebml(input: TokenStream) -> TokenStream {
    let input = match syn::parse::<EasyEBML>(input) {
        Ok(syntax_tree) => syntax_tree,
        Err(err) => {
            return TokenStream::from(
                Error::new(
                    err.span(),
                    "easy_ebml! {} content must be of format: enum Name {\
                Root: Type = id,\
                Path/Of/Component: Type = id,\
                // example\
                Ebml: Master = 0x1a45dfa3,\
                Ebml/EbmlVersion: UnsignedInt = 0x4286,\
                // global elements can be used in paths, example:\
                (1-)/Crc32: Binary = 0xbf,\
            }",
                )
                .to_compile_error(),
            )
        }
    };

    input.implement().unwrap_or_else(|err| err.to_compile_error()).into()
}
