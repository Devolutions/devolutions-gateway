use std::collections::HashMap;
use std::str::FromStr;

use ebml_iterable_specification::TagDataType;
use ebml_iterable_specification::TagDataType::Master;
use proc_macro2::TokenStream;
use quote::{quote, quote_spanned, ToTokens};
use syn::spanned::Spanned;
use syn::{Attribute, Error, Fields, FieldsUnnamed, Ident, ItemEnum, Path, Result, Variant, Visibility};

use super::ast::Enum;
use super::pathing::PathPart;

pub fn impl_ebml_specification(original: &mut ItemEnum) -> Result<TokenStream> {
    let tag_data_type = spanned_tag_data_type(original);
    original.variants.push(syn::parse2::<Variant>(quote! {
        #[id(0xbf)]
        #[data_type(#tag_data_type::Binary)]
        #[doc_path((1-))]
        Crc32
    })?);
    original.variants.push(syn::parse2::<Variant>(quote! {
        #[id(0xec)]
        #[data_type(#tag_data_type::Binary)]
        #[doc_path((-))]
        Void
    })?);

    let input = Enum::from_syn(original)?;

    let mut used_ids = HashMap::<u64, &Variant>::new();
    for var in &input.variants {
        if let Some(original) = used_ids.insert(var.id_attr.0, var.original) {
            let mut err = Error::new_spanned(
                var.original,
                format!("duplicate {} detected", var.id_attr.1.original.to_token_stream()),
            );
            err.combine(Error::new_spanned(
                original,
                format!("{} already used previously", var.id_attr.1.original.to_token_stream()),
            ));
            return Err(err);
        }
    }

    let map: HashMap<_, _> = input.variants.iter().map(|var| (&var.ident, var)).collect();
    for origin in &input.variants {
        if !matches!(origin.data_type_attr.0, TagDataType::Master) && origin.path_attr.is_some() {
            validate_path(origin, &map)?;
        }
    }

    let ebml_specification_impl = get_impl(input)?;
    let modified_orig = modify_orig(original)?;

    Ok(quote!(
        #modified_orig

        #ebml_specification_impl
    ))
}

// verify all parents are Master type elements and their path lines up with this item's path
fn validate_path(origin: &crate::ast::Variant, variants_map: &HashMap<&Ident, &crate::ast::Variant>) -> Result<()> {
    // Only validate the element if it has a path attribute
    if let Some(path_parts) = origin.path_attr.as_ref().map(|(path, _)| &path.parts) {
        // Only validate if there is a specific parent element
        if let Some(parent) = path_parts
            .iter()
            .rev()
            .filter_map(|p| {
                if let PathPart::Ident(ident) = p {
                    Some(ident)
                } else {
                    None
                }
            })
            .next()
        {
            let parent = *variants_map.get(parent).unwrap();
            if parent.data_type_attr.0 != Master {
                return Err(Error::new_spanned(parent.original, "Parents must be of Master type"));
            }

            if let Some((parent_path, _)) = parent.path_attr.as_ref() {
                for i in 0..parent_path.parts.len() {
                    if parent_path.parts[i] != path_parts[i] {
                        return Err(Error::new_spanned(
                            origin.original,
                            format!(
                                "Path segment [{}] did not align with parent [{}] path.",
                                path_parts[i], parent.ident
                            ),
                        ));
                    }
                }
                validate_path(parent, variants_map)?;
            }
        }
    }

    Ok(())
}

fn modify_orig(original: &mut ItemEnum) -> Result<TokenStream> {
    let spanned_master_enum = spanned_master_enum(original);
    for var in original.variants.iter_mut() {
        let data_type_attribute: &Attribute = var
            .attrs
            .iter()
            .find(|a| a.path.is_ident("data_type"))
            .expect("#[data_type()] attribute required for variants under #[ebml_specification]");

        let data_type_path = data_type_attribute.parse_args::<Path>().map_err(|err| {
            Error::new(
                err.span(),
                format!(
                    "{} requires `ebml_iterable::TagDataType`",
                    data_type_attribute.to_token_stream()
                ),
            )
        })?;
        let data_type = get_last_path_ident(&data_type_path).ok_or_else(|| {
            Error::new_spanned(
                data_type_attribute.clone(),
                format!(
                    "{} requires `ebml_iterable::TagDataType`",
                    data_type_attribute.to_token_stream()
                ),
            )
        })?;

        let data_type = if data_type == "Master" {
            let orig_ident = &original.ident;
            quote!( (#spanned_master_enum<#orig_ident>) )
        } else if data_type == "UnsignedInt" {
            quote!((u64))
        } else if data_type == "Integer" {
            quote!((i64))
        } else if data_type == "Utf8" {
            quote!((String))
        } else if data_type == "Binary" {
            quote!((::std::vec::Vec<u8>))
        } else if data_type == "Float" {
            quote!((f64))
        } else {
            return Err(Error::new_spanned(
                data_type_attribute.clone(),
                format!("unknown data_type \"{data_type}\""),
            ));
        };

        var.attrs
            .retain(|a| !(a.path.is_ident("id") || a.path.is_ident("data_type") || a.path.is_ident("doc_path")));
        var.fields = Fields::Unnamed(syn::parse2::<FieldsUnnamed>(data_type)?);
    }
    original
        .variants
        .push(syn::parse_str::<Variant>("RawTag(u64, ::std::vec::Vec<u8>)")?);

    Ok(quote!(#original))
}

fn get_impl(input: Enum) -> Result<TokenStream> {
    let ty = &input.ident;
    let spanned_master_enum = spanned_master_enum(input.original);

    let get_tag_data_type = input.variants.iter().map(|var: &crate::ast::Variant| {
        let id = &var.id_attr.0;
        let data_type = &var.data_type_attr.1;

        quote_spanned! { var.data_type_attr.2.original.span() =>
            #id => Some(#data_type),
        }
    });

    let get_id = input.variants.iter().map(|var: &crate::ast::Variant| {
        let name = &var.ident;
        let id = &var.id_attr.0;

        quote_spanned! { var.id_attr.1.original.span() =>
            #ty::#name(_) => #id,
        }
    });

    let get_tag = |ret_val: String| {
        move |var: &crate::ast::Variant| {
            let name = &var.ident;
            let id = &var.id_attr.0;
            let ret_val = TokenStream::from_str(&ret_val)
                .expect("Misuse of get_tag function in ebml_iterable_specification_derive_attr");

            quote_spanned! { var.original.span() =>
                #id => Some(#ty::#name(#ret_val)),
            }
        }
    };

    let path_part = spanned_path_part(input.original);
    let variant_map: HashMap<_, _> = input.variants.iter().map(|var| (&var.ident, var)).collect();
    let get_path_by_id = input.variants.iter().filter_map(|v| match v.path_attr.as_ref() {
        None => None,
        Some(path) => {
            let id = &v.id_attr.0;
            let path_array: Vec<TokenStream> = path
                .0
                .parts
                .iter()
                .map(|p| match p {
                    PathPart::Ident(ident) => {
                        let id = variant_map.get(&ident).map(|v| v.id_attr.0).unwrap();
                        quote_spanned! { path.1.original.span() => #path_part::Id(#id) }
                    }
                    PathPart::Global((min, max)) => {
                        let min_tokens = if let Some(min) = min {
                            quote! {Some(#min)}
                        } else {
                            quote! {None}
                        };
                        let max_tokens = if let Some(max) = max {
                            quote! {Some(#max)}
                        } else {
                            quote! {None}
                        };
                        quote_spanned! { path.1.original.span() => #path_part::Global((#min_tokens, #max_tokens)) }
                    }
                })
                .collect();
            Some(quote_spanned! { v.original.span() =>
                #id => &[#(#path_array),*],
            })
        }
    });

    let get_unsigned_int_tag = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::UnsignedInt))
        .map(get_tag(String::from("data")));

    let get_signed_int_tag = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::Integer))
        .map(get_tag(String::from("data")));

    let get_utf8_tag = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::Utf8))
        .map(get_tag(String::from("data")));

    let get_binary_tag = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::Binary))
        .map(get_tag(String::from("data.to_vec()")));

    let get_float_tag = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::Float))
        .map(get_tag(String::from("data")));

    let get_master_tag = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::Master))
        .map(get_tag(String::from("data")));

    let as_data = |var: &crate::ast::Variant| {
        let name = &var.ident;

        quote! {
            #ty::#name(val) => Some(val),
        }
    };

    let as_unsigned_int = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::UnsignedInt))
        .map(as_data);

    let as_signed_int = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::Integer))
        .map(as_data);

    let as_utf8 = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::Utf8))
        .map(as_data);

    let as_binary = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::Binary))
        .map(as_data);

    let as_float = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::Float))
        .map(as_data);

    let as_master = input
        .variants
        .iter()
        .filter(|v| matches!(&v.data_type_attr.0, TagDataType::Master))
        .map(as_data);

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let ebml_spec_trait = spanned_ebml_specification_trait(input.original);
    let ebml_tag_trait = spanned_ebml_tag_trait(input.original);
    let tag_data_type = spanned_tag_data_type(input.original);

    Ok(quote! {
        impl #impl_generics #ebml_spec_trait <#ty> for #ty #ty_generics #where_clause {
            fn get_tag_data_type(id: u64) -> Option<#tag_data_type> {
                match id {
                    #(#get_tag_data_type)*
                    _ => None
                }
            }

            fn get_path_by_id(id: u64) -> &'static [#path_part] {
                match id {
                    #(#get_path_by_id)*
                    _ => &[]
                }
            }

            fn get_unsigned_int_tag(id: u64, data: u64) -> Option<#ty> {
                match id {
                    #(#get_unsigned_int_tag)*
                    _ => None
                }
            }

            fn get_signed_int_tag(id: u64, data: i64) -> Option<#ty> {
                match id {
                    #(#get_signed_int_tag)*
                    _ => None
                }
            }

            fn get_utf8_tag(id: u64, data: String) -> Option<#ty> {
                match id {
                    #(#get_utf8_tag)*
                    _ => None
                }
            }

            fn get_binary_tag(id: u64, data: &[u8]) -> Option<#ty> {
                match id {
                    #(#get_binary_tag)*
                    _ => None
                }
            }

            fn get_float_tag(id: u64, data: f64) -> Option<#ty> {
                match id {
                    #(#get_float_tag)*
                    _ => None
                }
            }

            fn get_master_tag(id: u64, data: #spanned_master_enum<#ty>) -> Option<#ty> {
                match id {
                    #(#get_master_tag)*
                    _ => None
                }
            }

            fn get_raw_tag(id: u64, data: &[u8]) -> #ty {
                #ty::RawTag(id, data.to_vec())
            }
        }

        impl #impl_generics #ebml_tag_trait <#ty> for #ty #ty_generics #where_clause {

            fn get_id(&self) -> u64 {
                match self {
                    #(#get_id)*
                    #ty::RawTag(id, _data) => *id,
                }
            }

            fn as_unsigned_int(&self) -> Option<&u64> {
                match self {
                    #(#as_unsigned_int)*
                    _ => None,
                }
            }

            fn as_signed_int(&self) -> Option<&i64> {
                match self {
                    #(#as_signed_int)*
                    _ => None,
                }
            }

            fn as_utf8(&self) -> Option<&str> {
                match self {
                    #(#as_utf8)*
                    _ => None,
                }
            }

            fn as_binary(&self) -> Option<&[u8]> {
                match self {
                    #(#as_binary)*
                    #ty::RawTag(_id, data) => Some(data),
                    _ => None,
                }
            }

            fn as_float(&self) -> Option<&f64> {
                match self {
                    #(#as_float)*
                    _ => None,
                }
            }

            fn as_master(&self) -> Option<&#spanned_master_enum<#ty>> {
                match self {
                    #(#as_master)*
                    _ => None,
                }
            }
        }
    })
}

fn spanned_ebml_iterable_specs(input: &ItemEnum) -> TokenStream {
    let vis_span = match &input.vis {
        Visibility::Public(vis) => Some(vis.pub_token.span()),
        Visibility::Crate(vis) => Some(vis.crate_token.span()),
        Visibility::Restricted(vis) => Some(vis.pub_token.span()),
        Visibility::Inherited => None,
    };
    let data_span = input.enum_token.span();
    let first_span = vis_span.unwrap_or(data_span);
    quote_spanned!(first_span=> ebml_iterable::specs::)
}

fn spanned_master_enum(input: &ItemEnum) -> TokenStream {
    let path = spanned_ebml_iterable_specs(input);
    let last_span = input.ident.span();
    let r#enum = quote_spanned!(last_span=> Master);
    quote!(#path #r#enum)
}

fn spanned_ebml_specification_trait(input: &ItemEnum) -> TokenStream {
    let path = spanned_ebml_iterable_specs(input);
    let last_span = input.ident.span();
    let spec = quote_spanned!(last_span=> EbmlSpecification);
    quote!(#path #spec)
}

fn spanned_ebml_tag_trait(input: &ItemEnum) -> TokenStream {
    let path = spanned_ebml_iterable_specs(input);
    let last_span = input.ident.span();
    let spec = quote_spanned!(last_span=> EbmlTag);
    quote!(#path #spec)
}

fn spanned_tag_data_type(input: &ItemEnum) -> TokenStream {
    let path = spanned_ebml_iterable_specs(input);
    let last_span = input.ident.span();
    let r#type = quote_spanned!(last_span=> TagDataType);
    quote!(#path #r#type)
}

fn spanned_path_part(input: &ItemEnum) -> TokenStream {
    let path = spanned_ebml_iterable_specs(input);
    let last_span = input.ident.span();
    let r#type = quote_spanned!(last_span=> PathPart);
    quote!(#path #r#type)
}

fn get_last_path_ident(path: &Path) -> Option<&Ident> {
    let seg = path.segments.iter().last();
    seg.map(|seg| &seg.ident)
}
