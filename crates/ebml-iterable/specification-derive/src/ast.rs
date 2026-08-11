use std::collections::HashSet;

use ebml_iterable_specification::TagDataType;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::{Error, Generics, Ident, ItemEnum, LitInt, Path, Result};

use crate::pathing::{EBMLPath, PathPart};

pub struct Enum<'a> {
    pub original: &'a ItemEnum,
    pub ident: Ident,
    pub variants: Vec<Variant<'a>>,
    pub generics: &'a Generics,
}

pub struct Variant<'a> {
    pub original: &'a syn::Variant,
    pub ident: Ident,
    pub id_attr: (u64, Attribute<'a>),
    pub data_type_attr: (TagDataType, Path, Attribute<'a>),
    pub path_attr: Option<(EBMLPath, Attribute<'a>)>,
}

pub struct Attribute<'a> {
    pub original: &'a syn::Attribute,
}

impl<'a> Enum<'a> {
    pub fn from_syn(node: &'a ItemEnum) -> Result<Self> {
        let variant_names: HashSet<_> = node.variants.iter().map(|var| var.ident.clone()).collect();
        let variants = node
            .variants
            .iter()
            .map(|node| Variant::from_syn(node, &variant_names))
            .collect::<Result<_>>()?;

        Ok(Enum {
            original: node,
            ident: node.ident.clone(),
            variants,
            generics: &node.generics,
        })
    }
}

impl<'a> Variant<'a> {
    fn from_syn(node: &'a syn::Variant, variant_names: &HashSet<Ident>) -> Result<Self> {
        let mut id_attr: Option<(u64, Attribute<'a>)> = None;
        let mut data_type_attr: Option<(TagDataType, Path, Attribute<'a>)> = None;
        let mut path_attr: Option<(EBMLPath, Attribute<'a>)> = None;

        for attr in &node.attrs {
            if attr.path.is_ident("id") {
                if id_attr.is_some() {
                    return Err(Error::new_spanned(
                        node,
                        format!("duplicate {} attribute", attr.to_token_stream()),
                    ));
                }
                let val = attr.parse_args::<LitInt>()?.base10_parse::<u64>()?;
                id_attr = Some((val, Attribute { original: attr }));
            } else if attr.path.is_ident("data_type") {
                if data_type_attr.is_some() {
                    return Err(Error::new_spanned(
                        node,
                        format!("duplicate {} attribute", attr.to_token_stream()),
                    ));
                }

                let val = attr.parse_args::<syn::Path>().map_err(|err| {
                    Error::new(
                        err.span(),
                        format!("{} requires `ebml_iterable::TagDataType`", attr.to_token_stream()),
                    )
                })?;
                let data_type_name = val.segments.iter().last();
                if data_type_name.is_none() {
                    return Err(Error::new_spanned(
                        val,
                        format!("{} requires `ebml_iterable::TagDataType`", attr.to_token_stream()),
                    ));
                }
                let data_type_name = data_type_name.unwrap().ident.to_string();
                let data_type_val = if data_type_name == "UnsignedInt" {
                    TagDataType::UnsignedInt
                } else if data_type_name == "Integer" {
                    TagDataType::Integer
                } else if data_type_name == "Utf8" {
                    TagDataType::Utf8
                } else if data_type_name == "Binary" {
                    TagDataType::Binary
                } else if data_type_name == "Float" {
                    TagDataType::Float
                } else if data_type_name == "Master" {
                    TagDataType::Master
                } else {
                    return Err(Error::new_spanned(
                        val,
                        format!("unrecognized `ebml_iterable::TagDataType` value: {data_type_name}"),
                    ));
                };
                data_type_attr = Some((data_type_val, val, Attribute { original: attr }));
            } else if attr.path.is_ident("doc_path") {
                if path_attr.is_some() {
                    return Err(Error::new_spanned(
                        node,
                        format!("duplicate {} attribute", attr.to_token_stream()),
                    ));
                }
                let path = attr.parse_args::<EBMLPath>().map_err(|err| {
                    Error::new(err.span(), format!("{} must be a path string", attr.to_token_stream()))
                })?;
                let mut last_was_global = false;
                for path_part in &path.parts {
                    match path_part {
                        PathPart::Ident(id) => {
                            last_was_global = false;
                            variant_names
                                .get(id)
                                .ok_or(Error::new(id.span(), format!("Unknown variant [{id}] in path")))?;
                        }
                        PathPart::Global((_, max)) => {
                            if matches!(max, Some(0)) {
                                return Err(Error::new(attr.span(), "Global maximum cannot be 0".to_string()));
                            }
                            if last_was_global {
                                return Err(Error::new(
                                    attr.span(),
                                    "Cannot use GlobalPlaceholders back-to-back in path".to_string(),
                                ));
                            }
                            last_was_global = true;
                        }
                    }
                }
                path_attr = Some((path, Attribute { original: attr }))
            }
        }

        let id_attr = if let Some(id_attr) = id_attr {
            id_attr
        } else {
            return Err(Error::new_spanned(
                node,
                "#[id] attribute is required when using #[ebml_specification] attribute",
            ));
        };

        let data_type_attr = if let Some(data_type_attr) = data_type_attr {
            data_type_attr
        } else {
            return Err(Error::new_spanned(
                node,
                "#[data_type] attribute is required when using #[ebml_specification] attribute",
            ));
        };

        Ok(Variant {
            original: node,
            ident: node.ident.clone(),
            id_attr,
            data_type_attr,
            path_attr,
        })
    }
}
