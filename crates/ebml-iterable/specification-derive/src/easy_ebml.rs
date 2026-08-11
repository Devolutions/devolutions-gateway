use proc_macro2::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseBuffer, ParseStream};
use syn::punctuated::Punctuated;
use syn::{AttrStyle, Attribute, Error, Ident, LitInt, Result, Token, Variant, Visibility};

use crate::pathing::{EBMLPath, PathPart};

pub struct EasyEBML {
    attrs: Vec<Attribute>,
    visibility: Visibility,
    ident: Ident,
    variants: Punctuated<EasyEBMLVariant, Token![,]>,
}

impl Parse for EasyEBML {
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let visibility: Visibility = input.parse()?;
        input.parse::<Token![enum]>()?;
        let ident = input.parse::<Ident>()?;
        let content: ParseBuffer;
        syn::braced!(content in input);
        let variants = content.parse_terminated(EasyEBMLVariant::parse)?;
        Ok(Self {
            attrs,
            visibility,
            ident,
            variants,
        })
    }
}

impl EasyEBML {
    pub fn implement(self) -> Result<TokenStream> {
        let EasyEBML {
            attrs,
            visibility,
            ident,
            variants,
        } = self;

        let variants: Vec<_> = variants
            .into_iter()
            .map(EasyEBMLVariant::into_variant)
            .collect::<Result<_>>()?;

        Ok(quote!(
            #[ebml_iterable::specs::ebml_specification]
            #(#attrs)*
            #visibility enum #ident {
                #(#variants),*
            }
        ))
    }
}

pub struct EasyEBMLVariant {
    path: EBMLPath,
    ty: Ident,
    id: LitInt,
}

impl EasyEBMLVariant {
    pub fn into_variant(self) -> Result<Variant> {
        let EasyEBMLVariant { path, ty, id } = self;
        let span = path.span;
        let mut path: Vec<PathPart> = path.parts.into_iter().collect();
        let ident: Ident = match path
            .pop()
            .ok_or_else(|| Error::new(span, "easy_ebml enum variant must be at least: `Name: Type = id`"))?
        {
            PathPart::Ident(id) => Ok(id),
            PathPart::Global(_) => Err(Error::new(span, "easy_ebml enum variant cannot end in global path")),
        }?;
        let mut attrs = vec![];
        attrs.push(Attribute {
            pound_token: Default::default(),
            style: AttrStyle::Outer,
            bracket_token: Default::default(),
            path: Ident::new("id", proc_macro2::Span::call_site()).into(),
            tokens: quote!((#id)),
        });
        attrs.push(Attribute {
            pound_token: Default::default(),
            style: AttrStyle::Outer,
            bracket_token: Default::default(),
            path: Ident::new("data_type", proc_macro2::Span::call_site()).into(),
            tokens: quote!((TagDataType::#ty)),
        });

        if !path.is_empty() {
            let mut tokens: Punctuated<PathPart, Token![/]> = Punctuated::new();
            for part in path {
                tokens.push(part);
            }
            attrs.push(Attribute {
                pound_token: Default::default(),
                style: AttrStyle::Outer,
                bracket_token: Default::default(),
                path: Ident::new("doc_path", proc_macro2::Span::call_site()).into(),
                tokens: quote!((#tokens)),
            });
        }

        Ok(Variant {
            attrs,
            ident,
            fields: syn::Fields::Unit,
            discriminant: None,
        })
    }
}

impl Parse for EasyEBMLVariant {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let path = input.parse()?;
        input.parse::<Token![:]>()?;
        let ty: Ident = input.parse()?;
        input.parse::<Token![=]>()?;
        let id: LitInt = input.parse()?;
        Ok(Self { path, ty, id })
    }
}
