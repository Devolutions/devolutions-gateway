use proc_macro2::Span;
use quote::{quote, TokenStreamExt};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Ident, LitInt, Result, Token};

pub struct EBMLPath {
    pub span: Span,
    pub parts: Punctuated<PathPart, Token![/]>,
}

impl Parse for EBMLPath {
    fn parse(input: ParseStream) -> Result<Self> {
        let parts: Punctuated<PathPart, Token![/]> = Punctuated::parse_separated_nonempty(input)?;
        Ok(Self {
            parts,
            span: input.span(),
        })
    }
}

#[derive(PartialEq)]
pub enum PathPart {
    Ident(Ident),
    Global((Option<u64>, Option<u64>)),
}

impl Parse for PathPart {
    fn parse(input: ParseStream) -> Result<Self> {
        if input.lookahead1().peek(syn::token::Paren) {
            let content;
            syn::parenthesized!(content in input);
            let min: Option<u64> = {
                if content.lookahead1().peek(Token![-]) {
                    None
                } else {
                    Some(content.parse::<LitInt>()?.base10_parse()?)
                }
            };
            content.parse::<Token![-]>()?;
            let max: Option<u64> = {
                let val: Option<LitInt> = content.parse()?;
                if let Some(val) = val {
                    Some(val.base10_parse()?)
                } else {
                    None
                }
            };

            Ok(PathPart::Global((min, max)))
        } else {
            let id: Ident = input.parse()?;
            Ok(PathPart::Ident(id))
        }
    }
}

impl std::fmt::Display for PathPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathPart::Ident(id) => write!(f, "{id}"),
            PathPart::Global((min, max)) => {
                let min = if let Some(min) = min {
                    min.to_string()
                } else {
                    String::new()
                };
                let max = if let Some(max) = max {
                    max.to_string()
                } else {
                    String::new()
                };
                write!(f, "({min}-{max})")
            }
        }
    }
}

impl quote::ToTokens for PathPart {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        match self {
            PathPart::Ident(id) => tokens.append(id.clone()),
            PathPart::Global((min, max)) => tokens.extend(quote! {(#min-#max)}),
        }
    }
}
