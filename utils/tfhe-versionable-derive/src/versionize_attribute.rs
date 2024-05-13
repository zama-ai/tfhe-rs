use proc_macro2::Span;
use quote::{quote, ToTokens};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Attribute, Expr, Ident, Lit, Meta, Path, Token, Type};

use crate::{parse_const_str, UNVERSIONIZE_ERROR_NAME};

/// Name of the attribute used to give arguments to our macros
const VERSIONIZE_ATTR_NAME: &str = "versionize";

pub(crate) struct VersionizeAttribute {
    dispatch_enum: Path,
    from: Option<Path>,
    try_from: Option<Path>,
    into: Option<Path>,
}

#[derive(Default)]
struct VersionizeAttributeBuilder {
    dispatch_enum: Option<Path>,
    from: Option<Path>,
    try_from: Option<Path>,
    into: Option<Path>,
}

impl VersionizeAttributeBuilder {
    fn build(self) -> Option<VersionizeAttribute> {
        // These attributes are mutually exclusive
        if self.from.is_some() && self.try_from.is_some() {
            return None;
        }
        Some(VersionizeAttribute {
            dispatch_enum: self.dispatch_enum?,
            from: self.from,
            try_from: self.try_from,
            into: self.into,
        })
    }
}

impl VersionizeAttribute {
    /// Find and parse an attribute with the form `#[versionize(DispatchType)]`, where
    /// `DispatchType` is the name of the type holding the dispatch enum.
    /// Returns an error if no `versionize` attribute has been found, if multiple attributes are
    /// present on the same struct or if the attribute is malformed.
    pub(crate) fn parse_from_attributes_list(attributes: &[Attribute]) -> syn::Result<Self> {
        let version_attributes: Vec<&Attribute> = attributes
            .iter()
            .filter(|attr| attr.path().is_ident(VERSIONIZE_ATTR_NAME))
            .collect();

        match version_attributes.as_slice() {
            [] => Err(syn::Error::new(
                Span::call_site(),
                "Missing `versionize` attribute for `Versionize`",
            )),
            [attr] => Self::parse_from_attribute(attr),
            [_, attr2, ..] => Err(syn::Error::new(
                attr2.span(),
                "Multiple `versionize` attributes found",
            )),
        }
    }

    fn default_error(span: Span) -> syn::Error {
        syn::Error::new(span, "Malformed `versionize` attribute")
    }

    /// Parse a `versionize` attribute.
    /// The attribute is assumed to be a `versionize` attribute.
    pub(crate) fn parse_from_attribute(attribute: &Attribute) -> syn::Result<Self> {
        let nested = attribute.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;

        let mut attribute_builder = VersionizeAttributeBuilder::default();
        for meta in nested.iter() {
            match meta {
                Meta::Path(dispatch_enum) => {
                    if attribute_builder.dispatch_enum.is_some() {
                        return Err(Self::default_error(meta.span()));
                    } else {
                        attribute_builder.dispatch_enum = Some(dispatch_enum.clone());
                    }
                }
                Meta::List(_) => {
                    return Err(Self::default_error(meta.span()));
                }
                Meta::NameValue(name_value) => {
                    if name_value.path.is_ident("from") {
                        if attribute_builder.from.is_some() {
                            return Err(Self::default_error(meta.span()));
                        } else {
                            attribute_builder.from =
                                Some(parse_path_ignore_quotes(&name_value.value)?);
                        }
                    } else if name_value.path.is_ident("try_from") {
                        if attribute_builder.try_from.is_some() {
                            return Err(Self::default_error(meta.span()));
                        } else {
                            attribute_builder.try_from =
                                Some(parse_path_ignore_quotes(&name_value.value)?);
                        }
                    } else if name_value.path.is_ident("into") {
                        if attribute_builder.into.is_some() {
                            return Err(Self::default_error(meta.span()));
                        } else {
                            attribute_builder.into =
                                Some(parse_path_ignore_quotes(&name_value.value)?);
                        }
                    } else {
                        return Err(Self::default_error(meta.span()));
                    }
                }
            }
        }

        attribute_builder
            .build()
            .ok_or_else(|| Self::default_error(attribute.span()))
    }

    pub(crate) fn dispatch_enum(&self) -> &Path {
        &self.dispatch_enum
    }

    pub(crate) fn needs_conversion(&self) -> bool {
        self.try_from.is_some() || self.from.is_some()
    }

    pub(crate) fn dispatch_target(&self) -> Path {
        self.from
            .as_ref()
            .or(self.try_from.as_ref())
            .map(|target| target.to_owned())
            .unwrap_or_else(|| {
                syn::parse_str("Self").expect("Parsing of const value should never fail")
            })
    }

    pub(crate) fn versionize_method_body(&self) -> proc_macro2::TokenStream {
        self.into
            .as_ref()
            .map(|target| {
                quote! {
                    #target::from(self.to_owned()).versionize_owned()
                }
            })
            .unwrap_or_else(|| {
                quote! {
                    self.into()
                }
            })
    }

    pub(crate) fn unversionize_method_body(&self, arg_name: &Ident) -> proc_macro2::TokenStream {
        let error: Type = parse_const_str(UNVERSIONIZE_ERROR_NAME);
        if let Some(target) = &self.from {
            quote! { #target::unversionize(#arg_name).map(|value| value.into()) }
        } else if let Some(target) = &self.try_from {
            let target_name = format!("{}", target.to_token_stream());
            quote! { #target::unversionize(#arg_name).and_then(|value| TryInto::<Self>::try_into(value)
                .map_err(|e| #error::conversion(#target_name, &format!("{}", e))))
            }
        } else {
            quote! { #arg_name.try_into() }
        }
    }
}

fn parse_path_ignore_quotes(value: &Expr) -> syn::Result<Path> {
    match &value {
        Expr::Path(expr_path) => Ok(expr_path.path.clone()),
        Expr::Lit(expr_lit) => match &expr_lit.lit {
            Lit::Str(s) => syn::parse_str(&s.value()),
            _ => Err(syn::Error::new(
                value.span(),
                "Malformed `versionize` attribute",
            )),
        },
        _ => Err(syn::Error::new(
            value.span(),
            "Malformed `versionize` attribute",
        )),
    }
}
