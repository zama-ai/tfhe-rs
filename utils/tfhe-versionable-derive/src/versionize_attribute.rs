//! This module handles the parsing of the parameters of the proc macro, found in the
//! `#[versionize(...)]` attribute

use proc_macro2::Span;
use quote::ToTokens;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Attribute, Expr, Lit, Meta, Path, Token};

/// Name of the attribute used to give arguments to the `Versionize` macro
const VERSIONIZE_ATTR_NAME: &str = "versionize";

/// Transparent mode can also be activated using `#[repr(transparent)]`
pub(crate) const REPR_ATTR_NAME: &str = "repr";

/// Represent the parsed `#[versionize(...)]` attribute
pub(crate) enum VersionizeAttribute {
    Classic(ClassicVersionizeAttribute),
    Convert(ConvertVersionizeAttribute),
    Transparent,
}

/// The "classic" variant of the versionize attribute: `#[versionize(MyTypeVersions)]`
pub(crate) struct ClassicVersionizeAttribute {
    pub(crate) dispatch_enum: Path,
}

/// A versionize attribute with a type conversion: `#[versionize(convert = "SerializableMyType")]`
/// or `#[versionize(from = "SerializableMyType", into = "SerializableMyType")]`
pub(crate) struct ConvertVersionizeAttribute {
    pub(crate) conversion_target: Path,
    pub(crate) conversion_type: ConversionType,
}

/// Tell if the conversion can fail or not
pub(crate) enum ConversionType {
    Direct,
    Try,
}

#[derive(Default)]
struct VersionizeAttributeBuilder {
    dispatch_enum: Option<Path>,
    convert: Option<Path>,
    try_convert: Option<Path>,
    from: Option<Path>,
    try_from: Option<Path>,
    into: Option<Path>,
    transparent: bool,
}

impl VersionizeAttributeBuilder {
    fn build(self, base_span: Span) -> syn::Result<VersionizeAttribute> {
        if self.transparent {
            if self.dispatch_enum.is_some()
                || self.convert.is_some()
                || self.try_convert.is_some()
                || self.from.is_some()
                || self.into.is_some()
            {
                return Err(syn::Error::new(
                    base_span,
                    "'transparent' does not accept any other parameters",
                ));
            } else {
                return Ok(VersionizeAttribute::Transparent);
            }
        }

        let convert_is_try = self.try_convert.is_some() || self.try_from.is_some();
        // User should not use `from` and `try_from` at the same time
        let from_target = match (self.from, self.try_from) {
            (None, None) => None,
            (Some(_), Some(try_from)) => {
                return Err(syn::Error::new(
                    try_from.span(),
                    "'try_from' and 'from' attributes are mutually exclusive",
                ))
            }
            (None, Some(try_from)) => Some(try_from),
            (Some(from), None) => Some(from),
        };

        // Same with `convert`/`try_convert`
        let convert_target = match (self.convert, self.try_convert) {
            (None, None) => None,
            (Some(_), Some(try_convert)) => {
                return Err(syn::Error::new(
                    try_convert.span(),
                    "'try_convert' and 'convert' attributes are mutually exclusive",
                ))
            }
            (None, Some(try_convert)) => Some(try_convert),
            (Some(convert), None) => Some(convert),
        };

        // from/into are here for similarity with serde, but we don't actually support having
        // different target inside. So we check this to warn the user
        let from_target =
            match (from_target, self.into) {
                (None, None) => None,
                (None, Some(into)) => return Err(syn::Error::new(
                    into.span(),
                    "unidirectional conversions are not handled, please add a 'from'/'try_from' \
attribute or use the 'convert'/'try_convert' attribute instead",
                )),
                (Some(from), None) => return Err(syn::Error::new(
                    from.span(),
                    "unidirectional conversions are not handled, please add a 'into' attribute or \
use the 'convert'/'try_convert' attribute instead",
                )),
                (Some(from), Some(into)) => {
                    if format!("{}", from.to_token_stream())
                        != format!("{}", into.to_token_stream())
                    {
                        return Err(syn::Error::new(
                        from.span(),
                        "unidirectional conversions are not handled, 'from' and 'into' parameters \
should have the same value",
                    ));
                    } else {
                        Some(from)
                    }
                }
            };

        // Finally, checks that the user doesn't use both from/into and convert
        let conversion_target = match (from_target, convert_target) {
            (None, None) => None,
            (Some(_), Some(convert)) => {
                return Err(syn::Error::new(
                    convert.span(),
                    "'convert' and 'from'/'into' attributes are mutually exclusive",
                ))
            }
            (None, Some(convert)) => Some(convert),
            (Some(from), None) => Some(from),
        };

        if let Some(conversion_target) = conversion_target {
            Ok(VersionizeAttribute::Convert(ConvertVersionizeAttribute {
                conversion_target,
                conversion_type: if convert_is_try {
                    ConversionType::Try
                } else {
                    ConversionType::Direct
                },
            }))
        } else {
            Ok(VersionizeAttribute::Classic(ClassicVersionizeAttribute {
                dispatch_enum: self
                    .dispatch_enum
                    .ok_or(syn::Error::new(base_span, "Missing dispatch enum argument"))?,
            }))
        }
    }
}

impl VersionizeAttribute {
    /// Find and parse an attribute with the form `#[versionize(DispatchType)]`, where
    /// `DispatchType` is the name of the type holding the dispatch enum.
    /// Return an error if no `versionize` attribute has been found, if multiple attributes are
    /// present on the same struct or if the attribute is malformed.
    pub(crate) fn parse_from_attributes_list(attributes: &[Attribute]) -> syn::Result<Self> {
        let version_attributes: Vec<&Attribute> = attributes
            .iter()
            .filter(|attr| attr.path().is_ident(VERSIONIZE_ATTR_NAME))
            .collect();

        // Check if transparent mode is enabled via repr(transparent). It can also be enabled with
        // the versionize attribute.
        let type_is_transparent = is_transparent(attributes)?;

        match version_attributes.as_slice() {
            [] => {
                if type_is_transparent {
                    Ok(Self::Transparent)
                } else {
                    Err(syn::Error::new(
                        Span::call_site(),
                        "Missing `versionize` attribute for `Versionize`",
                    ))
                }
            }
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
                Meta::Path(path) => {
                    // parse versionize(transparent)
                    if path.is_ident("transparent") {
                        if attribute_builder.transparent {
                            return Err(Self::default_error(meta.span()));
                        } else {
                            attribute_builder.transparent = true;
                        }
                        // parse versionize(MyTypeVersions)
                    } else if attribute_builder.dispatch_enum.is_some() {
                        return Err(Self::default_error(meta.span()));
                    } else {
                        attribute_builder.dispatch_enum = Some(path.clone());
                    }
                }
                Meta::NameValue(name_value) => {
                    // parse versionize(convert = "TypeConvert")
                    if name_value.path.is_ident("convert") {
                        if attribute_builder.convert.is_some() {
                            return Err(Self::default_error(meta.span()));
                        } else {
                            attribute_builder.convert =
                                Some(parse_path_ignore_quotes(&name_value.value)?);
                        }
                        // parse versionize(try_convert = "TypeTryConvert")
                    } else if name_value.path.is_ident("try_convert") {
                        if attribute_builder.try_convert.is_some() {
                            return Err(Self::default_error(meta.span()));
                        } else {
                            attribute_builder.try_convert =
                                Some(parse_path_ignore_quotes(&name_value.value)?);
                        }
                    // parse versionize(from = "TypeFrom")
                    } else if name_value.path.is_ident("from") {
                        if attribute_builder.from.is_some() {
                            return Err(Self::default_error(meta.span()));
                        } else {
                            attribute_builder.from =
                                Some(parse_path_ignore_quotes(&name_value.value)?);
                        }
                        // parse versionize(try_from = "TypeTryFrom")
                    } else if name_value.path.is_ident("try_from") {
                        if attribute_builder.try_from.is_some() {
                            return Err(Self::default_error(meta.span()));
                        } else {
                            attribute_builder.try_from =
                                Some(parse_path_ignore_quotes(&name_value.value)?);
                        }
                        // parse versionize(into = "TypeInto")
                    } else if name_value.path.is_ident("into") {
                        if attribute_builder.into.is_some() {
                            return Err(Self::default_error(meta.span()));
                        } else {
                            attribute_builder.into =
                                Some(parse_path_ignore_quotes(&name_value.value)?);
                        }
                        // parse versionize(dispatch = "MyTypeVersions")
                    } else if name_value.path.is_ident("dispatch") {
                        if attribute_builder.dispatch_enum.is_some() {
                            return Err(Self::default_error(meta.span()));
                        } else {
                            attribute_builder.dispatch_enum =
                                Some(parse_path_ignore_quotes(&name_value.value)?);
                        }
                    } else {
                        return Err(Self::default_error(meta.span()));
                    }
                }
                _ => return Err(Self::default_error(meta.span())),
            }
        }

        attribute_builder.build(attribute.span())
    }
}

/// Allow the user to give type arguments as `#[versionize(MyType)]` as well as
/// `#[versionize("MyType")]`
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

/// Check if the target type has the `#[repr(transparent)]` attribute in its attributes list
pub(crate) fn is_transparent(attributes: &[Attribute]) -> syn::Result<bool> {
    if let Some(attr) = attributes
        .iter()
        .find(|attr| attr.path().is_ident(REPR_ATTR_NAME))
    {
        let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;

        for meta in nested.iter() {
            if let Meta::Path(path) = meta {
                if path.is_ident("transparent") {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}
