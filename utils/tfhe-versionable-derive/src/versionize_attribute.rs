use proc_macro2::Span;
use quote::{quote, ToTokens};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    parse_quote, Attribute, Expr, GenericArgument, GenericParam, Generics, Ident, Lifetime, Lit,
    Meta, Path, PathArguments, Token, TraitBound, Type, TypeParam, WhereClause,
};

use crate::{
    add_lifetime_where_clause, add_trait_where_clause, add_where_lifetime_bound_to_generics,
    parse_const_str, DISPATCH_TRAIT_NAME, ERROR_TRAIT_NAME, FROM_TRAIT_NAME, INTO_TRAIT_NAME,
    SEND_TRAIT_NAME, STATIC_LIFETIME_NAME, SYNC_TRAIT_NAME, TRY_INTO_TRAIT_NAME,
    UNVERSIONIZE_ERROR_NAME, UNVERSIONIZE_TRAIT_NAME, VERSIONIZE_OWNED_TRAIT_NAME,
};

/// Name of the attribute used to give arguments to the `Versionize` macro
const VERSIONIZE_ATTR_NAME: &str = "versionize";

pub(crate) struct ClassicVersionizeAttribute {
    dispatch_enum: Path,
}

pub(crate) enum ConversionType {
    Direct,
    Try,
}

pub(crate) struct ConvertVersionizeAttribute {
    conversion_target: Path,
    conversion_type: ConversionType,
}

pub(crate) enum VersionizeAttribute {
    Classic(ClassicVersionizeAttribute),
    Convert(ConvertVersionizeAttribute),
}

#[derive(Default)]
struct VersionizeAttributeBuilder {
    dispatch_enum: Option<Path>,
    convert: Option<Path>,
    try_convert: Option<Path>,
    from: Option<Path>,
    try_from: Option<Path>,
    into: Option<Path>,
}

impl VersionizeAttributeBuilder {
    fn build(self, base_span: &Span) -> syn::Result<VersionizeAttribute> {
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
                dispatch_enum: self.dispatch_enum.ok_or(syn::Error::new(
                    *base_span,
                    "Missing dispatch enum argument",
                ))?,
            }))
        }
    }
}

impl VersionizeAttribute {
    /// Find and parse an attribute with the form `#[versionize(DispatchType)]`, where
    /// `DispatchType` is the name of the type holding the dispatch enum.
    /// Return an error if no `versionize` attribute has been found, if multiple attributes are
    /// present on the same struct or if the attribute is malformed.
    pub(crate) fn parse_from_attributes_list(
        attributes: &[Attribute],
    ) -> syn::Result<Option<Self>> {
        let version_attributes: Vec<&Attribute> = attributes
            .iter()
            .filter(|attr| attr.path().is_ident(VERSIONIZE_ATTR_NAME))
            .collect();

        match version_attributes.as_slice() {
            [] => Ok(None),
            [attr] => Self::parse_from_attribute(attr).map(Some),
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
                        // parse versionize(dispatch = "Type")
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

        attribute_builder.build(&attribute.span())
    }

    pub(crate) fn needs_conversion(&self) -> bool {
        match self {
            VersionizeAttribute::Classic(_) => false,
            VersionizeAttribute::Convert(_) => true,
        }
    }

    /// Return the associated type used in the `Versionize` trait: `MyType::Versioned<'vers>`
    ///
    /// If the type is directly versioned, this will be a type generated by the `VersionDispatch`.
    ///
    /// If we have a conversion before the versioning, we re-use the versioned_owned type of the
    /// conversion target. The versioned_owned is needed because the conversion will create a new
    /// value, so we can't just use a reference.
    pub(crate) fn versioned_type(
        &self,
        lifetime: &Lifetime,
        input_generics: &Generics,
    ) -> proc_macro2::TokenStream {
        match self {
            VersionizeAttribute::Classic(attr) => {
                let (_, ty_generics, _) = input_generics.split_for_impl();

                let dispatch_trait: Path = parse_const_str(DISPATCH_TRAIT_NAME);
                let dispatch_enum_path = &attr.dispatch_enum;
                quote! {
                    <#dispatch_enum_path #ty_generics as
                    #dispatch_trait<Self>>::Ref<#lifetime>
                }
            }
            VersionizeAttribute::Convert(_) => {
                // If we want to apply a conversion before the call to versionize we need to use the
                // "owned" alternative of the dispatch enum to be able to store the
                // conversion result.
                self.versioned_owned_type(input_generics)
            }
        }
    }

    /// Return the where clause for `MyType::Versioned<'vers>`. if `MyType` has generics, this means
    /// adding a 'vers lifetime bound on them.
    pub(crate) fn versioned_type_where_clause(
        &self,
        lifetime: &Lifetime,
        input_generics: &Generics,
    ) -> Option<WhereClause> {
        let mut generics = input_generics.clone();

        add_where_lifetime_bound_to_generics(&mut generics, lifetime);
        let (_, _, where_clause) = generics.split_for_impl();
        where_clause.cloned()
    }

    /// Return the associated type used in the `VersionizeOwned` trait: `MyType::VersionedOwned`
    ///
    /// If the type is directly versioned, this will be a type generated by the `VersionDispatch`.
    ///
    /// If we have a conversion before the versioning, we re-use the versioned_owned type of the
    /// conversion target.
    pub(crate) fn versioned_owned_type(
        &self,
        input_generics: &Generics,
    ) -> proc_macro2::TokenStream {
        let (_, ty_generics, _) = input_generics.split_for_impl();
        match self {
            VersionizeAttribute::Classic(attr) => {
                let dispatch_trait: Path = parse_const_str(DISPATCH_TRAIT_NAME);
                let dispatch_enum_path = &attr.dispatch_enum;
                quote! {
                    <#dispatch_enum_path #ty_generics as
                    #dispatch_trait<Self>>::Owned
                }
            }
            VersionizeAttribute::Convert(convert_attr) => {
                let convert_type_path = &convert_attr.conversion_target;
                let versionize_owned_trait: Path = parse_const_str(VERSIONIZE_OWNED_TRAIT_NAME);

                quote! {
                    <#convert_type_path as #versionize_owned_trait>::VersionedOwned
                }
            }
        }
    }

    /// Return the where clause for `MyType::VersionedOwned`.
    ///
    /// This is simply the where clause of the input type.
    pub(crate) fn versioned_owned_type_where_clause(
        &self,
        input_generics: &Generics,
    ) -> Option<WhereClause> {
        match self {
            VersionizeAttribute::Classic(_) => input_generics.split_for_impl().2.cloned(),
            VersionizeAttribute::Convert(convert_attr) => {
                extract_generics(&convert_attr.conversion_target)
                    .split_for_impl()
                    .2
                    .cloned()
            }
        }
    }

    /// Return the where clause needed to implement the Versionize trait.
    ///
    /// This is the same as the one for the VersionizeOwned, with an additional "Clone" bound in the
    /// case where we need to perform a conversion before the versioning.
    pub(crate) fn versionize_trait_where_clause(
        &self,
        input_generics: &Generics,
    ) -> syn::Result<Option<WhereClause>> {
        // The base bounds for the owned traits are also used for the ref traits
        let mut generics = input_generics.clone();
        if self.needs_conversion() {
            // The versionize method takes a ref. We need to own the input type in the conversion
            // case to apply `From<Input> for Target`. This adds a `Clone` bound to have
            // a better error message if the input type is not Clone.
            add_trait_where_clause(&mut generics, [&parse_quote! { Self }], &["Clone"])?;
        }

        self.versionize_owned_trait_where_clause(&generics)
    }

    /// Return the where clause needed to implement the VersionizeOwned trait.
    ///
    /// If the type is directly versioned, the bound states that the argument points to a valid
    /// DispatchEnum for this type. This is done by adding a bound on this argument to
    /// `VersionsDisaptch<Self>`.
    ///
    /// If there is a conversion, the target of the conversion should implement `VersionizeOwned`
    /// and `From<Self>`.
    pub(crate) fn versionize_owned_trait_where_clause(
        &self,
        input_generics: &Generics,
    ) -> syn::Result<Option<WhereClause>> {
        let mut generics = input_generics.clone();
        match self {
            VersionizeAttribute::Classic(attr) => {
                let dispatch_generics = generics.clone();
                let dispatch_ty_generics = dispatch_generics.split_for_impl().1;
                let dispatch_enum_path = &attr.dispatch_enum;

                add_trait_where_clause(
                    &mut generics,
                    [&parse_quote!(#dispatch_enum_path #dispatch_ty_generics)],
                    &[format!("{}<Self>", DISPATCH_TRAIT_NAME,)],
                )?;
            }
            VersionizeAttribute::Convert(convert_attr) => {
                let convert_type_path = &convert_attr.conversion_target;
                add_trait_where_clause(
                    &mut generics,
                    [&parse_quote!(#convert_type_path)],
                    &[
                        VERSIONIZE_OWNED_TRAIT_NAME,
                        &format!("{}<Self>", FROM_TRAIT_NAME),
                    ],
                )?;
            }
        }

        Ok(generics.split_for_impl().2.cloned())
    }

    /// Return the where clause for the `Unversionize` trait.
    ///
    /// If the versioning is direct, this is the same bound as the one used for `VersionizeOwned`.
    ///
    /// If there is a conversion, the target of the conversion need to implement `Unversionize` and
    /// `Into` or `TryInto<T, E>`, with `E: Error + Send + Sync + 'static`
    pub(crate) fn unversionize_trait_where_clause(
        &self,
        input_generics: &Generics,
    ) -> syn::Result<Option<WhereClause>> {
        match self {
            VersionizeAttribute::Classic(_) => {
                self.versionize_owned_trait_where_clause(input_generics)
            }
            VersionizeAttribute::Convert(convert_attr) => {
                let mut generics = input_generics.clone();
                let convert_type_path = &convert_attr.conversion_target;
                let into_trait = match convert_attr.conversion_type {
                    ConversionType::Direct => format!("{}<Self>", INTO_TRAIT_NAME),
                    ConversionType::Try => {
                        // Doing a TryFrom requires that the error
                        // impl Error + Send + Sync + 'static
                        let try_into_trait: Path = parse_const_str(TRY_INTO_TRAIT_NAME);
                        add_trait_where_clause(
                            &mut generics,
                            [&parse_quote!(<#convert_type_path as #try_into_trait<Self>>::Error)],
                            &[ERROR_TRAIT_NAME, SYNC_TRAIT_NAME, SEND_TRAIT_NAME],
                        )?;
                        add_lifetime_where_clause(
                            &mut generics,
                            [&parse_quote!(<#convert_type_path as #try_into_trait<Self>>::Error)],
                            &[STATIC_LIFETIME_NAME],
                        )?;

                        format!("{}<Self>", TRY_INTO_TRAIT_NAME)
                    }
                };
                add_trait_where_clause(
                    &mut generics,
                    [&parse_quote!(#convert_type_path)],
                    &[
                        UNVERSIONIZE_TRAIT_NAME,
                        &format!("{}<Self>", FROM_TRAIT_NAME),
                        &into_trait,
                    ],
                )?;

                Ok(generics.split_for_impl().2.cloned())
            }
        }
    }

    /// Return the body of the versionize method.
    pub(crate) fn versionize_method_body(&self) -> proc_macro2::TokenStream {
        let versionize_owned_trait: TraitBound = parse_const_str(VERSIONIZE_OWNED_TRAIT_NAME);

        match self {
            VersionizeAttribute::Classic(_) => {
                quote! {
                    self.into()
                }
            }
            VersionizeAttribute::Convert(convert_attr) => {
                let convert_type_path = with_turbofish(&convert_attr.conversion_target);
                quote! {
                    #versionize_owned_trait::versionize_owned(#convert_type_path::from(self.to_owned()))
                }
            }
        }
    }

    /// Return the body of the versionize_owned method.
    pub(crate) fn versionize_owned_method_body(&self) -> proc_macro2::TokenStream {
        let versionize_owned_trait: TraitBound = parse_const_str(VERSIONIZE_OWNED_TRAIT_NAME);

        match self {
            VersionizeAttribute::Classic(_) => {
                quote! {
                    self.into()
                }
            }
            VersionizeAttribute::Convert(convert_attr) => {
                let convert_type_path = with_turbofish(&convert_attr.conversion_target);
                quote! {
                    #versionize_owned_trait::versionize_owned(#convert_type_path::from(self))
                }
            }
        }
    }

    /// Return the body of the unversionize method.
    pub(crate) fn unversionize_method_body(&self, arg_name: &Ident) -> proc_macro2::TokenStream {
        let error: Type = parse_const_str(UNVERSIONIZE_ERROR_NAME);
        match self {
            VersionizeAttribute::Classic(_) => {
                quote! { #arg_name.try_into() }
            }
            VersionizeAttribute::Convert(convert_attr) => {
                let target = with_turbofish(&convert_attr.conversion_target);
                match convert_attr.conversion_type {
                    ConversionType::Direct => {
                        quote! { #target::unversionize(#arg_name).map(|value| value.into()) }
                    }
                    ConversionType::Try => {
                        let target_name = format!("{}", target.to_token_stream());
                        quote! { #target::unversionize(#arg_name).and_then(|value| TryInto::<Self>::try_into(value)
                            .map_err(|e| #error::conversion(#target_name, e)))
                        }
                    }
                }
            }
        }
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

/// Return the same type but with generics that use the turbofish syntax. Converts
/// `MyStruct<T>` into `MyStruct::<T>`
fn with_turbofish(path: &Path) -> Path {
    let mut with_turbo = path.clone();

    for segment in with_turbo.segments.iter_mut() {
        if let PathArguments::AngleBracketed(generics) = &mut segment.arguments {
            generics.colon2_token = Some(Token![::](generics.span()));
        }
    }

    with_turbo
}

/// Extract the generics inside a type
fn extract_generics(path: &Path) -> Generics {
    let mut generics = Generics::default();

    if let Some(last_segment) = path.segments.last() {
        if let PathArguments::AngleBracketed(args) = &last_segment.arguments {
            for arg in &args.args {
                if let GenericArgument::Type(Type::Path(type_path)) = arg {
                    if let Some(ident) = type_path.path.get_ident() {
                        let param = TypeParam::from(ident.clone());
                        generics.params.push(GenericParam::Type(param));
                    }
                }
            }
        }
    }

    generics
}
