use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;
use syn::{
    parse_quote, Data, DeriveInput, Field, Fields, Generics, ItemEnum, ItemImpl, Lifetime, Path,
    Type, Variant,
};

use crate::associated::{
    generate_from_trait_impl, generate_try_from_trait_impl, AssociatedType, AssociatedTypeKind,
    ConversionDirection,
};
use crate::{
    parse_const_str, LIFETIME_NAME, UNVERSIONIZE_ERROR_NAME, UPGRADE_TRAIT_NAME, VERSION_TRAIT_NAME,
};

/// This is the enum that holds all the versions of a specific type. Each variant of the enum is
/// a Version of a given type. The users writes the input enum using its own types. The macro
/// will generate two types:
/// - a `ref` type that uses the `ref` Version equivalent of each variant
/// - an owned type, that uses the VersionOwned equivalent of each variant
pub(crate) struct DispatchType {
    orig_type: ItemEnum,
    kind: AssociatedTypeKind,
}

/// The `VersionsDispatch` macro can only be used on enum. This converts the
/// generic `DeriveInput` into an `ItemEnum` or returns an explicit error.
fn derive_input_to_enum(input: &DeriveInput) -> syn::Result<ItemEnum> {
    match &input.data {
        Data::Enum(enu) => Ok(ItemEnum {
            attrs: input.attrs.clone(),
            vis: input.vis.clone(),
            enum_token: enu.enum_token,
            ident: input.ident.clone(),
            generics: input.generics.clone(),
            brace_token: enu.brace_token,
            variants: enu.variants.clone(),
        }),
        _ => Err(syn::Error::new(
            input.span(),
            "VersionsDispatch can only be derived on an enum",
        )),
    }
}

impl AssociatedType for DispatchType {
    fn ref_bounds(&self) -> &'static [&'static str] {
        &[VERSION_TRAIT_NAME]
    }

    fn owned_bounds(&self) -> &'static [&'static str] {
        &[VERSION_TRAIT_NAME]
    }

    fn new_ref(orig_type: &DeriveInput) -> syn::Result<Self> {
        for lt in orig_type.generics.lifetimes() {
            // check for collision with other lifetimes in `orig_type`
            if lt.lifetime.ident == LIFETIME_NAME {
                return Err(syn::Error::new(
                    lt.lifetime.span(),
                    format!(
                        "Lifetime name {} conflicts with the one used by macro `Version`",
                        LIFETIME_NAME
                    ),
                ));
            }
        }

        let lifetime = Lifetime::new(LIFETIME_NAME, Span::call_site());
        Ok(Self {
            orig_type: derive_input_to_enum(orig_type)?,
            kind: AssociatedTypeKind::Ref(Some(lifetime)),
        })
    }

    fn new_owned(orig_type: &DeriveInput) -> syn::Result<Self> {
        Ok(Self {
            orig_type: derive_input_to_enum(orig_type)?,
            kind: AssociatedTypeKind::Owned,
        })
    }

    fn generate_type_declaration(&self) -> syn::Result<syn::Item> {
        let variants: syn::Result<Punctuated<Variant, Comma>> = self
            .orig_type
            .variants
            .iter()
            .map(|variant| {
                let dispatch_field = self.convert_field(self.variant_field(variant)?);
                let dispatch_variant = Variant {
                    fields: Fields::Unnamed(parse_quote!((#dispatch_field))),
                    ..variant.clone()
                };

                Ok(dispatch_variant)
            })
            .collect();

        Ok(ItemEnum {
            ident: self.ident(),
            generics: self.type_generics()?,
            attrs: vec![parse_quote! { #[automatically_derived] }],
            variants: variants?,
            ..self.orig_type.clone()
        }
        .into())
    }

    fn kind(&self) -> &AssociatedTypeKind {
        &self.kind
    }

    fn is_transparent(&self) -> bool {
        false
    }

    fn orig_type_generics(&self) -> &Generics {
        &self.orig_type.generics
    }

    fn conversion_generics(&self, direction: ConversionDirection) -> syn::Result<Generics> {
        let mut generics = self.type_generics()?;
        let preds = &mut generics.make_where_clause().predicates;

        let upgrade_trait: Path = parse_const_str(UPGRADE_TRAIT_NAME);

        if let ConversionDirection::AssociatedToOrig = direction {
            if let AssociatedTypeKind::Owned = &self.kind {
                // Add a bound for each version to be upgradable into the next one
                for src_idx in 0..(self.versions_count() - 1) {
                    let src_ty = self.version_type_at(src_idx)?;
                    let next_ty = self.version_type_at(src_idx + 1)?;
                    preds.push(parse_quote! { #src_ty: #upgrade_trait<#next_ty> })
                }
            }
        }

        Ok(generics)
    }

    fn generate_conversion(&self) -> syn::Result<Vec<ItemImpl>> {
        match &self.kind {
            AssociatedTypeKind::Ref(lifetime) => {
                // Wraps the highest version into the dispatch enum
                let generics = self.conversion_generics(ConversionDirection::OrigToAssociated)?;
                let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

                let src_type = self.latest_version_type()?;
                let src = parse_quote! { &#lifetime #src_type };
                let dest_ident = self.ident();
                let dest = parse_quote! { #dest_ident #ty_generics };
                let constructor = self.generate_conversion_constructor_ref("value")?;

                generate_from_trait_impl(
                    &src,
                    &dest,
                    &impl_generics,
                    where_clause,
                    &constructor,
                    "value",
                )
                .map(|res| vec![res])
            }
            AssociatedTypeKind::Owned => {
                // Upgrade to the highest version the convert to the main type
                let generics = self.conversion_generics(ConversionDirection::AssociatedToOrig)?;
                let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

                let src_ident = self.ident();
                let src = parse_quote! { #src_ident #ty_generics };
                let dest_type = self.latest_version_type()?;
                let dest = parse_quote! { #dest_type };
                let error = parse_const_str(UNVERSIONIZE_ERROR_NAME);
                let constructor = self.generate_conversion_constructor_owned("value")?;

                let assoc_to_orig = generate_try_from_trait_impl(
                    &src,
                    &dest,
                    &error,
                    &impl_generics,
                    where_clause,
                    &constructor,
                    "value",
                )?;

                // Wraps the highest version into the dispatch enum
                let generics = self.conversion_generics(ConversionDirection::OrigToAssociated)?;
                let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

                let src_type = self.latest_version_type()?;
                let src = parse_quote! { #src_type };
                let dest_ident = self.ident();
                let dest = parse_quote! { #dest_ident #ty_generics };
                let constructor = self.generate_conversion_constructor_ref("value")?;

                let orig_to_assoc = generate_from_trait_impl(
                    &src,
                    &dest,
                    &impl_generics,
                    where_clause,
                    &constructor,
                    "value",
                )?;

                Ok(vec![orig_to_assoc, assoc_to_orig])
            }
        }
    }

    fn ident(&self) -> Ident {
        match &self.kind {
            AssociatedTypeKind::Ref(_) => {
                format_ident!("{}Dispatch", self.orig_type.ident)
            }
            AssociatedTypeKind::Owned => {
                format_ident!("{}DispatchOwned", self.orig_type.ident)
            }
        }
    }

    fn lifetime(&self) -> Option<&Lifetime> {
        match &self.kind {
            AssociatedTypeKind::Ref(lifetime) => lifetime.as_ref(),
            AssociatedTypeKind::Owned => None,
        }
    }

    fn inner_types(&self) -> syn::Result<Vec<&Type>> {
        self.version_types()
    }

    fn as_trait_param(&self) -> Option<syn::Result<&Type>> {
        Some(self.latest_version_type())
    }
}

impl DispatchType {
    /// Returns the error sent to the user for a wrong use of this macro
    fn error(&self) -> syn::Error {
        syn::Error::new(
            self.orig_type.span(),
            "VersionsDispatch should be used on a enum with single anonymous field variants",
        )
    }

    /// Returns the number of versions in this dispatch enum
    fn versions_count(&self) -> usize {
        self.orig_type.variants.len()
    }

    /// Returns the latest version of the original type, which is the last variant in the enum
    fn latest_version(&self) -> syn::Result<&Variant> {
        self.orig_type.variants.last().ok_or_else(|| self.error())
    }

    fn version_types(&self) -> syn::Result<Vec<&Type>> {
        self.orig_type
            .variants
            .iter()
            .map(|variant| self.variant_field(variant))
            .map(|field_opt| field_opt.map(|field| &field.ty))
            .collect()
    }

    /// Returns the type of the version at index `idx`
    fn version_type_at(&self, idx: usize) -> syn::Result<&Type> {
        self.variant_at(idx)
            .and_then(|variant| self.variant_field(variant))
            .map(|field| &field.ty)
    }

    /// Returns the variant at index `idx`
    fn variant_at(&self, idx: usize) -> syn::Result<&Variant> {
        self.orig_type
            .variants
            .iter()
            .nth(idx)
            .ok_or_else(|| self.error())
    }

    /// Returns the type of the latest version of the original type
    fn latest_version_type(&self) -> syn::Result<&Type> {
        self.latest_version()
            .and_then(|variant| self.variant_field(variant))
            .map(|field| &field.ty)
    }

    /// Returns the field inside a specific variant of the enum. Checks that this variant contains
    /// only one unnamed field.
    fn variant_field<'a>(&'a self, variant: &'a Variant) -> syn::Result<&'a Field> {
        match &variant.fields {
            // Check that the variant is of the form `Vn(XXXVersion)`
            Fields::Named(_) => Err(self.error()),
            Fields::Unnamed(fields) => {
                if fields.unnamed.len() != 1 {
                    Err(self.error())
                } else {
                    // Ok to unwrap because we checked that len is 1
                    Ok(fields.unnamed.first().unwrap())
                }
            }
            Fields::Unit => Err(self.error()),
        }
    }

    /// Converts the field of a variant of a dispatch enum into a field that uses
    /// the `Version` equivalent of the type
    fn convert_field(&self, field: &Field) -> Field {
        let orig_ty = field.ty.clone();
        let version_trait: Path = parse_const_str(VERSION_TRAIT_NAME);

        let ty: Type = match &self.kind {
            AssociatedTypeKind::Ref(lifetime) => parse_quote! {
                <#orig_ty as #version_trait>::Ref<#lifetime>
            },
            AssociatedTypeKind::Owned => parse_quote! {
                <#orig_ty as #version_trait>::Owned
            },
        };

        Field {
            ty,
            ..field.clone()
        }
    }

    /// Generates the conversion from a reference to the original type into the `ref` dispatch
    /// type. This basically generates code that wrapes the input into the last variant of the enum.
    fn generate_conversion_constructor_ref(&self, arg_name: &str) -> syn::Result<TokenStream> {
        let variant_ident = &self.latest_version()?.ident;
        let arg_ident = Ident::new(arg_name, Span::call_site());

        Ok(quote! {
            Self::#variant_ident(#arg_ident.into())
        })
    }

    /// Generates conversion from the `owned` dispatch type to the original type. This generates a
    /// `match` on the dispatch enum that calls the update method on each version enough times to
    /// get to the latest version.
    fn generate_conversion_constructor_owned(&self, arg_name: &str) -> syn::Result<TokenStream> {
        let arg_ident = Ident::new(arg_name, Span::call_site());
        let error_ty: Type = parse_const_str(UNVERSIONIZE_ERROR_NAME);
        let upgrade_trait: Path = parse_const_str(UPGRADE_TRAIT_NAME);

        let match_cases =
            self.orig_type
                .variants
                .iter()
                .enumerate()
                .map(|(src_idx, variant)| -> syn::Result<_> {
                    let last_version = self.versions_count() - 1;
                    let enum_ident = self.ident();
                    let target_type = self.version_type_at(src_idx)?;
                    let variant_ident = &variant.ident;
                    let var_name = format_ident!("v{}", src_idx);

                    let upgrades_needed =  last_version - src_idx;

                    // Add chained calls to the upgrade method, with error handling
                    let upgrades_chain = (0..upgrades_needed).map(|upgrade_idx| {
                        // Here we can unwrap because src_idx + upgrade_idx < version_count or we wouldn't need to upgrade
                        let src_type = self.version_type_at(src_idx + upgrade_idx).unwrap();
                        let src_variant = self.variant_at(src_idx + upgrade_idx).unwrap().ident.to_string();
                        let dest_variant = self.variant_at(src_idx + upgrade_idx + 1).unwrap().ident.to_string();
                        quote! {
                            .and_then(|value: #src_type| {
                                #upgrade_trait::upgrade(value)
                                .map_err(|e|
                                    #error_ty::upgrade(#src_variant, #dest_variant, e)
                                )
                            })
                        }
                    });

                    Ok(quote! {
                        #enum_ident::#variant_ident(#var_name) => TryInto::<#target_type>::try_into(#var_name)
                            #(#upgrades_chain)*
                    })
                }).collect::<syn::Result<Vec<TokenStream>>>()?;

        Ok(quote! {
            match #arg_ident {
                #(#match_cases),*
            }
        })
    }
}
