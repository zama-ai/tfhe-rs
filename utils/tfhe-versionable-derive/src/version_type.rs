use std::iter::zip;

use proc_macro2::{Literal, Span, TokenStream};
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;
use syn::{
    parse_quote, Data, DataEnum, DataStruct, DataUnion, DeriveInput, Field, Fields, FieldsNamed,
    FieldsUnnamed, Generics, Ident, Item, ItemEnum, ItemImpl, ItemStruct, ItemUnion, Lifetime,
    Path, Type, Variant,
};

use crate::associated::{
    generate_from_trait_impl, generate_try_from_trait_impl, AssociatedType, AssociatedTypeKind,
    ConversionDirection,
};
use crate::versionize_attribute::is_transparent;
use crate::{
    add_trait_where_clause, parse_const_str, parse_trait_bound, punctuated_from_iter_result,
    INTO_TRAIT_NAME, LIFETIME_NAME, TRY_INTO_TRAIT_NAME, UNVERSIONIZE_ERROR_NAME,
    UNVERSIONIZE_TRAIT_NAME, VERSIONIZE_OWNED_TRAIT_NAME, VERSIONIZE_TRAIT_NAME,
    VERSION_TRAIT_NAME,
};

/// The types generated for a specific version of a given exposed type. These types are identical to
/// the user written version types except that their subtypes are replaced by their "Versioned"
/// form. This allows recursive versioning.
pub(crate) struct VersionType {
    orig_type: DeriveInput,
    kind: AssociatedTypeKind,
    is_transparent: bool,
}

impl AssociatedType for VersionType {
    fn ref_bounds(&self) -> &'static [&'static str] {
        if self.is_transparent {
            &[VERSION_TRAIT_NAME]
        } else {
            &[VERSIONIZE_TRAIT_NAME]
        }
    }

    fn owned_bounds(&self) -> &'static [&'static str] {
        if self.is_transparent {
            &[VERSION_TRAIT_NAME]
        } else {
            &[VERSIONIZE_OWNED_TRAIT_NAME]
        }
    }

    fn new_ref(orig_type: &DeriveInput) -> syn::Result<VersionType> {
        let is_transparent = is_transparent(&orig_type.attrs)?;

        let lifetime = if is_unit(orig_type) {
            None
        } else {
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
            Some(Lifetime::new(LIFETIME_NAME, Span::call_site()))
        };
        Ok(Self {
            orig_type: orig_type.clone(),
            kind: AssociatedTypeKind::Ref(lifetime),
            is_transparent,
        })
    }

    fn new_owned(orig_type: &DeriveInput) -> syn::Result<Self> {
        let is_transparent = is_transparent(&orig_type.attrs)?;

        Ok(Self {
            orig_type: orig_type.clone(),
            kind: AssociatedTypeKind::Owned,
            is_transparent,
        })
    }

    fn generate_type_declaration(&self) -> syn::Result<Item> {
        match &self.orig_type.data {
            Data::Struct(stru) => self.generate_struct(stru).map(Item::Struct),
            Data::Enum(enu) => self.generate_enum(enu).map(Item::Enum),
            Data::Union(uni) => self.generate_union(uni).map(Item::Union),
        }
    }

    fn generate_conversion(&self) -> syn::Result<Vec<ItemImpl>> {
        let (_, orig_generics, _) = self.orig_type.generics.split_for_impl();

        match &self.kind {
            AssociatedTypeKind::Ref(lifetime) => {
                // Convert from `&'vers XXX` into `XXXVersion<'vers>`
                let generics = self.conversion_generics(ConversionDirection::OrigToAssociated)?;
                let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

                let src_ident = self.orig_type.ident.clone();
                let src = lifetime
                    .as_ref()
                    .map(|lifetime| parse_quote! { &#lifetime #src_ident #orig_generics })
                    .unwrap_or_else(|| parse_quote! { &#src_ident #orig_generics });
                let dest_ident = self.ident();
                let dest = parse_quote! { #dest_ident #ty_generics };
                let constructor = self.generate_conversion_constructor(
                    "value",
                    &src_ident,
                    ConversionDirection::OrigToAssociated,
                )?;

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
                // Convert from `XXXVersionOwned` into `XXX`
                let generics = self.conversion_generics(ConversionDirection::AssociatedToOrig)?;
                let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

                let src_ident = self.ident();
                let src = parse_quote! { #src_ident #ty_generics };
                let dest_ident = self.orig_type.ident.clone();
                let dest = parse_quote! { #dest_ident #orig_generics };
                let error = parse_const_str(UNVERSIONIZE_ERROR_NAME);
                let constructor = self.generate_conversion_constructor(
                    "value",
                    &src_ident,
                    ConversionDirection::AssociatedToOrig,
                )?;

                let assoc_to_orig = generate_try_from_trait_impl(
                    &src,
                    &dest,
                    &error,
                    &impl_generics,
                    where_clause,
                    &constructor,
                    "value",
                )?;

                // Convert from `&XXX` into `XXXVersionOwned`
                let generics = self.conversion_generics(ConversionDirection::OrigToAssociated)?;
                let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

                let src_ident = self.orig_type.ident.clone();
                let src = parse_quote! { #src_ident #orig_generics };
                let dest_ident = self.ident();
                let dest = parse_quote! { #dest_ident #ty_generics };
                let constructor = self.generate_conversion_constructor(
                    "value",
                    &src_ident,
                    ConversionDirection::OrigToAssociated,
                )?;

                let orig_to_assoc = generate_from_trait_impl(
                    &src,
                    &dest,
                    &impl_generics,
                    where_clause,
                    &constructor,
                    "value",
                )?;

                Ok(vec![assoc_to_orig, orig_to_assoc])
            }
        }
    }

    fn ident(&self) -> Ident {
        match &self.kind {
            AssociatedTypeKind::Ref(_) => {
                format_ident!("{}Version", self.orig_type.ident)
            }
            AssociatedTypeKind::Owned => {
                format_ident!("{}VersionOwned", self.orig_type.ident)
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
        self.orig_type_fields()
            .iter()
            .map(|field| Ok(&field.ty))
            .collect()
    }

    fn as_trait_param(&self) -> Option<syn::Result<&Type>> {
        None
    }

    fn kind(&self) -> &AssociatedTypeKind {
        &self.kind
    }

    fn is_transparent(&self) -> bool {
        self.is_transparent
    }

    fn orig_type_generics(&self) -> &Generics {
        &self.orig_type.generics
    }

    fn conversion_generics(&self, direction: ConversionDirection) -> syn::Result<Generics> {
        let mut generics = self.type_generics()?;

        if !self.is_transparent {
            if let ConversionDirection::AssociatedToOrig = direction {
                if let AssociatedTypeKind::Owned = &self.kind {
                    add_trait_where_clause(
                        &mut generics,
                        self.inner_types()?,
                        &[UNVERSIONIZE_TRAIT_NAME],
                    )?;
                }
            }
        }

        Ok(generics)
    }
}

impl VersionType {
    /// Returns the fields of the original declaration.
    fn orig_type_fields(&self) -> Punctuated<&Field, Comma> {
        derive_type_fields(&self.orig_type)
    }

    /// Generates the declaration for the Version equivalent of the input struct
    fn generate_struct(&self, stru: &DataStruct) -> syn::Result<ItemStruct> {
        let fields = match &stru.fields {
            Fields::Named(fields) => Fields::Named(self.convert_fields_named(fields)?),
            Fields::Unnamed(fields) => Fields::Unnamed(self.convert_fields_unnamed(fields)?),
            Fields::Unit => Fields::Unit,
        };

        let versioned_stru = ItemStruct {
            fields,
            ident: self.ident(),
            vis: self.orig_type.vis.clone(),
            attrs: vec![parse_quote! { #[automatically_derived] }],
            generics: self.type_generics()?,
            struct_token: stru.struct_token,
            semi_token: stru.semi_token,
        };

        Ok(versioned_stru)
    }

    /// Generates the declaration for the Version equivalent of the input enum
    fn generate_enum(&self, enu: &DataEnum) -> syn::Result<ItemEnum> {
        if enu.variants.is_empty() {
            return Err(syn::Error::new(
                self.orig_type.span(),
                "Version cannot be derived on empty enums",
            ));
        }

        let variants = punctuated_from_iter_result(
            enu.variants
                .iter()
                .map(|variant| self.convert_enum_variant(variant)),
        )?;

        let versioned_enu = ItemEnum {
            ident: self.ident(),
            vis: self.orig_type.vis.clone(),
            attrs: vec![parse_quote! { #[automatically_derived] }],
            generics: self.type_generics()?,
            enum_token: enu.enum_token,
            brace_token: enu.brace_token,
            variants,
        };

        Ok(versioned_enu)
    }

    /// Generates the declaration for the Version equivalent of the input union
    fn generate_union(&self, uni: &DataUnion) -> syn::Result<ItemUnion> {
        let fields = self.convert_fields_named(&uni.fields)?;

        let versioned_uni = ItemUnion {
            fields,
            ident: self.ident(),
            vis: self.orig_type.vis.clone(),
            attrs: vec![parse_quote! { #[automatically_derived] }],
            generics: self.type_generics()?,
            union_token: uni.union_token,
        };

        Ok(versioned_uni)
    }

    /// Converts an enum variant into its "Version" form
    fn convert_enum_variant(&self, variant: &Variant) -> syn::Result<Variant> {
        let fields = match &variant.fields {
            Fields::Named(fields) => Fields::Named(self.convert_fields_named(fields)?),
            Fields::Unnamed(fields) => Fields::Unnamed(self.convert_fields_unnamed(fields)?),
            Fields::Unit => Fields::Unit,
        };

        let versioned_variant = Variant {
            attrs: Vec::new(),
            ident: variant.ident.clone(),
            fields,
            discriminant: variant.discriminant.clone(),
        };

        Ok(versioned_variant)
    }

    /// Converts unnamed fields into Versioned
    fn convert_fields_unnamed(&self, fields: &FieldsUnnamed) -> syn::Result<FieldsUnnamed> {
        Ok(FieldsUnnamed {
            unnamed: punctuated_from_iter_result(self.convert_fields(fields.unnamed.iter()))?,
            ..fields.clone()
        })
    }

    /// Converts named fields into Versioned
    fn convert_fields_named(&self, fields: &FieldsNamed) -> syn::Result<FieldsNamed> {
        Ok(FieldsNamed {
            named: punctuated_from_iter_result(self.convert_fields(fields.named.iter()))?,
            ..fields.clone()
        })
    }

    /// Converts all fields in the given iterator into their "Versioned" counterparts.
    fn convert_fields<'a, I: Iterator<Item = &'a Field> + 'a>(
        &self,
        fields_iter: I,
    ) -> impl IntoIterator<Item = syn::Result<Field>> + 'a {
        let kind = self.kind.clone();
        let is_transparent = self.is_transparent;

        fields_iter.into_iter().map(move |field| {
            let unver_ty = field.ty.clone();

            if is_transparent {
                // If the type is transparent, we reuse the "Version" impl of the inner type
                let version_trait = parse_trait_bound(VERSION_TRAIT_NAME)?;

                let ty: Type = match &kind {
                    AssociatedTypeKind::Ref(lifetime) => parse_quote! {
                        <#unver_ty as #version_trait>::Ref<#lifetime>
                    },
                    AssociatedTypeKind::Owned => parse_quote! {
                        <#unver_ty as #version_trait>::Owned
                    },
                };

                Ok(Field {
                    ty,
                    ..field.clone()
                })
            } else {
                let versionize_trait = parse_trait_bound(VERSIONIZE_TRAIT_NAME)?;
                let versionize_owned_trait = parse_trait_bound(VERSIONIZE_OWNED_TRAIT_NAME)?;

                let ty: Type = match &kind {
                    AssociatedTypeKind::Ref(lifetime) => parse_quote! {
                        <#unver_ty as #versionize_trait>::Versioned<#lifetime>
                    },
                    AssociatedTypeKind::Owned => parse_quote! {
                        <#unver_ty as #versionize_owned_trait>::VersionedOwned
                    },
                };

                Ok(Field {
                    ty,
                    ..field.clone()
                })
            }
        })
    }

    /// Generates the constructor part of the conversion impl block. This will create the dest type
    /// using fields of the src one. This is easy since they both have the same shape.
    /// If the conversion is from the original type to a reference version type, this is done by
    /// calling the `versionize` method on all fields.
    /// If this is a conversion between the owned version type to the original type, this is done by
    /// calling the `unversionize` method.
    fn generate_conversion_constructor(
        &self,
        arg_name: &str,
        src_type: &Ident,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let constructor = match &self.orig_type.data {
            Data::Struct(stru) => self.generate_constructor_struct(arg_name, stru, direction),
            Data::Enum(enu) => self.generate_constructor_enum(arg_name, src_type, enu, direction),
            Data::Union(uni) => self.generate_constructor_union(arg_name, uni, direction),
        }?;

        match direction {
            ConversionDirection::OrigToAssociated => Ok(constructor),
            ConversionDirection::AssociatedToOrig => Ok(quote! { Ok(#constructor)  }),
        }
    }

    /// Generates the constructor for a struct.
    fn generate_constructor_struct(
        &self,
        arg_name: &str,
        stru: &DataStruct,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let fields = match &stru.fields {
            Fields::Named(fields) => {
                self.generate_constructor_fields_named(arg_name, fields.named.iter(), direction)?
            }
            Fields::Unnamed(fields) => self.generate_constructor_fields_unnamed(
                arg_name,
                fields.unnamed.iter(),
                direction,
            )?,
            Fields::Unit => TokenStream::new(),
        };

        Ok(quote! {
            Self #fields
        })
    }

    /// Generates the constructor for an enum.
    fn generate_constructor_enum(
        &self,
        arg_name: &str,
        src_type: &Ident,
        enu: &DataEnum,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        if enu.variants.is_empty() {
            return Err(syn::Error::new(
                self.orig_type.span(),
                "Version cannot be derived on empty enums",
            ));
        }

        let variant_constructors: syn::Result<Vec<TokenStream>> = enu
            .variants
            .iter()
            .map(|variant| self.generate_constructor_enum_variant(src_type, variant, direction))
            .collect();
        let variant_constructors = variant_constructors?;

        let arg_ident = Ident::new(arg_name, Span::call_site());

        Ok(quote! {
            match #arg_ident {
                #(#variant_constructors),*
            }
        })
    }

    /// Generates the constructor for an union.
    fn generate_constructor_union(
        &self,
        arg_name: &str,
        uni: &DataUnion,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let fields =
            self.generate_constructor_fields_named(arg_name, uni.fields.named.iter(), direction)?;

        Ok(quote! {
            Self #fields
        })
    }

    /// Generates the constructor for a specific variant of an enum
    fn generate_constructor_enum_variant(
        &self,
        src_type: &Ident,
        variant: &Variant,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let (param, fields) = match &variant.fields {
            Fields::Named(fields) => {
                let args_iter = fields
                    .named
                    .iter()
                    // Ok to unwrap because the field is named so field.ident is Some
                    .map(|field| field.ident.as_ref().unwrap());
                let args = args_iter.clone();

                (
                    quote! { {
                        #(#args),*
                    }},
                    self.generate_constructor_enum_variants_named(
                        args_iter.cloned(),
                        fields.named.iter(),
                        direction,
                    )?,
                )
            }
            Fields::Unnamed(fields) => {
                let args_iter = generate_args_list(fields.unnamed.len());
                let args = args_iter.clone();
                (
                    quote! { (#(#args),*) },
                    self.generate_constructor_enum_variants_unnamed(
                        args_iter,
                        fields.unnamed.iter(),
                        direction,
                    )?,
                )
            }
            Fields::Unit => (TokenStream::new(), TokenStream::new()),
        };
        let variant_ident = &variant.ident;

        Ok(quote! {
            #src_type::#variant_ident #param => Self::#variant_ident #fields
        })
    }

    /// Generates the constructor for the fields of a named struct.
    fn generate_constructor_fields_named<'a, I: Iterator<Item = &'a Field> + 'a>(
        &self,
        arg_name: &'a str,
        fields: I,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let fields: syn::Result<Vec<TokenStream>> = fields
            .into_iter()
            .map(move |field| self.generate_constructor_field_named(arg_name, field, direction))
            .collect();
        let fields = fields?;

        Ok(quote! {
            {
                #(#fields),*
            }
        })
    }

    /// Generates the constructor for a field of a named struct.
    fn generate_constructor_field_named(
        &self,
        arg_name: &str,
        field: &Field,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let arg_ident = Ident::new(arg_name, Span::call_site());
        // Ok to unwrap because the field is named so field.ident is Some
        let field_ident = field.ident.as_ref().unwrap();
        let ty = &field.ty;
        let param = quote! { #arg_ident.#field_ident };

        let rhs = if self.is_transparent() {
            self.generate_constructor_transparent_rhs(param, direction)?
        } else {
            self.generate_constructor_field_rhs(ty, param, false, direction)?
        };

        Ok(quote! {
            #field_ident: #rhs
        })
    }

    /// Generates the constructor for the fields of a named enum variant.
    fn generate_constructor_enum_variants_named<
        'a,
        I: Iterator<Item = &'a Field> + 'a,
        J: Iterator<Item = Ident>,
    >(
        &self,
        arg_names: J,
        fields: I,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let fields: syn::Result<Vec<TokenStream>> = zip(arg_names, fields)
            .map(move |(arg_name, field)| {
                // Ok to unwrap because the field is named so field.ident is Some
                let field_ident = field.ident.as_ref().unwrap();
                let rhs = if self.is_transparent() {
                    self.generate_constructor_transparent_rhs(quote! {#arg_name}, direction)?
                } else {
                    self.generate_constructor_field_rhs(
                        &field.ty,
                        quote! {#arg_name},
                        true,
                        direction,
                    )?
                };
                Ok(quote! {
                    #field_ident: #rhs
                })
            })
            .collect();
        let fields = fields?;

        Ok(quote! {
            {
                #(#fields),*
            }
        })
    }

    /// Generates the constructor for the fields of an unnamed struct.
    fn generate_constructor_fields_unnamed<'a, I: Iterator<Item = &'a Field> + 'a>(
        &self,
        arg_name: &'a str,
        fields: I,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let fields: syn::Result<Vec<TokenStream>> = fields
            .into_iter()
            .enumerate()
            .map(move |(idx, field)| {
                self.generate_constructor_field_unnamed(arg_name, field, idx, direction)
            })
            .collect();
        let fields = fields?;

        Ok(quote! {
            (#(#fields),*)
        })
    }

    /// Generates the constructor for a field of an unnamed struct.
    fn generate_constructor_field_unnamed(
        &self,
        arg_name: &str,
        field: &Field,
        idx: usize,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let arg_ident = Ident::new(arg_name, Span::call_site());
        let idx = Literal::usize_unsuffixed(idx);
        let ty = &field.ty;
        let param = quote! { #arg_ident.#idx };

        if self.is_transparent {
            self.generate_constructor_transparent_rhs(param, direction)
        } else {
            self.generate_constructor_field_rhs(ty, param, false, direction)
        }
    }

    /// Generates the constructor for the fields of an unnamed enum variant.
    fn generate_constructor_enum_variants_unnamed<
        'a,
        I: Iterator<Item = &'a Field> + 'a,
        J: Iterator<Item = Ident>,
    >(
        &self,
        arg_names: J,
        fields: I,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let fields: syn::Result<Vec<TokenStream>> = zip(arg_names, fields)
            .map(move |(arg_name, field)| {
                if self.is_transparent {
                    self.generate_constructor_transparent_rhs(quote! {#arg_name}, direction)
                } else {
                    self.generate_constructor_field_rhs(
                        &field.ty,
                        quote! {#arg_name},
                        true,
                        direction,
                    )
                }
            })
            .collect();
        let fields = fields?;

        Ok(quote! {
            (#(#fields),*)
        })
    }

    /// Generates the rhs part of a field constructor.
    /// For example, in `Self { count: value.count.versionize() }`, this is
    /// `value.count.versionize()`.
    fn generate_constructor_field_rhs(
        &self,
        ty: &Type,
        field_param: TokenStream,
        is_ref: bool, // True if the param is already a reference
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let versionize_trait: Path = parse_const_str(VERSIONIZE_TRAIT_NAME);
        let versionize_owned_trait: Path = parse_const_str(VERSIONIZE_OWNED_TRAIT_NAME);
        let unversionize_trait: Path = parse_const_str(UNVERSIONIZE_TRAIT_NAME);

        let field_constructor = match direction {
            ConversionDirection::OrigToAssociated => {
                match self.kind {
                    AssociatedTypeKind::Ref(_) => {
                        let param = if is_ref {
                            field_param
                        } else {
                            quote! {&#field_param}
                        };

                        quote! {
                            #versionize_trait::versionize(#param)
                        }},
                    AssociatedTypeKind::Owned => quote! {
                        #versionize_owned_trait::versionize_owned(#field_param)
                    },
                }
            }
            ConversionDirection::AssociatedToOrig => match self.kind {
                AssociatedTypeKind::Ref(_) =>
panic!("No conversion should be generated between associated ref type to original type"),
                AssociatedTypeKind::Owned => quote! {
                    <#ty as #unversionize_trait>::unversionize(#field_param)?
                },
            },
        };
        Ok(field_constructor)
    }

    fn generate_constructor_transparent_rhs(
        &self,
        field_param: TokenStream,
        direction: ConversionDirection,
    ) -> syn::Result<TokenStream> {
        let into_trait: Path = parse_const_str(INTO_TRAIT_NAME);
        let try_into_trait: Path = parse_const_str(TRY_INTO_TRAIT_NAME);

        let field_constructor = match direction {
            ConversionDirection::OrigToAssociated => match self.kind {
                AssociatedTypeKind::Ref(_) => {
                    quote! {
                        #into_trait::into(&#field_param)
                    }
                }
                AssociatedTypeKind::Owned => {
                    quote! {
                        #into_trait::into(#field_param)
                    }
                }
            },
            ConversionDirection::AssociatedToOrig => match self.kind {
                AssociatedTypeKind::Ref(_) => {
                    panic!("No conversion should be generated between associated ref type to original type");
                }
                AssociatedTypeKind::Owned => {
                    quote! {
                        #try_into_trait::try_into(#field_param)?
                    }
                }
            },
        };
        Ok(field_constructor)
    }
}

/// Generates a list of argument names. This is used to create a pattern matching of a
/// tuple-like enum variant.
fn generate_args_list(count: usize) -> impl Iterator<Item = Ident> + Clone {
    (0..count).map(|val| format_ident!("value{}", val))
}

/// Checks if the type is a unit type that contains no data
fn is_unit(input: &DeriveInput) -> bool {
    match &input.data {
        Data::Struct(stru) => stru.fields.is_empty(),
        Data::Enum(enu) => enu.variants.iter().all(|variant| variant.fields.is_empty()),
        Data::Union(uni) => uni.fields.named.is_empty(),
    }
}

/// Returns the fields of the input type. This is independent of the kind of type
/// (enum, struct, ...)
fn derive_type_fields(input: &DeriveInput) -> Punctuated<&Field, Comma> {
    match &input.data {
        Data::Struct(stru) => match &stru.fields {
            Fields::Named(fields) => Punctuated::from_iter(fields.named.iter()),
            Fields::Unnamed(fields) => Punctuated::from_iter(fields.unnamed.iter()),
            Fields::Unit => Punctuated::new(),
        },
        Data::Enum(enu) => Punctuated::<&Field, Comma>::from_iter(
            enu.variants
                .iter()
                .filter_map(|variant| match &variant.fields {
                    Fields::Named(fields) => Some(fields.named.iter()),
                    Fields::Unnamed(fields) => Some(fields.unnamed.iter()),
                    Fields::Unit => None,
                })
                .flatten(),
        ),
        Data::Union(uni) => Punctuated::from_iter(uni.fields.named.iter()),
    }
}
