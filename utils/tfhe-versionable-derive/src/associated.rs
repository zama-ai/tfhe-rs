use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{
    parse_quote, DeriveInput, ImplGenerics, Item, ItemImpl, Lifetime, Path, Type, WhereClause,
};

use crate::{
    add_lifetime_bound, add_trait_bound, add_trait_where_clause, add_where_lifetime_bound,
    parse_const_str, DESERIALIZE_TRAIT_NAME, LIFETIME_NAME, SERIALIZE_TRAIT_NAME,
};

/// Generates an impl block for the From trait. This will be:
/// ```
/// impl From<Src> for Dest  {
///    fn from(value: Src) -> Self {
///        ...[constructor]...
///    }
/// }
/// ```
pub(crate) fn generate_from_trait_impl(
    src: &Type,
    dest: &Type,
    impl_generics: &ImplGenerics,
    where_clause: Option<&WhereClause>,
    constructor: &TokenStream,
    from_variable_name: &str,
) -> syn::Result<ItemImpl> {
    let from_variable = Ident::new(from_variable_name, Span::call_site());
    Ok(parse_quote! {
        impl #impl_generics From<#src> for #dest #where_clause {
            fn from(#from_variable: #src) -> Self {
                #constructor
            }
        }
    })
}

/// Generates an impl block for the TryFrom trait. This will be:
/// ```
/// impl TryFrom<Src> for Dest  {
///    type Error = ErrorType;
///    fn from(value: Src) -> Self {
///        ...[constructor]...
///    }
/// }
/// ```
pub(crate) fn generate_try_from_trait_impl(
    src: &Type,
    dest: &Type,
    error: &Type,
    impl_generics: &ImplGenerics,
    where_clause: Option<&WhereClause>,
    constructor: &TokenStream,
    from_variable_name: &str,
) -> syn::Result<ItemImpl> {
    let from_variable = Ident::new(from_variable_name, Span::call_site());
    Ok(parse_quote! {
        impl #impl_generics TryFrom<#src> for #dest #where_clause {
            type Error = #error;
            fn try_from(#from_variable: #src) -> Result<Self, Self::Error> {
                #constructor
            }
        }
    })
}

/// The ownership kind of the data for a associated type.
#[derive(Clone)]
pub(crate) enum AssociatedTypeKind {
    /// This version type use references to non-Copy rust underlying built-in types.
    /// This is used for versioning before serialization. Unit types are considered as ref types
    /// for trait implementations, but they do not hold a lifetime.
    Ref(Option<Lifetime>),
    /// This version type own the non-Copy rust underlying built-in types.
    /// This is used for unversioning after serialization.
    Owned,
}

/// A type that will be generated by the proc macro that are used in the versioning/unversioning
/// process. We use associated types to avoid to rely on generated names. The two associated types
/// used in this proc macro are the [`DispatchType`] and the [`VersionType`].
///
/// To be able have a more efficient versioning, these types actually come in two versions:
/// - A `ref` type, that holds a reference to the underlying data. This is used for faster
///   versioning using only references.
/// - An owned type, that owns the underlying data. This is used for unversioning. The ownership of
///   the data will be transfered during the unversioning process.
///
/// [`DispatchType`]: crate::dispatch_type::DispatchType
/// [`VersionType`]: crate::dispatch_type::VersionType
pub(crate) trait AssociatedType: Sized {
    /// This will create the alternative of the type that holds a reference to the underlying data
    fn new_ref(orig_type: &DeriveInput) -> syn::Result<Self>;
    /// This will create the alternative of the type that owns the underlying data
    fn new_owned(orig_type: &DeriveInput) -> syn::Result<Self>;

    /// Generates the type declaration for this type
    fn generate_type_declaration(&self) -> syn::Result<Item>;

    /// Generates conversion methods between the origin type and the associated type. If the version
    /// type is a ref, the conversion is `From<&'vers OrigType> for Associated<'vers>` because this
    /// conversion is used for versioning. If the version type is owned, the conversion is
    /// `From<XXXAssociatedOwned> for XXX` because the owned type is used for unversioning (where
    /// Associated should be replaced by [`Version`] or [`Dispatch`].
    ///
    /// [`Dispatch`]: crate::dispatch_type::DispatchType
    /// [`Version`]: crate::dispatch_type::VersionType
    fn generate_conversion(&self) -> syn::Result<Vec<ItemImpl>>;

    /// The lifetime added for this type, if it is a "ref" type. It also returns None if the type is
    /// a unit type (no data)
    //fn lifetime(&self) -> Option<&Lifetime>;

    /// The identifier used to name this type
    fn ident(&self) -> Ident;

    /// The lifetime associated with this type, if it is a "ref" type. It can also be None if the
    /// ref type holds no data.
    fn lifetime(&self) -> Option<&Lifetime>;

    /// The types that compose the original type. For example, for a structure, this is the type of
    /// its attributes
    fn inner_types(&self) -> syn::Result<Vec<&Type>>;

    /// If the associating trait that uses this type needs a type parameter, this returns it.
    /// For the `VersionsDispatch` trait this paramter is the name of the currently used version,
    /// which is the latest variant of the dispatch enum. The `Version` trait does not need a
    /// parameter.
    fn as_trait_param(&self) -> Option<syn::Result<&Type>>;
}

#[derive(Clone, Copy)]
pub(crate) enum ConversionDirection {
    OrigToAssociated,
    AssociatedToOrig,
}

/// A trait that is used to hold a category of associated types generated by this proc macro.
/// These traits holds the 2 versions of the associated type, the "ref" one and the "owned" one.
pub(crate) struct AssociatingTrait<T> {
    ref_type: T,
    owned_type: T,
    orig_type: DeriveInput,
    trait_path: Path,
    /// Bounds that should be added to the generics for the impl
    generics_bounds: Vec<String>,
    /// Bounds that should be added on the struct attributes
    attributes_bounds: Vec<String>,
}

impl<T: AssociatedType> AssociatingTrait<T> {
    pub(crate) fn new(
        orig_type: &DeriveInput,
        name: &str,
        generics_bounds: &[&str],
        attributes_bounds: &[&str],
    ) -> syn::Result<Self> {
        let ref_type = T::new_ref(orig_type)?;
        let owned_type = T::new_owned(orig_type)?;
        let trait_path = syn::parse_str(name)?;

        let generics_bounds = generics_bounds
            .iter()
            .map(|bound| bound.to_string())
            .collect();

        let attributes_bounds = attributes_bounds
            .iter()
            .map(|bound| bound.to_string())
            .collect();

        Ok(Self {
            ref_type,
            owned_type,
            orig_type: orig_type.clone(),
            trait_path,
            generics_bounds,
            attributes_bounds,
        })
    }

    /// Generates the impl for the associating trait
    pub(crate) fn generate_impl(&self) -> syn::Result<TokenStream> {
        let orig_ident = &self.orig_type.ident;
        let lifetime = Lifetime::new(LIFETIME_NAME, Span::call_site());

        let ref_ident = self.ref_type.ident();
        let owned_ident = self.owned_type.ident();

        let mut generics = self.orig_type.generics.clone();

        for bound in &self.generics_bounds {
            add_trait_bound(&mut generics, bound)?;
        }

        let trait_param = self.ref_type.as_trait_param().transpose()?;

        let mut ref_type_generics = generics.clone();

        add_trait_where_clause(
            &mut generics,
            self.ref_type.inner_types()?,
            &self.attributes_bounds,
        )?;

        // If the original type has some generics, we need to add a lifetime bound on them
        if let Some(lifetime) = self.ref_type.lifetime() {
            add_lifetime_bound(&mut ref_type_generics, lifetime);
            add_where_lifetime_bound(&mut ref_type_generics, lifetime);
        }

        let (impl_generics, orig_generics, where_clause) = generics.split_for_impl();
        let (_, ref_generics, ref_where_clause) = ref_type_generics.split_for_impl();

        let trait_ident = &self.trait_path;

        Ok(quote! {
            impl #impl_generics #trait_ident<#trait_param> for #orig_ident #orig_generics #where_clause {
                type Ref<#lifetime> = #ref_ident #ref_generics #ref_where_clause;
                type Owned = #owned_ident #orig_generics;
            }
        })
    }

    pub(crate) fn generate_types_declarations(&self) -> syn::Result<TokenStream> {
        let owned_decla = self.owned_type.generate_type_declaration()?;

        let owned_conversion = self.owned_type.generate_conversion()?;

        let serialize_trait: Path = parse_const_str(SERIALIZE_TRAIT_NAME);
        let deserialize_trait: Path = parse_const_str(DESERIALIZE_TRAIT_NAME);

        let ignored_lints = quote! {
        #[allow(
            // We add bounds on the generated code because it will make the compiler
            // generate better errors in case of misuse of the macros. However in some cases
            // this may generate a warning, so we silence it.
            private_bounds,
            // If these lints doesn't trigger on the orginal type, we don't want them to trigger
            // on the generated one
            clippy::upper_case_acronyms,
            clippy::large_enum_variant
        )
        ]};

        let owned_tokens = quote! {
            #[derive(#serialize_trait, #deserialize_trait)]
            #ignored_lints
            #owned_decla

            #(#owned_conversion)*
        };

        let ref_decla = self.ref_type.generate_type_declaration()?;

        let ref_conversion = self.ref_type.generate_conversion()?;

        let ref_tokens = quote! {
            #[derive(#serialize_trait)]
            #ignored_lints
            #ref_decla

            #(#ref_conversion)*
        };

        Ok(quote! {
            #owned_tokens
            #ref_tokens
        })
    }
}