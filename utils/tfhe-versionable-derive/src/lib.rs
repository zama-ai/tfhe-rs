//! Set of derive macro to automatically implement the `Versionize` and `Unversionize` traits.
//! The macro defined in this crate are:
//! - `Versionize`: should be derived on the main type that is used in your code
//! - `Version`: should be derived on a previous version of this type
//! - `VersionsDispatch`: should be derived ont the enum that holds all the versions of the type
//! - `NotVersioned`: can be used to implement `Versionize` for a type that is not really versioned

mod associated;
mod dispatch_type;
mod transparent;
mod version_type;
mod versionize_attribute;
mod versionize_impl;

use dispatch_type::DispatchType;
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{quote, ToTokens};
use syn::parse::Parse;
use syn::punctuated::Punctuated;
use syn::token::Plus;
use syn::{
    parse_macro_input, parse_quote, DeriveInput, GenericParam, Generics, Ident, Lifetime,
    LifetimeParam, Path, TraitBound, TraitBoundModifier, Type, TypeParamBound, WhereClause,
};

/// Adds the full path of the current crate name to avoid name clashes in generated code.
macro_rules! crate_full_path {
    ($trait_name:expr) => {
        concat!("::tfhe_versionable::", $trait_name)
    };
}

pub(crate) const LIFETIME_NAME: &str = "'vers";
pub(crate) const VERSION_TRAIT_NAME: &str = crate_full_path!("Version");
pub(crate) const DISPATCH_TRAIT_NAME: &str = crate_full_path!("VersionsDispatch");
pub(crate) const VERSIONIZE_TRAIT_NAME: &str = crate_full_path!("Versionize");
pub(crate) const VERSIONIZE_OWNED_TRAIT_NAME: &str = crate_full_path!("VersionizeOwned");
pub(crate) const VERSIONIZE_SLICE_TRAIT_NAME: &str = crate_full_path!("VersionizeSlice");
pub(crate) const VERSIONIZE_VEC_TRAIT_NAME: &str = crate_full_path!("VersionizeVec");
pub(crate) const UNVERSIONIZE_TRAIT_NAME: &str = crate_full_path!("Unversionize");
pub(crate) const UNVERSIONIZE_VEC_TRAIT_NAME: &str = crate_full_path!("UnversionizeVec");
pub(crate) const UPGRADE_TRAIT_NAME: &str = crate_full_path!("Upgrade");
pub(crate) const UNVERSIONIZE_ERROR_NAME: &str = crate_full_path!("UnversionizeError");

pub(crate) const SERIALIZE_TRAIT_NAME: &str = "::serde::Serialize";
pub(crate) const DESERIALIZE_TRAIT_NAME: &str = "::serde::Deserialize";
pub(crate) const DESERIALIZE_OWNED_TRAIT_NAME: &str = "::serde::de::DeserializeOwned";
pub(crate) const FROM_TRAIT_NAME: &str = "::core::convert::From";
pub(crate) const TRY_INTO_TRAIT_NAME: &str = "::core::convert::TryInto";
pub(crate) const INTO_TRAIT_NAME: &str = "::core::convert::Into";
pub(crate) const ERROR_TRAIT_NAME: &str = "::core::error::Error";
pub(crate) const SYNC_TRAIT_NAME: &str = "::core::marker::Sync";
pub(crate) const SEND_TRAIT_NAME: &str = "::core::marker::Send";
pub(crate) const STATIC_LIFETIME_NAME: &str = "'static";

use associated::AssociatingTrait;
use versionize_impl::VersionizeImplementor;

use crate::version_type::VersionType;
use crate::versionize_attribute::VersionizeAttribute;

/// unwrap a `syn::Result` by extracting the Ok value or returning from the outer function with
/// a compile error
macro_rules! syn_unwrap {
    ($e:expr) => {
        match $e {
            Ok(res) => res,
            Err(err) => return err.to_compile_error().into(),
        }
    };
}

#[proc_macro_derive(Version)]
/// Implement the `Version` trait for the target type.
pub fn derive_version(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    impl_version_trait(&input).into()
}

/// Actual implementation of the version trait. This will create the ref and owned
/// associated types and use them to implement the trait.
fn impl_version_trait(input: &DeriveInput) -> proc_macro2::TokenStream {
    let version_trait = syn_unwrap!(AssociatingTrait::<VersionType>::new(
        input,
        VERSION_TRAIT_NAME,
    ));

    let version_types = syn_unwrap!(version_trait.generate_types_declarations());

    let version_impl = syn_unwrap!(version_trait.generate_impl());

    quote! {
        const _: () = {
            #version_types

            #[automatically_derived]
            #version_impl
        };
    }
}

/// Implement the `VersionsDispatch` trait for the target type. The type where this macro is
/// applied should be an enum where each variant is a version of the type that we want to
/// versionize.
#[proc_macro_derive(VersionsDispatch)]
pub fn derive_versions_dispatch(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let dispatch_trait = syn_unwrap!(AssociatingTrait::<DispatchType>::new(
        &input,
        DISPATCH_TRAIT_NAME,
    ));

    let dispatch_types = syn_unwrap!(dispatch_trait.generate_types_declarations());

    let dispatch_impl = syn_unwrap!(dispatch_trait.generate_impl());

    quote! {
        const _: () = {
            #dispatch_types

            #[automatically_derived]
            #dispatch_impl
        };
    }
    .into()
}

/// This derives the `Versionize` and `Unversionize` trait for the target type.
///
/// This macro has a mandatory attribute parameter, which is the name of the versioned enum for this
/// type. This enum can be anywhere in the code but should be in scope.
///
/// Example:
/// ```ignore
/// // The structure that should be versioned, as defined in your code
/// #[derive(Versionize)]
/// // We have to link to the enum type that will holds all the versions of this
/// // type. This can also be written `#[versionize(dispatch = MyStructVersions)]`.
/// #[versionize(MyStructVersions)]
/// struct MyStruct<T> {
///     attr: T,
///     builtin: u32,
/// }
///
/// // To avoid polluting your code, the old versions can be defined in another module/file, along with
/// // the dispatch enum
/// #[derive(Version)] // Used to mark an old version of the type
/// struct MyStructV0 {
///     builtin: u32,
/// }
///
/// // The Upgrade trait tells how to go from the first version to the last. During unversioning, the
/// // upgrade method will be called on the deserialized value enough times to go to the last variant.
/// impl<T: Default> Upgrade<MyStruct<T>> for MyStructV0 {
///     type Error = Infallible;
///
///     fn upgrade(self) -> Result<MyStruct<T>, Self::Error> {
///         Ok(MyStruct {
///             attr: T::default(),
///             builtin: self.builtin,
///         })
///     }
/// }
///
/// // This is the dispatch enum, that holds one variant for each version of your type.
/// #[derive(VersionsDispatch)]
/// // This enum is not directly used but serves as a template to generate a new enum that will be
/// // serialized. This allows recursive versioning.
/// #[allow(unused)]
/// enum MyStructVersions<T> {
///     V0(MyStructV0),
///     V1(MyStruct<T>),
/// }
/// ```
#[proc_macro_derive(Versionize, attributes(versionize))]
pub fn derive_versionize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let input_generics = filter_unsized_bounds(&input.generics);

    let attributes = syn_unwrap!(VersionizeAttribute::parse_from_attributes_list(
        &input.attrs
    ));

    let implementor = syn_unwrap!(VersionizeImplementor::new(
        attributes,
        &input.data,
        Span::call_site()
    ));

    // If we apply a type conversion before the call to versionize, the type that implements
    // the `Version` trait is the target type and not Self
    let version_trait_impl: Option<proc_macro2::TokenStream> =
        if implementor.is_directly_versioned() {
            Some(impl_version_trait(&input))
        } else {
            None
        };

    // Parse the name of the traits that we will implement
    let versionize_trait: Path = parse_const_str(VERSIONIZE_TRAIT_NAME);
    let versionize_owned_trait: Path = parse_const_str(VERSIONIZE_OWNED_TRAIT_NAME);
    let unversionize_trait: Path = parse_const_str(UNVERSIONIZE_TRAIT_NAME);
    let versionize_vec_trait: Path = parse_const_str(VERSIONIZE_VEC_TRAIT_NAME);
    let versionize_slice_trait: Path = parse_const_str(VERSIONIZE_SLICE_TRAIT_NAME);
    let unversionize_vec_trait: Path = parse_const_str(UNVERSIONIZE_VEC_TRAIT_NAME);

    let input_ident = &input.ident;
    let lifetime = Lifetime::new(LIFETIME_NAME, Span::call_site());

    // split generics so they can be used inside the generated code
    let (_, ty_generics, _) = input_generics.split_for_impl();

    // Generates the associated types required by the traits
    let versioned_type = implementor.versioned_type(&lifetime, &input_generics);
    let versioned_owned_type = implementor.versioned_owned_type(&input_generics);
    let versioned_type_where_clause =
        implementor.versioned_type_where_clause(&lifetime, &input_generics);
    let versioned_owned_type_where_clause =
        implementor.versioned_owned_type_where_clause(&input_generics);

    // If the original type has some generics, we need to add bounds on them for
    // the traits impl
    let versionize_trait_where_clause =
        syn_unwrap!(implementor.versionize_trait_where_clause(&input_generics));
    let versionize_owned_trait_where_clause =
        syn_unwrap!(implementor.versionize_owned_trait_where_clause(&input_generics));
    let unversionize_trait_where_clause =
        syn_unwrap!(implementor.unversionize_trait_where_clause(&input_generics));

    let trait_impl_generics = input_generics.split_for_impl().0;

    let versionize_body = implementor.versionize_method_body();
    let versionize_owned_body = implementor.versionize_owned_method_body();
    let unversionize_arg_name = Ident::new("versioned", Span::call_site());
    let unversionize_body = implementor.unversionize_method_body(&unversionize_arg_name);
    let unversionize_error: Path = parse_const_str(UNVERSIONIZE_ERROR_NAME);

    quote! {
        #version_trait_impl

        #[automatically_derived]
        impl #trait_impl_generics #versionize_trait for #input_ident #ty_generics
        #versionize_trait_where_clause
        {
            type Versioned<#lifetime> = #versioned_type #versioned_type_where_clause;

            fn versionize(&self) -> Self::Versioned<'_> {
                #versionize_body
            }
        }

        #[automatically_derived]
        impl #trait_impl_generics #versionize_owned_trait for #input_ident #ty_generics
        #versionize_owned_trait_where_clause
        {
            type VersionedOwned = #versioned_owned_type #versioned_owned_type_where_clause;

            fn versionize_owned(self) -> Self::VersionedOwned {
                #versionize_owned_body
            }
        }

        #[automatically_derived]
        impl #trait_impl_generics #unversionize_trait for #input_ident #ty_generics
        #unversionize_trait_where_clause
        {
            fn unversionize(#unversionize_arg_name: Self::VersionedOwned) -> Result<Self, #unversionize_error>  {
                #unversionize_body
            }
        }

        #[automatically_derived]
        impl #trait_impl_generics #versionize_slice_trait for #input_ident #ty_generics
        #versionize_trait_where_clause
        {
            type VersionedSlice<#lifetime> = Vec<<Self as #versionize_trait>::Versioned<#lifetime>> #versioned_type_where_clause;

            fn versionize_slice(slice: &[Self]) -> Self::VersionedSlice<'_> {
                slice.iter().map(|val| #versionize_trait::versionize(val)).collect()
            }
        }

        #[automatically_derived]
        impl #trait_impl_generics #versionize_vec_trait for #input_ident #ty_generics
        #versionize_owned_trait_where_clause
        {

            type VersionedVec = Vec<<Self as #versionize_owned_trait>::VersionedOwned> #versioned_owned_type_where_clause;

            fn versionize_vec(vec: Vec<Self>) -> Self::VersionedVec {
                vec.into_iter().map(|val| #versionize_owned_trait::versionize_owned(val)).collect()
            }
        }

        #[automatically_derived]
        impl #trait_impl_generics #unversionize_vec_trait for #input_ident #ty_generics
        #unversionize_trait_where_clause
        {
            fn unversionize_vec(versioned: Self::VersionedVec) -> Result<Vec<Self>, #unversionize_error> {
                versioned
                .into_iter()
                .map(|versioned| <Self as #unversionize_trait>::unversionize(versioned))
                .collect()
            }
        }
    }
    .into()
}

/// This derives the `Versionize` and `Unversionize` trait for a type that should not
/// be versioned. The `versionize` method will simply return self
#[proc_macro_derive(NotVersioned)]
pub fn derive_not_versioned(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    // Versionize needs T to impl Serialize
    let mut versionize_generics = input.generics.clone();
    syn_unwrap!(add_trait_where_clause(
        &mut versionize_generics,
        &[parse_quote! { Self }],
        &[SERIALIZE_TRAIT_NAME]
    ));

    // VersionizeOwned needs T to impl Serialize and DeserializeOwned
    let mut versionize_owned_generics = input.generics.clone();
    syn_unwrap!(add_trait_where_clause(
        &mut versionize_owned_generics,
        &[parse_quote! { Self }],
        &[SERIALIZE_TRAIT_NAME, DESERIALIZE_OWNED_TRAIT_NAME]
    ));

    let (impl_generics, ty_generics, versionize_where_clause) =
        versionize_generics.split_for_impl();
    let (_, _, versionize_owned_where_clause) = versionize_owned_generics.split_for_impl();

    let input_ident = &input.ident;

    let versionize_trait: Path = parse_const_str(VERSIONIZE_TRAIT_NAME);
    let versionize_owned_trait: Path = parse_const_str(VERSIONIZE_OWNED_TRAIT_NAME);
    let unversionize_trait: Path = parse_const_str(UNVERSIONIZE_TRAIT_NAME);
    let unversionize_error: Path = parse_const_str(UNVERSIONIZE_ERROR_NAME);
    let lifetime = Lifetime::new(LIFETIME_NAME, Span::call_site());

    quote! {
        #[automatically_derived]
        impl #impl_generics #versionize_trait for #input_ident #ty_generics #versionize_where_clause {
            type Versioned<#lifetime> = &#lifetime Self where Self: 'vers;

            fn versionize(&self) -> Self::Versioned<'_> {
                self
            }
        }

        #[automatically_derived]
        impl #impl_generics #versionize_owned_trait for #input_ident #ty_generics #versionize_owned_where_clause {
            type VersionedOwned = Self;

            fn versionize_owned(self) -> Self::VersionedOwned {
                self
            }
        }

        #[automatically_derived]
        impl #impl_generics #unversionize_trait for #input_ident #ty_generics #versionize_owned_where_clause {
            fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, #unversionize_error> {
                Ok(versioned)
            }
        }

        #[automatically_derived]
        impl #impl_generics NotVersioned for #input_ident #ty_generics #versionize_owned_where_clause {}

    }
    .into()
}

/// Adds a where clause with a lifetime bound on all the generic types and lifetimes in `generics`
fn add_where_lifetime_bound_to_generics(generics: &mut Generics, lifetime: &Lifetime) {
    let mut params = Vec::new();
    for param in generics.params.iter() {
        let param_ident = match param {
            GenericParam::Lifetime(generic_lifetime) => {
                if generic_lifetime.lifetime.ident == lifetime.ident {
                    continue;
                }
                &generic_lifetime.lifetime.ident
            }
            GenericParam::Type(generic_type) => &generic_type.ident,
            GenericParam::Const(_) => continue,
        };
        params.push(param_ident.clone());
    }

    for param in params.iter() {
        generics
            .make_where_clause()
            .predicates
            .push(parse_quote! { #param: #lifetime  });
    }
}

/// Adds a new lifetime param with a bound for all the generic types in `generics`
fn add_lifetime_param(generics: &mut Generics, lifetime: &Lifetime) {
    generics
        .params
        .push(GenericParam::Lifetime(LifetimeParam::new(lifetime.clone())));
    for param in generics.type_params_mut() {
        param
            .bounds
            .push(TypeParamBound::Lifetime(lifetime.clone()));
    }
}

/// Parse the input str trait bound
fn parse_trait_bound(trait_name: &str) -> syn::Result<TraitBound> {
    let trait_path: Path = syn::parse_str(trait_name)?;
    Ok(parse_quote!(#trait_path))
}

/// Adds a "where clause" bound for all the input types with all the input traits
fn add_trait_where_clause<'a, S: AsRef<str>, I: IntoIterator<Item = &'a Type>>(
    generics: &mut Generics,
    types: I,
    traits_name: &[S],
) -> syn::Result<()> {
    let preds = &mut generics.make_where_clause().predicates;

    if !traits_name.is_empty() {
        let bounds: Vec<TraitBound> = traits_name
            .iter()
            .map(|bound_name| parse_trait_bound(bound_name.as_ref()))
            .collect::<syn::Result<_>>()?;
        for ty in types {
            preds.push(parse_quote! { #ty: #(#bounds)+*  });
        }
    }

    Ok(())
}

/// Adds a "where clause" bound for all the input types with all the input lifetimes
fn add_lifetime_where_clause<'a, S: AsRef<str>, I: IntoIterator<Item = &'a Type>>(
    generics: &mut Generics,
    types: I,
    lifetimes: &[S],
) -> syn::Result<()> {
    let preds = &mut generics.make_where_clause().predicates;

    if !lifetimes.is_empty() {
        let bounds: Vec<Lifetime> = lifetimes
            .iter()
            .map(|lifetime| syn::parse_str(lifetime.as_ref()))
            .collect::<syn::Result<_>>()?;
        for ty in types {
            preds.push(parse_quote! { #ty: #(#bounds)+*  });
        }
    }

    Ok(())
}

/// Extends a where clause with predicates from another one, filtering duplicates
fn extend_where_clause(base_clause: &mut WhereClause, extension_clause: &WhereClause) {
    for extend_predicate in &extension_clause.predicates {
        if base_clause.predicates.iter().all(|base_predicate| {
            base_predicate.to_token_stream().to_string()
                != extend_predicate.to_token_stream().to_string()
        }) {
            base_clause.predicates.push(extend_predicate.clone());
        }
    }
}

/// Creates a Result [`syn::punctuated::Punctuated`] from an iterator of Results
fn punctuated_from_iter_result<T, P: Default, I: IntoIterator<Item = syn::Result<T>>>(
    iter: I,
) -> syn::Result<Punctuated<T, P>> {
    let mut ret = Punctuated::new();
    for value in iter {
        ret.push(value?)
    }
    Ok(ret)
}

/// Like [`syn::parse_str`] for inputs that are known at compile time to be valid
fn parse_const_str<T: Parse>(s: &'static str) -> T {
    syn::parse_str(s).expect("Parsing of const string should not fail")
}

/// Remove the '?Sized' bounds from the generics
///
/// The VersionDispatch trait requires that the versioned type is Sized so we have to remove this
/// bound. It means that for a type `MyStruct<T: ?Sized>`, we will only be able to call
/// `.versionize()` when T is Sized.
fn filter_unsized_bounds(generics: &Generics) -> Generics {
    let mut generics = generics.clone();

    for param in generics.type_params_mut() {
        param.bounds = remove_unsized_bound(&param.bounds);
    }

    if let Some(clause) = &mut generics.where_clause {
        for pred in &mut clause.predicates {
            match pred {
                syn::WherePredicate::Lifetime(_) => {}
                syn::WherePredicate::Type(type_predicate) => {
                    type_predicate.bounds = remove_unsized_bound(&type_predicate.bounds);
                }
                _ => {}
            }
        }
    }

    generics
}

/// Filter the ?Sized bound in a list of bounds
fn remove_unsized_bound(
    bounds: &Punctuated<TypeParamBound, Plus>,
) -> Punctuated<TypeParamBound, Plus> {
    bounds
        .iter()
        .filter(|bound| match bound {
            TypeParamBound::Trait(trait_bound) => {
                if !matches!(trait_bound.modifier, TraitBoundModifier::None) {
                    if let Some(segment) = trait_bound.path.segments.iter().next_back() {
                        if segment.ident == "Sized" {
                            return false;
                        }
                    }
                }
                true
            }
            TypeParamBound::Lifetime(_) => true,
            TypeParamBound::Verbatim(_) => true,
            _ => true,
        })
        .cloned()
        .collect()
}
