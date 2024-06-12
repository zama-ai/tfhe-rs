//! Set of derive macro to automatically implement the `Versionize` and `Unversionize` traits.
//! The macro defined in this crate are:
//! - `Versionize`: should be derived on the main type that is used in your code
//! - `Version`: should be derived on a previous version of this type
//! - `VersionsDispatch`: should be derived ont the enum that holds all the versions of the type
//! - `NotVersioned`: can be used to implement `Versionize` for a type that is not really versioned

mod associated;
mod dispatch_type;
mod version_type;
mod versionize_attribute;

use dispatch_type::DispatchType;
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{quote, ToTokens};
use syn::parse::Parse;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_quote, DeriveInput, GenericParam, Generics, Ident, Lifetime,
    LifetimeParam, Path, TraitBound, Type, TypeParam, TypeParamBound,
};
use versionize_attribute::VersionizeAttribute;

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
pub(crate) const UNVERSIONIZE_TRAIT_NAME: &str = crate_full_path!("Unversionize");
pub(crate) const VERSIONIZE_VEC_TRAIT_NAME: &str = crate_full_path!("VersionizeVec");
pub(crate) const UNVERSIONIZE_VEC_TRAIT_NAME: &str = crate_full_path!("UnversionizeVec");
pub(crate) const UNVERSIONIZE_ERROR_NAME: &str = crate_full_path!("UnversionizeError");

pub(crate) const SERIALIZE_TRAIT_NAME: &str = "::serde::Serialize";
pub(crate) const DESERIALIZE_TRAIT_NAME: &str = "::serde::Deserialize";
pub(crate) const DESERIALIZE_OWNED_TRAIT_NAME: &str = "::serde::de::DeserializeOwned";

use associated::AssociatingTrait;

use crate::version_type::VersionType;

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
        &[SERIALIZE_TRAIT_NAME, DESERIALIZE_OWNED_TRAIT_NAME],
        &[VERSIONIZE_TRAIT_NAME, UNVERSIONIZE_TRAIT_NAME]
    ));

    let version_types = syn_unwrap!(version_trait.generate_types_declarations());

    let version_impl = syn_unwrap!(version_trait.generate_impl());

    quote! {
        const _: () = {
            #version_types
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
        &[
            VERSIONIZE_TRAIT_NAME,
            VERSIONIZE_VEC_TRAIT_NAME,
            UNVERSIONIZE_TRAIT_NAME,
            UNVERSIONIZE_VEC_TRAIT_NAME,
            SERIALIZE_TRAIT_NAME,
            DESERIALIZE_OWNED_TRAIT_NAME
        ],
        &[]
    ));

    let dispatch_types = syn_unwrap!(dispatch_trait.generate_types_declarations());

    let dispatch_impl = syn_unwrap!(dispatch_trait.generate_impl());

    quote! {
        const _: () = {
            #dispatch_types
            #dispatch_impl
        };
    }
    .into()
}

/// This derives the `Versionize` and `Unversionize` trait for the target type. This macro
/// has a mandatory attribute parameter, which is the name of the versioned enum for this type.
/// This enum can be anywhere in the code but should be in scope.
#[proc_macro_derive(Versionize, attributes(versionize))]
pub fn derive_versionize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let attributes = syn_unwrap!(VersionizeAttribute::parse_from_attributes_list(
        &input.attrs
    ));

    // If we apply a type conversion before the call to versionize, the type that implements
    // the `Version` trait is the target type and not Self
    let version_trait_impl: Option<proc_macro2::TokenStream> = if attributes.needs_conversion() {
        None
    } else {
        Some(impl_version_trait(&input))
    };

    let dispatch_enum_path = attributes.dispatch_enum();
    let dispatch_target = attributes.dispatch_target();
    let input_ident = &input.ident;
    let mut ref_generics = input.generics.clone();
    let mut trait_generics = input.generics.clone();
    let (_, ty_generics, owned_where_clause) = input.generics.split_for_impl();

    // If the original type has some generics, we need to add bounds on them for
    // the impl
    let lifetime = Lifetime::new(LIFETIME_NAME, Span::call_site());
    add_where_lifetime_bound(&mut ref_generics, &lifetime);

    // The versionize method takes a ref. We need to own the input type in the conversion case
    // to apply `From<Input> for Target`. This adds a `Clone` bound to have a better error message
    // if the input type is not Clone.
    if attributes.needs_conversion() {
        syn_unwrap!(add_trait_where_clause(
            &mut trait_generics,
            [&parse_quote! { Self }],
            &["Clone"]
        ));
    };

    let dispatch_generics = if attributes.needs_conversion() {
        None
    } else {
        Some(&ty_generics)
    };

    let dispatch_trait: Path = parse_const_str(DISPATCH_TRAIT_NAME);

    syn_unwrap!(add_trait_where_clause(
        &mut trait_generics,
        [&parse_quote!(#dispatch_enum_path #dispatch_generics)],
        &[format!(
            "{}<{}>",
            DISPATCH_TRAIT_NAME,
            dispatch_target.to_token_stream()
        )]
    ));

    let versionize_trait: Path = parse_const_str(VERSIONIZE_TRAIT_NAME);
    let unversionize_trait: Path = parse_const_str(UNVERSIONIZE_TRAIT_NAME);
    let versionize_vec_trait: Path = parse_const_str(VERSIONIZE_VEC_TRAIT_NAME);
    let unversionize_vec_trait: Path = parse_const_str(UNVERSIONIZE_VEC_TRAIT_NAME);

    let mut versionize_generics = trait_generics.clone();
    for bound in attributes.versionize_bounds() {
        syn_unwrap!(add_type_param_bound(&mut versionize_generics, bound));
    }

    // Add generic bounds specified by the user with the `bound` attribute
    let mut unversionize_generics = trait_generics.clone();
    for bound in attributes.unversionize_bounds() {
        syn_unwrap!(add_type_param_bound(&mut unversionize_generics, bound));
    }

    // Add Generics for the `VersionizeVec` and `UnversionizeVec` traits
    let mut versionize_vec_generics = versionize_generics.clone();
    syn_unwrap!(add_trait_bound(
        &mut versionize_vec_generics,
        VERSIONIZE_TRAIT_NAME
    ));
    let mut unversionize_vec_generics = unversionize_generics.clone();
    syn_unwrap!(add_trait_bound(
        &mut unversionize_vec_generics,
        UNVERSIONIZE_TRAIT_NAME
    ));

    // split generics so they can be used inside the generated code
    let (_, _, ref_where_clause) = ref_generics.split_for_impl();
    let (versionize_impl_generics, _, versionize_where_clause) =
        versionize_generics.split_for_impl();
    let (unversionize_impl_generics, _, unversionize_where_clause) =
        unversionize_generics.split_for_impl();

    let (versionize_vec_impl_generics, _, versionize_vec_where_clause) =
        versionize_vec_generics.split_for_impl();
    let (unversionize_vec_impl_generics, _, unversionize_vec_where_clause) =
        unversionize_vec_generics.split_for_impl();

    // If we want to apply a conversion before the call to versionize we need to use the "owned"
    // alternative of the dispatch enum to be able to store the conversion result.
    let versioned_type_kind = if attributes.needs_conversion() {
        quote! { Owned #owned_where_clause }
    } else {
        quote! { Ref<#lifetime> #ref_where_clause }
    };

    let versionize_body = attributes.versionize_method_body();
    let unversionize_arg_name = Ident::new("versioned", Span::call_site());
    let unversionize_body = attributes.unversionize_method_body(&unversionize_arg_name);
    let unversionize_error: Path = parse_const_str(UNVERSIONIZE_ERROR_NAME);

    quote! {
        #version_trait_impl

        impl #versionize_impl_generics #versionize_trait for #input_ident #ty_generics
        #versionize_where_clause
        {
            type Versioned<#lifetime> =
            <#dispatch_enum_path #dispatch_generics as
            #dispatch_trait<#dispatch_target>>::#versioned_type_kind;

            fn versionize(&self) -> Self::Versioned<'_> {
                #versionize_body
            }

            fn versionize_owned(&self) -> Self::VersionedOwned {
                #versionize_body
            }

        type VersionedOwned =
            <#dispatch_enum_path #dispatch_generics as
            #dispatch_trait<#dispatch_target>>::Owned #owned_where_clause;

        }

        impl #unversionize_impl_generics #unversionize_trait for #input_ident #ty_generics
        #unversionize_where_clause
        {
            fn unversionize(#unversionize_arg_name: Self::VersionedOwned) -> Result<Self, #unversionize_error>  {
                #unversionize_body
            }
        }

        impl #versionize_vec_impl_generics #versionize_vec_trait for #input_ident #ty_generics
        #versionize_vec_where_clause
        {
            type VersionedSlice<#lifetime> = Vec<<Self as #versionize_trait>::Versioned<#lifetime>> #ref_where_clause;

            fn versionize_slice(slice: &[Self]) -> Self::VersionedSlice<'_> {
                slice.iter().map(|val| val.versionize()).collect()
            }

            type VersionedVec = Vec<<Self as #versionize_trait>::VersionedOwned> #owned_where_clause;

            fn versionize_vec(slice: &[Self]) -> Self::VersionedVec {
                slice.iter().map(|val| val.versionize_owned()).collect()
            }
        }

        impl #unversionize_vec_impl_generics #unversionize_vec_trait for #input_ident #ty_generics
        #unversionize_vec_where_clause {
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

    let mut generics = input.generics.clone();
    syn_unwrap!(add_trait_where_clause(
        &mut generics,
        &[parse_quote! { Self }],
        &["Clone"]
    ));

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let input_ident = &input.ident;

    let versionize_trait: Path = parse_const_str(VERSIONIZE_TRAIT_NAME);
    let unversionize_trait: Path = parse_const_str(UNVERSIONIZE_TRAIT_NAME);
    let unversionize_error: Path = parse_const_str(UNVERSIONIZE_ERROR_NAME);
    let lifetime = Lifetime::new(LIFETIME_NAME, Span::call_site());

    quote! {
        impl #impl_generics #versionize_trait for #input_ident #ty_generics #where_clause {
            type Versioned<#lifetime> = &#lifetime Self;
            type VersionedOwned = Self;

            fn versionize(&self) -> Self::Versioned<'_> {
                self
            }

            fn versionize_owned(&self) -> Self::VersionedOwned {
                self.clone()
            }
        }

        impl #impl_generics #unversionize_trait for #input_ident #ty_generics #where_clause {
            fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, #unversionize_error> {
                Ok(versioned)
            }
        }

        impl NotVersioned for #input_ident #ty_generics #where_clause {}

    }
    .into()
}

/// Adds a where clause with a lifetime bound on all the generic types and lifetimes in `generics`
fn add_where_lifetime_bound(generics: &mut Generics, lifetime: &Lifetime) {
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

/// Adds a lifetime bound for all the generic types in `generics`
fn add_lifetime_bound(generics: &mut Generics, lifetime: &Lifetime) {
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

/// Adds a trait bound for `trait_name` on all the generic types in `generics`
fn add_trait_bound(generics: &mut Generics, trait_name: &str) -> syn::Result<()> {
    let trait_bound: TraitBound = parse_trait_bound(trait_name)?;
    for param in generics.type_params_mut() {
        param
            .bounds
            .push(TypeParamBound::Trait(trait_bound.clone()));
    }

    Ok(())
}

fn add_type_param_bound(generics: &mut Generics, type_param_bound: &TypeParam) -> syn::Result<()> {
    for param in generics.type_params_mut() {
        if param.ident == type_param_bound.ident {
            param.bounds.extend(type_param_bound.bounds.clone());
            return Ok(());
        }
    }

    Err(syn::Error::new(
        type_param_bound.span(),
        format!(
            "Bound type {} not found in target type generics",
            type_param_bound.ident
        ),
    ))
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
