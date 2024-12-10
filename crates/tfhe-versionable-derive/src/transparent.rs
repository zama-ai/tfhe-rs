use proc_macro2::Span;
use syn::punctuated::Punctuated;
use syn::{Data, Field, Ident, Token, Type};

/// A transparent struct that is versioned using its inner field
pub(crate) struct TransparentStruct {
    pub(crate) inner_type: Type,
    pub(crate) kind: TransparentStructKind,
}

/// Transparent struct can be either newtypes or regular structs with a single field.
pub(crate) enum TransparentStructKind {
    NewType,
    SingleField(Ident),
}

impl TransparentStruct {
    /// Parse the type declaration to find the target versioned type when the `transparent`
    /// attribute is used.
    pub(crate) fn new(decla: &Data, base_span: Span) -> syn::Result<Self> {
        let error = || {
            syn::Error::new(
                base_span,
                "'transparent' attribute is only supported for single field structs",
            )
        };

        match decla {
            Data::Struct(stru) => match &stru.fields {
                syn::Fields::Named(named_fields) => {
                    Self::from_fields(&named_fields.named).map_err(|_| error())
                }
                syn::Fields::Unnamed(unnamed_fields) => {
                    Self::from_fields(&unnamed_fields.unnamed).map_err(|_| error())
                }
                syn::Fields::Unit => Err(error()),
            },
            Data::Enum(_) => Err(error()),
            Data::Union(_) => Err(error()),
        }
    }

    /// Get the single element inside a transparent struct
    fn from_fields(fields: &Punctuated<Field, Token![,]>) -> Result<Self, ()> {
        if fields.len() != 1 {
            Err(())
        } else {
            let field = fields.first().unwrap();
            let inner_type = field.ty.clone();
            let kind = match &field.ident {
                Some(ident) => TransparentStructKind::SingleField(ident.clone()),
                None => TransparentStructKind::NewType,
            };

            Ok(Self { inner_type, kind })
        }
    }
}
