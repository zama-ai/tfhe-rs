#[cfg(any(feature = "boolean", feature = "shortint", feature = "integer"))]
macro_rules! define_key_structs {
    (
        $base_struct_name:ident {
            $(
                $name:ident: $base_ty_name:ident
            ),*
            $(,)?
        }
    ) => {

        ::paste::paste!{
            $(
                use super::types::static_::{
                    [<$base_ty_name Parameters>],
                    [<$base_ty_name ClientKey>],
                    [<$base_ty_name PublicKey>],
                    [<$base_ty_name CompressedPublicKey>],
                    [<$base_ty_name ServerKey>],
                    [<$base_ty_name CompressedServerKey>],
                };
            )*

            ///////////////////////
            // Config
            ///////////////////////
            #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
            pub(crate) struct [<$base_struct_name Config>] {
                $(
                    pub(crate) [<$name _params>]: Option<[<$base_ty_name Parameters>]>,
                )*
            }

            impl [<$base_struct_name Config>] {
                pub(crate) fn all_default() -> Self {
                    Self {
                        $(
                            [<$name _params>]: Some(Default::default()),
                        )*
                    }
                }

                pub(crate) fn all_none() -> Self {
                    Self {
                        $(
                            [<$name _params>]: None,
                        )*
                    }
                }
            }

            ///////////////////////
            // Client Key
            ///////////////////////
            #[derive(Clone, Debug, ::serde::Deserialize, ::serde::Serialize)]
            pub(crate) struct [<$base_struct_name ClientKey>] {
                $(
                    pub(super) [<$name _key>]: Option<[<$base_ty_name ClientKey>]>,
                    pub(super) [<$name _params>]: Option<[<$base_ty_name Parameters>]>,
                )*
            }

            impl [<$base_struct_name ClientKey>] {
                pub(crate) fn with_seed(
                    config: [<$base_struct_name Config>],
                    seed: ::concrete_csprng::seeders::Seed
                ) -> Self {
                    Self {
                        $(
                            [<$name _params>]: None,
                            [<$name _key>]: config
                                .[<$name _params>]
                                .map(|params| {
                                    <[<$base_ty_name ClientKey>]>::with_seed(params, seed)
                                }),
                        )*
                    }
                }
            }

            impl From<[<$base_struct_name Config>]> for [<$base_struct_name ClientKey>] {
                fn from(config: [<$base_struct_name Config>]) -> Self {
                    Self {
                        $(
                            [<$name _params>]: None,
                            [<$name _key>]: config.[<$name _params>].map(<[<$base_ty_name ClientKey>]>::from),
                        )*
                    }
                }
            }

            ///////////////////////
            // Public Key
            ///////////////////////
            #[derive(Clone, Debug, ::serde::Deserialize, ::serde::Serialize)]
            pub(crate) struct [<$base_struct_name PublicKey>] {
                $(
                    pub(super) [<$name _key>]: Option<[<$base_ty_name PublicKey>]>,
                )*
            }

            impl [<$base_struct_name PublicKey>] {
                pub(crate) fn new(client_key: &[<$base_struct_name ClientKey>]) -> Self {
                    Self {
                        $(
                            [<$name _key>]: client_key
                                .[<$name _key>]
                                .as_ref()
                                .map(<[<$base_ty_name PublicKey>]>::new),
                        )*
                    }
                }
            }

            ///////////////////////
            // Compressed Public Key
            ///////////////////////
            #[derive(Clone, Debug, ::serde::Deserialize, ::serde::Serialize)]
            pub(crate) struct [<$base_struct_name CompressedPublicKey>] {
                $(
                    pub(super) [<$name _key>]: Option<[<$base_ty_name CompressedPublicKey>]>,
                )*
            }

            impl [<$base_struct_name CompressedPublicKey>] {
                pub(crate) fn new(client_key: &[<$base_struct_name ClientKey>]) -> Self {
                    Self {
                        $(
                            [<$name _key>]: client_key
                                .[<$name _key>]
                                .as_ref()
                                .map(<[<$base_ty_name CompressedPublicKey>]>::new),
                        )*
                    }
                }

                pub(crate) fn decompress(self) -> [<$base_struct_name PublicKey>] {
                    [<$base_struct_name PublicKey>] {
                        $(
                            [<$name _key>]: self.[<$name _key>]
                                .map(|key| key.decompress()),
                        )*
                    }
                }
            }

            ///////////////////////
            // Server Key
            ///////////////////////
            #[derive(Clone, ::serde::Deserialize, ::serde::Serialize)]
            pub(crate) struct [<$base_struct_name ServerKey>] {
                $(
                    pub(super) [<$name _key>]: Option<[<$base_ty_name ServerKey>]>,
                )*
            }

            impl [<$base_struct_name ServerKey>] {
                pub(crate) fn new(client_key: &[<$base_struct_name ClientKey>]) -> Self {
                    Self {
                        $(
                            [<$name _key>]: client_key.[<$name _key>].as_ref().map(<[<$base_ty_name ServerKey>]>::new),
                        )*
                    }
                }
            }

            impl Default for [<$base_struct_name ServerKey>] {
                fn default() -> Self {
                    Self {
                        $(
                            [<$name _key>]: None,
                        )*
                    }
                }
            }

            /////////////////////////
            // Compressed Server Key
            /////////////////////////
            #[derive(Clone, ::serde::Deserialize, ::serde::Serialize)]
            pub(crate) struct [<$base_struct_name CompressedServerKey>] {
                $(
                    pub(super) [<$name _key>]: Option<[<$base_ty_name CompressedServerKey>]>,
                )*
            }

            impl [<$base_struct_name CompressedServerKey>] {
                pub(crate) fn new(client_key: &[<$base_struct_name ClientKey>]) -> Self {
                    Self {
                        $(
                            [<$name _key>]: client_key.[<$name _key>].as_ref().map(<[<$base_ty_name CompressedServerKey>]>::new),
                        )*
                    }
                }

                pub(crate) fn decompress(self) -> [<$base_struct_name ServerKey>] {
                    [<$base_struct_name ServerKey>] {
                        $(
                            [<$name _key>]: self.[<$name _key>].map(|compressed_key| compressed_key.decompress()),
                        )*
                    }
                }
            }

            impl Default for [<$base_struct_name CompressedServerKey>] {
                fn default() -> Self {
                    Self {
                        $(
                            [<$name _key>]: None,
                        )*
                    }
                }
            }

        }
    }
}
