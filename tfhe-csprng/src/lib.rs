#![deny(rustdoc::broken_intra_doc_links)]
//! Cryptographically secure pseudo random number generator.
//!
//! Welcome to the `tfhe-csprng` documentation.
//!
//! This crate provides a fast cryptographically secure pseudo-random number generator, suited to
//! work in a multithreaded setting.
//!
//! Random Generators
//! =================
//!
//! The central abstraction of this crate is the [`RandomGenerator`](generators::RandomGenerator)
//! trait, which is implemented by different types, each supporting a different platform. In
//! essence, a type implementing [`RandomGenerator`](generators::RandomGenerator) is a type that
//! outputs a new pseudo-random byte at each call to
//! [`next_byte`](generators::RandomGenerator::next_byte). Such a generator `g` can be seen as
//! enclosing a growing index into an imaginary array of pseudo-random bytes:
//! ```ascii
//!   0 1 2 3 4 5 6 7 8 9     M-1     │
//!  ┏━┯━┯━┯━┯━┯━┯━┯━┯━┯━┯━━━┯━┓      │
//!  ┃ │ │ │ │ │ │ │ │ │ │...│ ┃      │
//!  ┗↥┷━┷━┷━┷━┷━┷━┷━┷━┷━┷━━━┷━┛      │
//!   g                               │
//!                                   │
//!   g.next_byte()                   │
//!                                   │
//!   0 1 2 3 4 5 6 7 8 9     M-1     │
//!  ┏━┯━┯━┯━┯━┯━┯━┯━┯━┯━┯━━━┯━┓      │
//!  ┃╳│ │ │ │ │ │ │ │ │ │...│ ┃      │
//!  ┗━┷↥┷━┷━┷━┷━┷━┷━┷━┷━┷━━━┷━┛      │
//!     g                             │
//!                                   │
//!   g.next_byte()                   │  legend:
//!                                   │  -------
//!   0 1 2 3 4 5 6 7 8 9     M-1     │   ↥ : next byte to be outputted by g
//!  ┏━┯━┯━┯━┯━┯━┯━┯━┯━┯━┯━━━┯━┓      │  │ │: byte not yet outputted by g
//!  ┃╳│╳│ │ │ │ │ │ │ │ │...│ ┃      │  │╳│: byte already outputted by g
//!  ┗━┷━┷↥┷━┷━┷━┷━┷━┷━┷━┷━━━┷━┛      │  
//!       g                           🭭
//! ```
//!
//! While being large, this imaginary array is still bounded to M = 2¹³² bytes. Consequently, a
//! generator is always bounded to a maximal index. That is, there is always a max amount of
//! elements of this array that can be outputted by the generator. By default, generators created
//! via [`new`](generators::RandomGenerator::new) are always bounded to M-1.
//!
//! Tree partition of the pseudo-random stream
//! ==========================================
//!
//! One particularity of this implementation is that you can use the
//! [`try_fork`](generators::RandomGenerator::try_fork) method to create an arbitrary partition tree
//! of a region of this array. Indeed, calling `try_fork(nc, nb)` outputs `nc` new generators, each
//! able to output `nb` bytes. The `try_fork` method ensures that the states and bounds of the
//! parent and children generators are set so as to prevent the same substream to be outputted
//! twice:
//! ```ascii
//!   0 1 2 3 4 5 6 7 8 9     M   │   
//!  ┏━┯━┯━┯━┯━┯━┯━┯━┯━┯━┯━━━┯━┓  │  
//!  ┃P│P│P│P│P│P│P│P│P│P│...│P┃  │  
//!  ┗↥┷━┷━┷━┷━┷━┷━┷━┷━┷━┷━━━┷━┛  │  
//!   p                           │  
//!                               │  
//!   (a,b) = p.fork(2,4)         │  
//!                               │
//!   0 1 2 3 4 5 6 7 8 9     M   │
//!  ┏━┯━┯━┯━┯━┯━┯━┯━┯━┯━┯━━━┯━┓  │
//!  ┃A│A│A│A│B│B│B│B│P│P│...│P┃  │
//!  ┗↥┷━┷━┷━┷↥┷━┷━┷━┷↥┷━┷━━━┷━┛  │
//!   a       b       p           │
//!                               │  legend:
//!   (c,d) = b.fork(2, 1)        │  -------
//!                               │   ↥ : next byte to be outputted by p
//!   0 1 2 3 4 5 6 7 8 9     M   │  │P│: byte to be outputted by p
//!  ┏━┯━┯━┯━┯━┯━┯━┯━┯━┯━┯━━━┯━┓  │  │╳│: byte already outputted
//!  ┃A│A│A│A│C│D│B│B│P│P│...│P┃  │  
//!  ┗↥┷━┷━┷━┷↥┷↥┷↥┷━┷↥┷━┷━━━┷━┛  │
//!   a       c d b   p           🭭
//! ```
//!
//! This makes it possible to consume the stream at different places. This is particularly useful in
//! a multithreaded setting, in which we want to use the same generator from different independent
//! threads:
//!
//! ```ascii
//!   0 1 2 3 4 5 6 7 8 9     M   │   
//!  ┏━┯━┯━┯━┯━┯━┯━┯━┯━┯━┯━━━┯━┓  │  
//!  ┃A│A│A│A│C│D│B│B│P│P│...│P┃  │  
//!  ┗↥┷━┷━┷━┷↥┷↥┷↥┷━┷↥┷━┷━━━┷━┛  │  
//!   a       c d b   p           │  
//!                               │  
//!   a.next_byte()               │  
//!                               │
//!   0 1 2 3 4 5 6 7 8 9     M   │
//!  ┏━┯━┯━┯━┯━┯━┯━┯━┯━┯━┯━━━┯━┓  │
//!  ┃╳│A│A│A│C│D│B│B│P│P│...│P┃  │
//!  ┗━┷↥┷━┷━┷↥┷↥┷↥┷━┷↥┷━┷━━━┷━┛  │
//!     a     c d b   p           │
//!                               │  legend:
//!   b.next_byte()               │  -------
//!                               │   ↥ : next byte to be outputted by p
//!   0 1 2 3 4 5 6 7 8 9     M   │  │P│: byte to be outputted by p  
//!  ┏━┯━┯━┯━┯━┯━┯━┯━┯━┯━┯━━━┯━┓  │  │╳│: byte already outputted
//!  ┃╳│A│A│A│C│D│╳│B│P│P│...│P┃  │  
//!  ┗━┷↥┷━┷━┷↥┷↥┷━┷↥┷↥┷━┷━━━┷━┛  │
//!     a     c d   b p           🭭
//! ```
//!
//! Implementation
//! ==============
//!
//! The implementation is based on the AES blockcipher used in counter (CTR) mode, as presented
//! in the ISO/IEC 18033-4 document.
pub mod generators;
pub mod seeders;
