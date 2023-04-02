Internally the regex engine works on a vector of encrypted content characters
(ie each content's character is encrypted individually). As a consequence this
does mean that at least some information about the content is leaked to the
party that is applying the regex pattern: the length of the content.

It parses the pattern, then generates lazily (in the sense of not yet executing
any homomorphic operations) the list of potential homomorphic circuits that
must each be ran exhaustively. The list is lazily generated, so as to exclude
any pattern that is provably going to result in a false result from being
homomorphically executed. For example, consider an application of `/^a+b$/` on
content `acb`, then any pattern that doesn't start from the first content
character and any pattern that does not end at the final content character can
immediately be discarded. In this example it'd mean that we would only end up
executing the homomorphic circuit generated to test for `aab`. Finally, each
executed variant is then joined together with homomorphic `bitor` operations
to reach a single result.

Each homomorphic operation is expensive, and so to limit any double work there
is a cache maintained. For example, `/^a?ab/` will generate multiple circuit
variants where `a` is homomorphically compared to a same content's character.
The cache prevents any such recomputations from being actually recomputed; we
already know the answer.
