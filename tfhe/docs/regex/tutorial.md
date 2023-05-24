# FHE Regex Pattern Matching Tutorial

This tutorial explains how to build a Regex pattern matching engine where the
content that is matched against is ciphertext.

A regex Pattern Matching Engine (PME) is an essential tool for programmers. It
allows to perform complex searches on a content. The less powerful simple
search on string can only find matches of the exact given sequence of
characters (eg, your Browser's default search function does this). Regex PME
are more powerful, it allows to search on certain structures of text (where a
structure may take form in multiple possible sequences of characters). The
structure to be searched for is defined with the regex, a very concise
language. Here are some example regexes to give some idea of what is possible:

Regex | Semantics
--- | ---
/abc/ | Searches for the sequence `abc` (equivalent to the simple text search)
/^abc/ | Searches for the sequence `abc` at the beginning of the content
/a?bc/ | Searches for sequences `abc`, `bc`
/ab\|c+d/ | Searches for sequences of `ab`, `c` repeated 1 or more times followed by `d`

Regexes are powerful enough to be able to express structures like email address
formats. Capability like this is what makes regexes useful for many programming
solutions.

There are two main components identifiable in a PME:
1. the pattern that is to be matched has to be parsed, this translates from a
   textual representation into a recursively structured object (an Abstract
   Syntax Tree, or AST)
2. this AST has to then be applied to the text that is to be matched against,
   resulting in a yes or no to whether the pattern matched (and in the case of
   our FHE implementation, this result is an encrypted yes or an encrypted no)

Parsing is a well understood problem. There are a couple of different
approaches possible here.  Regardless of the approach chosen, it starts with
figuring out what the language is that we want to support. That is, what are
the kinds of sentences that we want our regex language to include?  A few
example sentences we definitely want to support are for example: `/a/`,
`/a?bc/`, `/^ab$/`, `/ab|cd/`, however example sentences don't suffice here as
a specification because they can never be exhaustive (they're endless). We need
something to specify _exactly_ the full set of sentences our language supports.
There exists a language that can help us describe exactly what our own
language's structure is: Grammars.

## The Grammar and Datastructure

It is useful to start with defining the Grammar before starting to write
the code for the parser. Because the code structure follows directly from the
Grammar. A Grammar consists of a (generally small) set of rules. For example,
a very basic Grammar could look like this:
```
Start := 'a'
```
this describes a language that only contains the sentence "a". Not a very interesting language.

We can make it more interesting though by introducing choice into the grammar
with \| (called a 'pipe') operators. If we want the above grammar to accept
either "a" or "b":
```
Start := 'a' | 'b'
```

So far only Grammars with a single rule have been shown. However, a Grammar can
consist of multiple rules. And in fact, most languages require to be defined
over multiple rules. Lets consider a more meaningful language, one that accepts
sentences consisting of one or more digits, we could describe such a language
with the following Grammar:
```
Start := Digit+

Digit := '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9'
```

The `+` above after `Digit` is another Grammar operator. With it we specify that
Digit must be matched 1 or more times. Here are all the Grammar operators that
are relevant for this tutorial:

Operator | Example | Semantics
--- | --- | ---
`\|` | a \| b | we first try matching on a, on no match we try to match on b
`+` | a+ | match a 1 or more times
`*` | a* | match a any amount of times (including zero times)
`?` | a? | optionally match a (match 0 or 1 time)
`.` | .  | match any character
`..` | a .. b | match on a range of alphabetically ordered characters from a to (and including) b
` ` | a b | sequencing; match on a and then on b

In the case of the example PME the grammar is as follows (notice the unquoted ? and quoted ? etc., the unquoted are Grammar operators and the quoted are characters we are matching in the parsing)
```
Start := '/' '^'? Regex '$'? '/' Modifier?

Regex := Term '|' Term
       | Term

Term := Factor*

Factor := Atom '?'
        | Repeated
        | Atom

Repeated := Atom '*'
          | Atom '+'
          | Atom '{' Digit* ','? '}'
          | Atom '{' Digit+ ',' Digit* '}'

Atom := '.'
      | '\' .
      | Character
      | '[' Range ']'
      | '(' Regex ')'

Range := '^' Range
       | AlphaNum '-' AlphaNum
       | AlphaNum+

Digit := '0' .. '9'

Character := AlphaNum
           | '&' | ';' | ':' | ',' | '`' | '~' | '-' | '_' | '!' | '@' | '#' | '%' | '\'' | '\"'

AlphaNum := 'a' .. 'z'
          | 'A' .. 'Z'
          | '0' .. '9'

Modifier := 'i'
```
Below will refer occasionally to specific parts in the Grammar above by \<rule name\>.\<variant index\> (where the first rule variant has index 1).

With the Grammar defined, we can start defining a type to parse into. In Rust we
have the `enum` kind of type that is perfect for this, as it allows to define
multiple variants that may recurse. I prefer to start by defining variants that
do not recurse (ie that don't contain nested regex expressions):
```rust
enum RegExpr {
    Char { c: char },  // matching against a single character (Atom.2 and Atom.3)
    AnyChar,  // matching _any_ character (Atom.1)
    SOF,  // matching only at the beginning of the content ('^' in Start.1)
    EOF,  // matching only at the end of the content (the '$' in Start.1)
    Range { cs: Vec<char> },  // matching on a list of characters (Range.3, eg '[acd]')
    Between { from: char, to: char },  // matching between 2 characters based on ascii ordering (Range.2, eg '[a-g]')
}
```

With this we would already be able to translate the following basic regexes:

Pattern | RegExpr value
--- | ---
`/a/` | `RegExpr::Char { c: 'a' }`
`/\\^/` | `RegExpr::Char { c: '^' }`
`/./` | `RegExpr::AnyChar`
`/^/` | `RegExpr::SOF`
`/$/` | `RegExpr::EOF`
`/[acd]/` | `RegExpr::Range { vec!['a', 'c', 'd'] }`
`/[a-g]/` | `RegExpr::Between { from: 'a', to: 'g' }`

Notice we're not yet able to sequence multiple components together. Lets define
the first variant that captures recursive RegExpr for this:
```rust
enum RegExpr {
    ...
    Seq { re_xs: Vec<RegExpr> },  // matching sequences of RegExpr components (Term.1)
}
```
With this Seq (short for sequence) variant we allow translating patterns that
contain multiple components:

Pattern | RegExpr value
--- | ---
`/ab/` | `RegExpr::Seq { re_xs: vec![RegExpr::Char { c: 'a' }, RegExpr::Char { c: 'b' }] }`
`/^a.$/` | `RegExpr::Seq { re_xs: vec![RegExpr::SOF, RexExpr::Char { 'a' }, RegExpr::AnyChar, RegExpr::EOF] }`
`/a[f-l]/` | `RegExpr::Seq { re_xs: vec![RegExpr::Char { c: 'a' }, RegExpr::Between { from: 'f', to: 'l' }] }`

Lets finish the RegExpr datastructure by adding variants for optional matching,
the not logic in a range, and the either left or right matching:
```rust
enum RegExpr {
    ...
    Optional { opt_re: Box<RegExpr> },  // matching optionally (Factor.1)
    Not { not_re: Box<RegExpr> },  // matching inversely on a range (Range.1)
    Either { l_re: Box<RegExpr>, r_re: Box<RegExpr> },  // matching the left or right regex (Regex.1)
}
```

Some features may make most sense to be implemented through post processing of
the parsed datastructure. For example, the case insensitivity feature (the `i`
Modifier) is implemented in the example implementation by taking the parsed
RegExpr, and mutating every character mentioned inside to cover both the lower
case as well as the upper case variant (see function `case_insensitive` in
`parser.rs` for the example implementation of this).

The modifier `i` in our Grammar (for enabling case insensitivity) seemed easiest
to implement by applying a post processing step to the parser.

We are now able to translate any complex regex into a RegExpr value. For example:

Pattern | RegExpr value
--- | ---
`/a?/` | `RegExpr::Optional { opt_re: Box::new(RegExpr::Char { c: 'a' }) }`
`/[a-d]?/` | `RegExpr::Optional { opt_re: Box::new(RegExpr::Between { from: 'a', to: 'd' }) }`
`/[^ab]/` | `RegExpr::Not { not_re: Box::new(RegExpr::Range { cs: vec!['a', 'b'] }) }`
`/av\|d?/` | `RegExpr::Either { l_re: Box::new(RegExpr::Seq { re_xs: vec![RegExpr::Char { c: 'a' }, RegExpr::Char { c: 'v' }] }), r_re: Box::new(RegExpr::Optional { opt_re: Box::new(RegExpr::Char { c: 'd' }) }) }`
`/(av\|d)?/` | `RegExpr::Optional { opt_re: Box::new(RegExpr::Either { l_re: Box::new(RegExpr::Seq { re_xs: vec![RegExpr::Char { c: 'a' }, RegExpr::Char { c: 'v' }] }), r_re: Box::new(RegExpr::Char { c: 'd' }) }) }`

With both the Grammar and the datastructure to parse into defined, we can now
start implementing the actual parsing logic. There are multiple ways this can
be done. For example there exist tools that can automatically generate parser
code by giving it the Grammar definition (these are called parser generators).
However, I prefer to write parsers myself with a parser combinator library.
Because, in my opinion the behavior in runtime is better understandable of
parsers constructed with a parser combinator library than of parsers that were
generated with a parser generator tool.

In Rust there exist a number of popular parser combinator libraries, I went
with `combine` but any other would work just as well. Choose whichever appeals
the most to you (including any parser generator tool). The implementation of
our regex parser will differ significantly depending on the approach you choose
and as such I think it is better to omit this part from the tutorial. You may
look at the parser code in the example implementation to get an idea on how
this could be done. In general though the Grammar and the datastructure are
the important components, the parser code follows directly from these.

## Matching the RegExpr to Encrypted Content

The next challenge is to build the execution engine, where we take a RegExpr
value and recurse into it to apply the necessary actions on the encrypted
content. We first have to define how we actually encode our content into an
encrypted state.  Once that is defined we can start working on how we will
execute our RegExpr onto the encrypted content.

### Encoding and Encrypting the Content

It is not possible to encrypt the entire content into a single encrypted value,
we can only encrypt numbers and do operations on those encrypted numbers with
FHE. Therefore we have to find a scheme where we encode the content into a
sequence of numbers that then are encrypted individually, to form a sequence of
encrypted numbers.

I saw two strategies (though there may be additional, potentially better,
ways):
1. map each character of the content into the u8 ascii value, and then encrypt
   each bit of these u8 values individually.
2. instead of encrypting each bit individually, encrypt each u8 ascii value in
   its entirety.

Even though strategy 1 would require more highlevel TFHE-rs operations to check
for even a simple characther match (we have to check each bit individually for
equality, as opposed to checking the entire byte in 1 highlevel TFHE-rs
operation), some experimentation did show that these options both performed
relatively equally well on a regex like `/a/`. I suppose this is because
bitwise FHE operations are relatively cheap compared to u8 FHE operations.
However, option 1 falls apart as soon as you introduce the '[a-z]' regex logic.
Because with option 2, it's possible to complete this match with just 3 TFHE-rs
operations:
```rust
// note: this is pseudocode
c       = <the encrypted character under inspection>;
sk      = <the server key, aka the public key>

ge_from = sk.ge(c, 'a');
le_to   = sk.le(c, 'z');
result  = sk.bitand(ge_from, le_to);
```
`ge`, `le`, and `bitand` are the 3 cryptographic operations here.

If on the other hand we had encrypted the content with the first strategy,
there would be no way to test for `greater/equal than from` and `less/equal
than to`. We'd have to check for potential equality of each character between
`from` and `to`, and then join the results together with a sequence of
`sk.bitor`; way more cryptographic operations than in strategy 2.

Because FHE operations are computationally expensive, and strategy 1 requires
significantly more FHE operations for matching on `[a-z]` regex logic, we
should opt for strategy 2.

### Matching with the AST Versus Matching with a derived DFA

There are a lot of regex pattern matching engines. It's been built many times
and it's been researched thoroughly. There are different strategies possible
here. A straight forward strategy is to directly recurse into our RegExpr
value and apply the necessary matching operations onto the content. In a way
this is nice, because it allows us to link the RegExpr structure directly to
the matching semantics. Resulting in code that is easier to
understand/maintain/etc.

Alternatively, there exists an algorithm that transforms the AST (ie the
RegExpr in our case) into a Deterministic Finite Automata (DFA). Normally this
is a favorable approach in terms of efficiency, because the derived DFA can be
walked over without needing to backtrack (whereas the former strategy cannot
prevent backtracking). This means that the content can be walked over from
character to character, and depending on what the character exactly is at this
cursor, the DFA is conjuctively traveled in a definite direction which
ultimately leads us to the `yes, there is a match` or the `no, there is no
match`. There is a small upfront cost of having to translate the AST into the
DFA, but the lack of backtracking during the matching generally makes up for
this (especially if the content that is matched against is significantly big).

In our case though we are matching on encrypted content. We have no way to know
what the character at our cursor is, and therefore no way to find this definite
direction to go forward to in the DFA. Therefore, I don't think that
translating the AST into the DFA helps us the way it does in normal regex
pattern matching engines. And for this reason I opted for the former strategy,
because it allows for matching logic that is easier to understand.

### Matching

In the previous section we decided we'll match by traversing into the RegExpr
value. This section will explain exactly how to do that. Similarly to defining
the Grammar, I find it is best to start with working out the non recursive
RegExpr variants.

We'll start by defining the function that will recursively traverse into the RegExpr value:
```rust

type StringCiphertext = Vec<RadixCiphertextBig>;
type ResultCiphertext = RadixCiphertextBig;

fn match(
    sk: &ServerKey,
    content: &StringCipherText,
    re: &RegExpr,
    content_pos: usize,
) -> Vec<(ResultCiphertext, usize)> {
    let content_char = &content[c_pos];
    match re {
        ...
    }
}
```

`sk` is the server key (aka public key),`content` is what we'll be matching
against, `re` is the RegExpr value we built when parsing the regex, and `c_pos`
is the cursor position (the index in content we are currently matching
against).

The result is a vector of tuples, with first value of the tuple the so far
computed ciphertext result, and second value the content position after the
regex components were applied.  It's a vector, because certain RegExpr variants
require to consider a list of possible execution paths. For example, the
RegExpr::Optional might succeed by applying _or_ by *not* applying the optional
regex (and notice that in the former case `c_pos` moves forward whereas in the
latter case it stays put).

On first call to `match` the entire regex pattern is matched starting with
`c_pos=0`, then `match` is called again for the entire regex pattern with
`c_pos=1`, etc. until `c_pos` exceeds the length of the content. Each of these
alternative matches results are then joined together with `sk.bitor` operations
(this works out correctly because if 1 of them results in true, then this means
our matching algorithm in general should return true).

The `...` within the match statement above is what we will be working out for
some of the RegExpr variants now. Starting with `RegExpr::Char`:
```rust
case RegExpr::Char { c } => {
    vec![(sk.eq(content_char, c), c_pos + 1)]
},
```

Lets consider an example of above's variant, if we apply `/a/` to content
`bac`, we'd have the following list of `match` calls' `re` and `c_pos` values
(for simplicity `re` is denoted in regex pattern instead of in RegExpr value):

re | c\_pos | Ciphertext operation
--- | --- | ---
/a/ | 0 | sk.eq(content[0], a)
/a/ | 1 | sk.eq(content[1], a)
/a/ | 2 | sk.eq(content[2], a)

And we would arrive at the following sequence of Ciphertext operations:
```
sk.bitor(sk.eq(content[0], a), sk.bitor(sk.eq(content[1], a), sk.eq(content[2], a)))
```

AnyChar is a no operation:
```rust
case RegExpr::AnyChar => {
    // note: ct_true is just some constant representing True that is trivially encoded into ciphertext
    return vec![(ct_true, c_pos + 1)];
}
```

Sequence iterates over its `re_xs`, increasing the content position
accordingly, and joins the results with `bitand` operations:
```rust
case RegExpr::Seq { re_xs } => {
    re_xs.iter().fold(|prev_results, re_x| {
        prev_results.iter().flat_map(|(prev_res, prev_c_pos)| {
            (x_res, new_c_pos) = match(sk, content, re_x, prev_c_pos);
            (sk.bitand(prev_res, x_res), new_c_pos)
        })
    }, (ct_true, c_pos))
},
```

Other variants are similar, they recurse and manipulate `re` and `c_pos`
accordingly. Hopefully the general idea is already clear.

Ultimately the entire pattern matching logic unfolds into a sequence of just
the following set of FHE operations:
1. eq (tests for an exact character match)
2. ge (tests for greater than or equal to a character)
3. le (tests for less than or equal to a character)
4. bitand (bitwise AND, used for sequencing multiple regex components)
5. bitor (bitwise OR, used for folding multiple possible execution variants'
   results into a single result)
6. bitxor (bitwise XOR, used for the not logic in ranges)

### Optimizations

Generally the included example PME follows above approach. However, there were
two additional optimizations applied. Both of these optimizations involved
reducing the number of unnecessary FHE operations. I think that given how
computationally expensive these operations are, it only makes sense to optimize
for this (and to for example ignore any suboptimal memory usage of our PME,
etc.).

The first optimization involved delaying execution of FHE operations to _after_
generation of all the possible execution paths that have to be considered. This
optimization allows us to prune execution paths during execution path
construction that are provably going to result in an encrypted false value,
without having already performed the FHE operations up to the point of pruning.
Consider for example the regex `/^a+b$/`, and we are applying this to a content
of size 4. If we're executing execution paths naively, we would go ahead and
check for all possible amount of `a` repetitions: `ab`, `aab`, `aaab`.
However, while building the execution paths, we can use the fact that `a+` must
begin at the beginning of the content, and that `b` must be the final character
of the content. From this follows that we only have to check for the following
sentence: `aaab`. Delaying execution of the FHE operations til after we've
built the possible execution paths in this example reduced the number of FHE
operations applied by half approximately!

The second optimization involved preventing the same FHE conditions to be
re-evaluated. Consider the regex `/^a?ab/`, this would give us the following
possible execution paths that must be considered:
1. `content[0] == a && content[1] == a && content[2] == b` (we match the `a` in
   `a?`)
2. `content[0] == a && content[1] == b` (we don't match the `a` in `a?`)

Notice that for both execution paths we are checking for `content[0] == a`.
Even though we cannot see what the encrypted result is, we do know that it's
either going to be an encrypted false for both cases or an encrypted true for
both cases. Therefore, we can skip the re-evaluation of `content[0] == a` and
simply copy the result from the first evaluation over. This optimization
involved maintaining a cache of known expression evaluations' results, and
reusing those where possible.

# Trying out the example implementation

The implementation that guided the writing of this tutorial can be found
under `tfhe/examples/regex_engine`.

When compiling with `--example regex_engine`, a binary is produced that serves
as a basic demo. Simply call it with first argument the content string and
second argument the pattern string. For example,
`cargo run --release --features=x86_64-unix,integer --example regex_engine  -- 'this is the content' '/^pattern$/'`;
note it's advicable to compile the executable with `--release` flag  as the key
generation and homomorphic operations otherwise seem to experience a heavy
performance penalty.

On execution it first creates a private and public key pair. It then encrypts
the content with the client key, and applies the regex pattern onto the
encrypted content string - with only access to the server key. Finally, it
decrypts the resulting encrypted result using the client key and prints the
verdict to the console.

To get some more information on what exactly it is doing, set the `RUST_LOG`
environment variable to `debug` or to `trace`.
