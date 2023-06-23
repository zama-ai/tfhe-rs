# FHE Regex Pattern Matching Tutorial

This tutorial explains how to build a regex Pattern Matching Engine (PME) where ciphertext is the
content that is evaluated.

A regex PME is an essential tool for programmers. It allows you to perform complex searches on content. 
A less powerful simple search on string can only find matches of the exact given sequence of
characters (e.g., your browser's default search function). Regex PMEs
are more powerful, allowing searches on certain structures of text, where a
structure may take any form in multiple possible sequences of characters. The
structure to be searched is defined with the regex, a very concise
language. 

Here are some example regexes to give you an idea of what is possible:

Regex | Semantics
--- | ---
/abc/ | Searches for the sequence `abc` (equivalent to a simple text search)
/^abc/ | Searches for the sequence `abc` at the beginning of the content
/a?bc/ | Searches for sequences `abc`, `bc`
/ab\|c+d/ | Searches for sequences of `ab`, `c` repeated 1 or more times, followed by `d`

Regexes are powerful enough to be able to express structures like email address
formats. This capability is what makes regexes useful for many programming
solutions.

There are two main components identifiable in a PME:
1. The pattern that is to be matched has to be parsed, translated from a
   textual representation into a recursively structured object (an Abstract
   Syntax Tree, or AST).
2. This AST must then be applied to the text that it is to be matched against,
   resulting in a 'yes' or 'no' to whether the pattern has matched (in the case of
   our FHE implementation, this result is an encrypted 'yes' or an encrypted 'no').

Parsing is a well understood problem. There are a couple of different
approaches possible here. Regardless of the approach chosen, it starts with
figuring out what language we want to support. That is, what are
the kinds of sentences we want our regex language to include? A few
example sentences we definitely want to support are, for example: `/a/`,
`/a?bc/`, `/^ab$/`, `/ab|cd/`, however example sentences don't suffice as
a specification because they can never be exhaustive (they're endless). We need
something to specify _exactly_ the full set of sentences our language supports.
There exists a language that can help us describe our own language's structure exactly: 
Grammar.

## The Grammar and datastructure

It is useful to start with defining the Grammar before starting to write
code for the parser because the code structure follows directly from the
Grammar. A Grammar consists of a generally small set of rules. For example,
a very basic Grammar could look like this:
```
Start := 'a'
```
This describes a language that only contains the sentence "a". Not a very interesting language.

We can make it more interesting though by introducing choice into the Grammar
with \| (called a 'pipe') operators. If we want the above Grammar to accept
either "a" or "b":
```
Start := 'a' | 'b'
```

So far, only Grammars with a single rule have been shown. However, a Grammar can
consist of multiple rules. Most languages require it. So let's consider a more meaningful language, 
one that accepts sentences consisting of one or more digits. We could describe such a language
with the following Grammar:
```
Start := Digit+

Digit := '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9'
```

The `+` after `Digit` is another Grammar operator. With it, we specify that
Digit must be matched one or more times. Here are all the Grammar operators that
are relevant for this tutorial:

Operator | Example | Semantics
--- | --- | ---
`\|` | a \| b | we first try matching on 'a' - if no match, we try to match on 'b'
`+` | a+ | match 'a' one or more times
`*` | a* | match 'a' any amount of times (including zero times)
`?` | a? | optionally match 'a' (match zero or one time)
`.` | .  | match any character
`..` | a .. b | match on a range of alphabetically ordered characters from 'a', up to and including 'b'
` ` | a b | sequencing; match on 'a' and then on 'b'

In the case of the example PME, the Grammar is as follows (notice the unquoted ? and quoted ?, etc. The unquoted characters are Grammar operators, and the quoted are characters we are matching in the parsing).
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
We will refer occasionally to specific parts in the Grammar listed above by \<rule name\>.\<variant index\> (where the first rule variant has index 1).

With the Grammar defined, we can start defining a type to parse into. In Rust, we
have the `enum` kind of type that is perfect for this, as it allows you to define
multiple variants that may recurse. I prefer to start by defining variants that
do not recurse (i.e., that don't contain nested regex expressions):
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

With this, we can translate the following basic regexes:

Pattern | RegExpr value
--- | ---
`/a/` | `RegExpr::Char { c: 'a' }`
`/\\^/` | `RegExpr::Char { c: '^' }`
`/./` | `RegExpr::AnyChar`
`/^/` | `RegExpr::SOF`
`/$/` | `RegExpr::EOF`
`/[acd]/` | `RegExpr::Range { vec!['a', 'c', 'd'] }`
`/[a-g]/` | `RegExpr::Between { from: 'a', to: 'g' }`

Notice we're not yet able to sequence multiple components together. Let's define
the first variant that captures recursive RegExpr for this:
```rust
enum RegExpr {
    ...
    Seq { re_xs: Vec<RegExpr> },  // matching sequences of RegExpr components (Term.1)
}
```
With this Seq (short for sequence) variant, we allow translating patterns that
contain multiple components:

Pattern | RegExpr value
--- | ---
`/ab/` | `RegExpr::Seq { re_xs: vec![RegExpr::Char { c: 'a' }, RegExpr::Char { c: 'b' }] }`
`/^a.$/` | `RegExpr::Seq { re_xs: vec![RegExpr::SOF, RexExpr::Char { 'a' }, RegExpr::AnyChar, RegExpr::EOF] }`
`/a[f-l]/` | `RegExpr::Seq { re_xs: vec![RegExpr::Char { c: 'a' }, RegExpr::Between { from: 'f', to: 'l' }] }`

Let's finish the RegExpr datastructure by adding variants for 'Optional' matching,
'Not' logic in a range, and 'Either' left or right matching:
```rust
enum RegExpr {
    ...
    Optional { opt_re: Box<RegExpr> },  // matching optionally (Factor.1)
    Not { not_re: Box<RegExpr> },  // matching inversely on a range (Range.1)
    Either { l_re: Box<RegExpr>, r_re: Box<RegExpr> },  // matching the left or right regex (Regex.1)
}
```

Some features may make the most sense being implemented during post-processing of
the parsed datastructure. For example, the case insensitivity feature (the `i`
Modifier) is implemented in the example implementation by taking the parsed
RegExpr and mutating every character mentioned inside to cover both the lower
case as well as the upper case variant (see function `case_insensitive` in
`parser.rs` for the example implementation).

The modifier `i` in our Grammar (for enabling case insensitivity) was easiest
to implement by applying a post-processing step to the parser.

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
be done. For example, there exist tools that can automatically generate parser
code by giving it the Grammar definition (these are called parser generators).
However, you might prefer to write parsers with a parser combinator library.
This may be the better option for you because the behavior in runtime is easier to understand
for parsers constructed with a parser combinator library than of parsers that were
generated with a parser generator tool.

Rust offers a number of popular parser combinator libraries. This tutorial used
`combine`, but any other library would work just as well. Choose whichever appeals
the most to you (including any parser generator tool). The implementation of
our regex parser will differ significantly depending on the approach you choose,
so we will not cover this in detail here. You may look at the parser code in the example 
implementation to get an idea of how this could be done. In general though, the Grammar and the
datastructure are the important components, while the parser code follows directly from these.

## Matching the RegExpr to encrypted content

The next challenge is to build the execution engine, where we take a RegExpr
value and recurse into it to apply the necessary actions on the encrypted
content. We first have to define how we actually encode our content into an
encrypted state. Once that is defined, we can start working on how we will
execute our RegExpr onto the encrypted content.

### Encoding and encrypting the content.

It is not possible to encrypt the entire content into a single encrypted value.
We can only encrypt numbers and perform operations on those encrypted numbers with
FHE. Therefore, we have to find a scheme where we encode the content into a
sequence of numbers that are then encrypted individually to form a sequence of
encrypted numbers.

We recommend the following two strategies:
1. to map each character of the content into the u8 ascii value, and then encrypt
   each bit of these u8 values individually.
2. to, instead of encrypting each bit individually, encrypt each u8 ascii value in
   its entirety.

Strategy 1 requires more high-level TFHE-rs operations to check for 
a simple character match (we have to check each bit individually for
equality as opposed to checking the entire byte in one, high-level TFHE-rs
operation), though some experimentation did show that both options performed
equally well on a regex like `/a/`. This is likely because bitwise FHE
operations are relatively cheap compared to u8 FHE operations. However,
option 1 falls apart as soon as you introduce '[a-z]' regex logic.
With option 2, it is possible to complete this match with just three TFHE-rs
operations: `ge`, `le`, and `bitand`.
```rust
// note: this is pseudocode
c       = <the encrypted character under inspection>;
sk      = <the server key, aka the public key>

ge_from = sk.ge(c, 'a');
le_to   = sk.le(c, 'z');
result  = sk.bitand(ge_from, le_to);
```

If, on the other hand, we had encrypted the content with the first strategy,
there would be no way to test for `greater/equal than from` and `less/equal
than to`. We'd have to check for the potential equality of each character between
`from` and `to`, and then join the results together with a sequence of
`sk.bitor`; that would require far more cryptographic operations than in strategy 2.

Because FHE operations are computationally expensive, and strategy 1 requires
significantly more FHE operations for matching on `[a-z]` regex logic, we
should opt for strategy 2.

### Matching with the AST versus matching with a derived DFA.

There are a lot of regex PMEs. It's been built many times and it's been
researched thoroughly. There are different strategies possible here.
A straight forward strategy is to directly recurse into our RegExpr
value and apply the necessary matching operations onto the content. In a way,
this is nice because it allows us to link the RegExpr structure directly to
the matching semantics, resulting in code that is easier to
understand, maintain, etc.

Alternatively, there exists an algorithm that transforms the AST (i.e., the
RegExpr, in our case) into a Deterministic Finite Automata (DFA). Normally, this
is a favorable approach in terms of efficiency because the derived DFA can be
walked over without needing to backtrack (whereas the former strategy cannot
prevent backtracking). This means that the content can be walked over from
character to character, and depending on what the character is at this
cursor, the DFA is conjunctively traveled in a definite direction which
ultimately leads us to the `yes, there is a match` or the `no, there is no
match`. There is a small upfront cost of having to translate the AST into the
DFA, but the lack of backtracking during matching generally makes up for
this, especially if the content that it is matched against is significantly big.

In our case though, we are matching on encrypted content. We have no way to know
what the character at our cursor is, and therefore no way to find this definite
direction to go forward in the DFA. Therefore, translating the AST into the DFA does 
not help us as it does in normal regex PMEs. For this reason, consider opting for the 
former strategy because it allows for matching logic that is easier to understand.

### Matching.

In the previous section, we decided we'll match by traversing into the RegExpr
value. This section will explain exactly how to do that. Similarly to defining
the Grammar, it is often best to start with working out the non-recursive
RegExpr variants.

We'll start by defining the function that will recursively traverse into the RegExpr value:
```rust

type StringCiphertext = Vec<RadixCiphertext>;
type ResultCiphertext = RadixCiphertext;

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

`sk` is the server key (aka, public key),`content` is what we'll be matching
against, `re` is the RegExpr value we built when parsing the regex, and `c_pos`
is the cursor position (the index in content we are currently matching
against).

The result is a vector of tuples, with the first value of the tuple being the computed
ciphertext result, and the second value being the content position after the
regex components were applied. It's a vector because certain RegExpr variants
require the consideration of a list of possible execution paths. For example,
RegExpr::Optional might succeed by applying _or_ and *not* applying the optional
regex (notice that in the former case, `c_pos` moves forward whereas in the
latter case it stays put).

On first call, a `match` of the entire regex pattern starts with `c_pos=0`. 
Then `match` is called again for the entire regex pattern with `c_pos=1`, etc. until
`c_pos` exceeds the length of the content. Each of these alternative match results
are then joined together with `sk.bitor` operations (this works because if one of them results 
in 'true' then, in general, our matching algorithm should return 'true').

The `...` within the match statement above is what we will be working out for
some of the RegExpr variants now. Starting with `RegExpr::Char`:
```rust
case RegExpr::Char { c } => {
    vec![(sk.eq(content_char, c), c_pos + 1)]
},
```

Let's consider an example of the variant above. If we apply `/a/` to content
`bac`, we'll have the following list of `match` calls `re` and `c_pos` values
(for simplicity, `re` is denoted in regex pattern instead of in RegExpr value):

re | c\_pos | Ciphertext operation
--- | --- | ---
/a/ | 0 | sk.eq(content[0], a)
/a/ | 1 | sk.eq(content[1], a)
/a/ | 2 | sk.eq(content[2], a)

And we would arrive at the following sequence of ciphertext operations:
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

The sequence iterates over its `re_xs`, increasing the content position
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

Other variants are similar, as they recurse and manipulate `re` and `c_pos`
accordingly. Hopefully, the general idea is already clear.

Ultimately the entire pattern-matching logic unfolds into a sequence of
the following set of FHE operations:
1. eq (tests for an exact character match)
2. ge (tests for 'greater than' or 'equal to' a character)
3. le (tests for 'less than' or 'equal to' a character)
4. bitand (bitwise AND, used for sequencing multiple regex components)
5. bitor (bitwise OR, used for folding multiple possible execution variants'
   results into a single result)
6. bitxor (bitwise XOR, used for the 'not' logic in ranges)

### Optimizations.

Generally, the included example PME follows the approach outlined above. However, there were
two additional optimizations applied. Both of these optimizations involved
reducing the number of unnecessary FHE operations. Given how computationally expensive 
these operations are, it makes sense to optimize for this (and to ignore any suboptimal
memory usage of our PME, etc.).

The first optimization involved delaying the execution of FHE operations to _after_
the generation of all possible execution paths to be considered. This optimization 
allows us to prune execution paths during execution path construction that are provably 
going to result in an encrypted false value, without having already performed the FHE 
operations up to the point of pruning. Consider the regex `/^a+b$/`, and we are applying 
this to a content of size 4. If we are executing execution paths naively, we would go ahead 
and check for all possible amounts of `a` repetitions: `ab`, `aab`, `aaab`.
However, while building the execution paths, we can use the fact that `a+` must
begin at the beginning of the content, and that `b` must be the final character
of the content. From this follows that we only have to check for the following
sentence: `aaab`. Delaying execution of the FHE operations until after we've
built the possible execution paths in this example reduced the number of FHE
operations applied by approximately half.

The second optimization involved preventing the same FHE conditions to be
re-evaluated. Consider the regex `/^a?ab/`. This would give us the following
possible execution paths to consider:
1. `content[0] == a && content[1] == a && content[2] == b` (we match the `a` in
   `a?`)
2. `content[0] == a && content[1] == b` (we don't match the `a` in `a?`)

Notice that, for both execution paths, we are checking for `content[0] == a`.
Even though we cannot see what the encrypted result is, we do know that it's
either going to be an encrypted false for both cases or an encrypted true for
both cases. Therefore, we can skip the re-evaluation of `content[0] == a` and
simply copy the result from the first evaluation over. This optimization
involves maintaining a cache of known expression evaluation results and
reusing those where possible.

## Trying out the example implementation

The implementation that guided the writing of this tutorial can be found
under `tfhe/examples/regex_engine`.

When compiling with `--example regex_engine`, a binary is produced that serves
as a basic demo. Simply call it with the content string as a first argument and
the pattern string as a second argument. For example,
`cargo run --release --features=x86_64-unix,integer --example regex_engine  -- 'this is the content' '/^pattern$/'`;
note it's advised to compile the executable with `--release` flag as the key
generation and homomorphic operations otherwise seem to experience a heavy
performance penalty.

On execution, a private and public key pair are created. Then, the content is
encrypted with the client key, and the regex pattern is applied onto the
encrypted content string - with access given only to the server key. Finally, it
decrypts the resulting encrypted result using the client key and prints the
verdict to the console.

To get more information on exact computations and performance, set the `RUST_LOG`
environment variable to `debug` or to `trace`.


### Supported regex patterns

This section specifies the supported set of regex patterns in the regex engine.

#### Components

A regex is described by a sequence of components surrounded by `/`, the
following components are supported:

Name | Notation | Examples
--- | --- | ---
Character | Simply the character itself | `/a/`, `/b/`, `/Z/`, `/5/`
Character range | `[<character>-<character]` | `/[a-d]/`, `/[C-H]`/
Any character | `.` | `/a.c/`
Escaped symbol | `\<symbol>` | `/\^/`, `/\$/`
Parenthesis | `(<regex>)` | `/(abc)*/`, `/d(ab)?/`
Optional | `<regex>?` | `/a?/`, `/(az)?/`
Zero or more | `<regex>*` | `/a*/`, `/ab*c/`
One or more | `<regex>+` | `/a+/`, `/ab+c/`
Exact repeat | `<regex{<number>}>` | `/ab{2}c/`
At least repeat | `<regex{<number>,}>` | `/ab{2,}c/`
At most repeat | `<regex{,<number>}>` | `/ab{,2}c/`
Repeat between | `<regex{<number>,<number>}>` | `/ab{2,4}c/`
Either | `<regex>\|<regex>` | `/a\|b/`, `/ab\|cd/`
Start matching | `/^<regex>` | `/^abc/`
End matching | `<regex>$/` | `/abc$/`

#### Modifiers

Modifiers are mode selectors that affect the entire regex behavior.  One modifier is
currently supported:

- Case insensitive matching, by appending an `i` after the regex pattern. For example: `/abc/i`

#### General examples

These components and modifiers can be combined to form any desired regex
pattern. To give some idea of what is possible, here is a non-exhaustive list of
supported regex patterns:

Pattern | Description
--- | ---
`/^abc$/` | Matches with content that equals exactly `abc` (case sensitive)
`/^abc$/i` | Matches with content that equals `abc` (case insensitive)
`/abc/` | Matches with content that contains somewhere `abc`
`/ab?c/` | Matches with content that contains somewhere `abc` or somwhere `ab`
`/^ab*c$/` | For example, matches with: `ac`, `abc`, `abbbbc`
`/^[a-c]b\|cd$/` | Matches with: `ab`, `bb`, `cb`, `cd`
`/^[a-c]b\|cd$/i` | Matches with: `ab`, `Ab`, `aB`, ..., `cD`, `CD`
`/^d(abc)+d$/` | For example, matches with: `dabcd`, `dabcabcd`, `dabcabcabcd`
`/^a.*d$/` | Matches with any content that starts with `a` and ends with `d`
