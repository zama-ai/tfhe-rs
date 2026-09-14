# Incorrect range for Barrett reduction intermediate results

Original issue is here: https://github.com/zama-ai/tfhe-rs/issues/2037
PR is here: https://github.com/zama-ai/tfhe-rs/pull/2748

## The problem

In order to compute the modular reduction of a value $v$ by a prime $p$, one wants to find $r$ such that:

$$
v \equiv r \mod p
$$

To avoid having to compute an actual modulo operation we rely on the euclidean division: for a given value $v$ and a divisor $p$ there exists a unique couple ($q$, $r$) with $r \lt p$ such that:

$$
v = pq + r
\iff r = v - pq
$$

and

$$
v \equiv r \mod p
$$

Note that $q = \lfloor \frac{v}{p} \rfloor$.

The Barrett reduction algorithm is explained and analyzed in this blog post: https://blog.zksecurity.xyz/posts/barrett-tighter-bound/ a major distinction to note is that the blog-post derives functions word-wise meaning that $b = 2^{32}$ or $2^{64}$. `tfhe-ntt` code is written in terms of bits so $b = 2$.

The `tfhe-ntt` code uses the Barrett reduction algorithm to compute a good first approximation $q_{barrett}$ of the quotient $q$ of the division of a given value $v$ by $p$. This in turns allows to compute a first approximation $r_{barrett}$ of $r$:

$$
r_{barrett} := v - pq_{barrett}
$$

Then one can subtract $p$ until $r_{barrett}$ satisfies $r_{barrett} \lt p$ to get the true value of $r$:

$$
\begin{align*}
\text{while }r_{barrett} \gt p: \\
r_{barrett} &:= r_{barrett} - p \\
\end{align*}
$$

As indicated in the blog post and in the original algorithm the first "guess" of q is off by at most 2, meaning:

$$
q_{barrett} \in \{q - 2, q - 1, q\}
$$

There is a risk of overflowing the integer types used for the implementation if $q_{barrett}$ is not equal to q, which happens frequently. There are hard thresholds that guarantee no overflows for all primes.

For an unsigned integer of $w$ bits, we have in the worst case:

$$
r_{barrett} = v - pq + 2p
\iff r_{barret} = r + 2p
$$

as $r \lt p$ then we have:

$$
r_{barrett} \lt 3p
$$

and the correctness condition to avoid overflow is:

$$
r_{barrett} \lt 2^w
\iff 3p \lt 2^w
\iff p \lt \frac{2^w}{3}
$$

The ZK Security blog post indicates that we can do better for certain primes beyond that threshold.
Here we will be using the notations from the code which are shared with this paper: https://eprint.iacr.org/2021/420

The relevant rust code doing Barrett reduction for 32 bits is the following:

```Rust
fn mul_accumulate_scalar(
    acc: &mut [u32],
    lhs: &[u32],
    rhs: &[u32],
    p: u32,
    p_barrett: u32,
    big_q: u32,
) {
    let big_q_m1 = big_q - 1;

    for (acc, lhs, rhs) in crate::izip!(acc, lhs, rhs) {
        let lhs = *lhs;
        let rhs = *rhs;

        let d = lhs as u64 * rhs as u64;
        let c1 = (d >> big_q_m1) as u32;
        let c3 = ((c1 as u64 * p_barrett as u64) >> 32) as u32;
        let prod = (d as u32).wrapping_sub(p.wrapping_mul(c3));
        let prod = prod.min(prod.wrapping_sub(p));

        let acc_ = prod + *acc;
        *acc = acc_.min(acc_.wrapping_sub(p));
    }
}
```

$p_{barrett}$ is the equivalent of the $\mu$ from the ZK Security blog, it's the precomputed constant for the algorithm.

For the notations here we have:

$$
2^{Q-1} \le p \le 2^{Q}
$$

So Q is about the number of bits required to represent $p$.

$p_{barrett}$ is computed as follows:

$$
\begin{align*}
L &= Q - 1 + w \\
p_{barrett} &= \lfloor\frac{2^L}{p}\rfloor
\end{align*}
$$

Where $w$ is the width of the registers we are working with (so 32, 52 or 64 for `tfhe-ntt`)

Here we have a value $d$ we want to reduce modulo $p$. Following the computations of the `mul_accumulate_scalar` function from above we see the following for the $q_{barrett}$ value:

$$
c_1 = \lfloor\frac{d}{2^{Q-1}}\rfloor \\
c_3 = \lfloor\frac{c_1 \cdot p_{barrett}}{2^{w}}\rfloor
$$

Given the usage of $c_3$ we can see it is actually $q_{barrett}$.

The ZK Security blog then re arranges the formula to derive interesting properties, you can first read their derivation with $b = 2$, as the following is based on their method only adapted to our particular case.

Now replacing the various terms by the way they were computed we get:

$$
q_{barrett} = c_3 = \lfloor\frac{\lfloor\frac{d}{2^{Q-1}}\rfloor\lfloor\frac{2^L}{p}\rfloor}{2^{w}}\rfloor
$$

Let's define $\alpha \equiv d \mod {2^{Q-1}}$, let's write the euclidean division formula for d:

$$
d = \lfloor\frac{d}{2^{Q-1}}\rfloor 2^{Q - 1} + \alpha
\iff \lfloor\frac{d}{2^{Q-1}}\rfloor = \frac{d - \alpha}{2^{Q - 1}}
$$

Defining in the same way $\beta \equiv 2^L \mod p$ we have:

$$
\lfloor\frac{2^L}{p}\rfloor = \frac{2^L - \beta}{p}
$$


We have:

$$
\begin{align*}
q_{barrett}
 &= \lfloor \frac{\frac{d - \alpha}{2^{Q - 1}}\cdot\frac{2^{Q - 1 + w} - \beta}{p}}{2^{w}}\rfloor \\
 &= \lfloor \frac{(d - \alpha)\cdot(2^{Q - 1 + w} - \beta)}{p \cdot 2^{Q - 1 + w}}\rfloor \\
 &= \lfloor \frac{d}{p} - {\color{red}{\frac{\alpha \cdot 2^{Q - 1 + w} + \beta \cdot (d - \alpha)}{p \cdot 2^{Q - 1 + w}}}} \rfloor
\end{align*}
$$

Let's call the red part $z$.

We have

$$
q_{barrett } = \lfloor \frac{d}{p} - {\color{red}{z}} \rfloor
$$

The floor function inequality gives us $\lfloor x \rfloor + \lfloor y \rfloor + 1 \ge \lfloor x + y \rfloor$

$$
\lfloor \frac{d}{p} - z \rfloor + \lfloor z \rfloor + 1 \ge \lfloor \left(\frac{d}{p} - z\right) + z \rfloor = \lfloor \frac{d}{p} \rfloor = q
$$

Therefore:

$$
q_{barrett} + \lfloor z \rfloor + 1 \ge q
$$

We want $q_{barrett} + 1 \ge q$ for the `tfhe-ntt` code which means we want $\lfloor z \rfloor = 0 \iff z \lt 1$ 

Recall $\alpha \le 2^{Q-1} - 1$ and $d - \alpha = c_1 \cdot 2^{Q - 1}$.

Then:

$$
\begin{align*}
z &= \frac{\alpha \cdot 2^{Q - 1 + w} + \beta \cdot (d - \alpha)}{p \cdot 2^{Q - 1 + w}} \\
&\le \frac{{\color{red}{(2^{Q - 1} - 1})} \cdot 2^{Q - 1 + w} + \beta \cdot {\color{red}{c_1 \cdot 2^{Q - 1}}}}{p\cdot 2^{Q - 1 + w}} \\
&\le \frac{(2^{Q - 1} - 1) \cdot 2^{w} + \beta \cdot c_1}{p \cdot 2^{w}} \\
&\le \frac{(2^{Q - 1} - 1) \cdot 2^{w} + \beta \cdot c_{1,max}}{p \cdot 2^{w}}
\end{align*}
$$

We want $z \lt 1$:

$$
\begin{align*}
(2^{Q - 1} - 1) \cdot 2^{w} + \beta \cdot c_{1,max} &\lt p \cdot 2^{w}
\iff \beta \cdot c_{1,max} &\lt (p - 2^{Q - 1} + 1) \cdot 2^{w}
\end{align*}
$$

Recall that $c_1 = \lfloor\frac{d}{2^{Q-1}}\rfloor$, $d$ is a product of two values $\lt p$ so we have $c_{1,max} = \lfloor\frac{(p - 1)^2}{2^{Q - 1}}\rfloor$. In that case since we are taking the floor division of a value by a power of two it corresponds to right shift by the power, so $Q - 1$, giving the criterion used in this patch.
