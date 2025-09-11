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

The Barret reduction algorithm is explained and analyzed in this blog post: https://blog.zksecurity.xyz/posts/barrett-tighter-bound/ a major distinction to note is that the blog-post derives functions word-wise meaning that $b = 2^{32}$ or $2^{64}$. `tfhe-ntt` code is writtent in terms of bits so $b = 2$.

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
L &= Q + 31 \\
p_{barrett} &= \lfloor\frac{2^L}{p}\rfloor
\end{align*}
$$

Here we have a value $d$ we want to reduce modulo $p$. Following the computations of the `mul_accumulate_scalar` function from above we see the following for the $q_{barrett}$ value:

$$
c1 = \lfloor\frac{d}{2^{Q-1}}\rfloor \\
c3 = \lfloor\frac{c1 \cdot p_{barrett}}{2^{32}}\rfloor
$$

Given the usage of $c3$ we can see it is actually $q_{barrett}$.

The ZK Security blog then re arranges the formula to derive interesting properties, you can first read their derivation with $b = 2$, as the following is based on their method only adapted to our particular case.

Now replacing the various terms by the way they were computed we get:

$$
q_{barrett} = c3 = \lfloor\frac{\lfloor\frac{d}{2^{Q-1}}\rfloor\lfloor\frac{2^L}{p}\rfloor}{2^{32}}\rfloor
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


Recall $L = Q + 31$ and we have:

$$
\begin{align*}
q_{barrett}
 &= \lfloor \frac{\frac{d - \alpha}{2^{Q - 1}}\cdot\frac{2^{Q + 31} - \beta}{p}}{2^{32}}\rfloor \\
 &= \lfloor \frac{(d - \alpha)\cdot(2^{Q + 31} - \beta)}{p \cdot 2^{Q + 31}}\rfloor \\
 &= \lfloor \frac{d}{p} - {\color{red}{\frac{\alpha \cdot 2^{Q + 31} + \beta \cdot (d - \alpha)}{p \cdot 2^{Q + 31}}}} \rfloor
\end{align*}
$$

Let's call the red part $z$.

We have

$$
q_{barrett } = \lfloor \frac{d}{m} - {\color{red}{z}} \rfloor
$$

The floor function inequality gives us $\lfloor x \rfloor + \lfloor y \rfloor + 1 \ge \lfloor x + y \rfloor$

$$
\lfloor \frac{d}{p} - z \rfloor + \lfloor z \rfloor + 1 \ge \lfloor \left(\frac{d}{p} - z\right) + z \rfloor = \lfloor \frac{d}{p} \rfloor = q
$$

Therefore:

$$
q_{barrett} + \lfloor z \rfloor + 1 \ge q
$$

If $0 \le z \lt 2$ then $\lfloor z \rfloor \le 1$ which then means $q_{barrett} + 2 \ge q_{barrett} + \lfloor z \rfloor + 1 \ge q$.

The code selects $p \lt 2^{31}$ as valid primes, meaning $Q = 31$

Recall $\alpha \lt 2^{Q-1} = 2^{30}$ and observe that $d \lt 2^{62}$ because $d$ is a product of two values that are smaller than $p$.

Then:

$$
\begin{align*}
z &= \frac{\alpha \cdot 2^{62} + \beta \cdot (d-\alpha)}{m \cdot 2^{62}} \\
&\lt \frac{{\color{red}{2^{Q - 1}}} \cdot 2^{62} + \beta \cdot {\color{red}{2^{62}}}}{p\cdot 2^{62}} \\
&= \frac{2^{Q - 1} + \beta}{p}
\end{align*}
$$

We know always have $2^{Q - 1} \lt p$ and $\beta$ is a value $\mod p$ so we have:

$$
z \lt \frac{p + p}{p} \lt 2
$$

Now assuming $Q \lt 31$ we know $z \lt 2$, let's go through the last derivation to find what the condition is to have $z \lt 1$.

$$
z \lt \frac{2^{Q - 1} + \beta}{p}
$$

So $z \lt 1$ holds if:

$$
\frac{2^{Q - 1} + \beta}{p} \le 1
$$

And finally:

$$
\beta \le p - 2^{Q-1}
$$

Recall $\beta \equiv 2^L \mod p$ and you have the formula used in this patch.
