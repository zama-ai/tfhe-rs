use crate::core_crypto::prelude::*;

pub struct BaseDecomposer {
    polynomial_size: PolynomialSize,
    table: Vec<Decomposition>,
}

#[derive(Copy, Clone, Default, Debug)]
pub struct Decomposition {
    pub base_power: u16,
    pub negative: bool,
}

impl BaseDecomposer {
    pub fn new(base: u64, polynomial_size: PolynomialSize) -> Self {
        let mut table = vec![Decomposition::default(); polynomial_size.0];

        let mut table_initialized = vec![false; polynomial_size.0];

        let m = 2 * polynomial_size.0 as u64;

        let mut power = 1;

        for base_power in 0..polynomial_size.0 / 2 {
            // power = base^base_power
            {
                assert!(power % 2 == 1);
                let index = power as usize / 2;

                assert!(!table_initialized[index]);
                table_initialized[index] = true;

                table[index] = Decomposition {
                    base_power: base_power as u16,
                    negative: false,
                };
            }

            let minus_power = (m - power) % m;

            {
                assert!(minus_power % 2 == 1);
                let index = minus_power as usize / 2;

                assert!(!table_initialized[index]);
                table_initialized[index] = true;

                table[index] = Decomposition {
                    base_power: base_power as u16,
                    negative: true,
                };
            }

            power = (power * base) % m;
        }

        for i in table_initialized {
            assert!(i);
        }

        Self {
            polynomial_size,
            table,
        }
    }

    pub fn decompose_in_base(&self, monomial_power: u64) -> Decomposition {
        assert!(monomial_power < 2 * self.polynomial_size.0 as u64);
        assert!(monomial_power % 2 == 1);

        self.table[monomial_power as usize / 2]
    }
}

pub fn compute_power(base: u64, power: u64, modulus: u64) -> u64 {
    let mut result = 1;
    for _ in 0..power {
        result = (result * base) % modulus
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_decomposer() {
        let polynomial_size = PolynomialSize(2048);

        let base = 5;

        let decomposer = BaseDecomposer::new(base, polynomial_size);

        let m = polynomial_size.0 as u64 * 2;

        for i in 0..2 * polynomial_size.0 {
            if i % 2 == 0 {
                continue;
            }
            let Decomposition {
                base_power,
                negative,
            } = decomposer.decompose_in_base(i as u64);

            let power = compute_power(base, base_power as u64, m);

            let power = if negative { (m - power) % m } else { power };

            assert_eq!(power, i as u64);
        }
    }
}
