use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use crate::shortint::{Ciphertext, MaxNoiseLevel, ServerKey};

fn test_ct_unary_op_noise_level_propagation(sk: &ServerKey, ct: &Ciphertext) {
    let test_fn = |op: &dyn Fn(&ServerKey, &Ciphertext) -> Ciphertext,
                   predicate: &dyn Fn(NoiseLevel) -> NoiseLevel| {
        assert_eq!(op(sk, ct).noise_level(), predicate(ct.noise_level()));
    };

    test_fn(&ServerKey::unchecked_neg, &|ct_noise| ct_noise);
    test_fn(
        &|sk, ct| ServerKey::unchecked_neg_with_correcting_term(sk, ct).0,
        &|ct_noise| ct_noise,
    );

    let acc = sk.generate_lookup_table(|_| 0);

    test_fn(
        &|sk, ct| ServerKey::apply_lookup_table(sk, ct, &acc),
        &|input_level| {
            if input_level == NoiseLevel::ZERO {
                NoiseLevel::ZERO
            } else {
                NoiseLevel::NOMINAL
            }
        },
    );
}

fn test_ct_unary_op_assign_noise_level_propagation(sk: &ServerKey, ct: &Ciphertext) {
    let test_fn = |op: &dyn Fn(&ServerKey, &mut Ciphertext),
                   predicate: &dyn Fn(NoiseLevel) -> NoiseLevel| {
        let mut clone = ct.clone();
        op(sk, &mut clone);
        assert_eq!(clone.noise_level(), predicate(ct.noise_level()));
    };

    test_fn(&ServerKey::unchecked_neg_assign, &|ct_noise| ct_noise);
    test_fn(
        &|sk, ct| {
            ServerKey::unchecked_neg_assign_with_correcting_term(sk, ct);
        },
        &|ct_noise| ct_noise,
    );

    let acc = sk.generate_lookup_table(|_| 0);

    test_fn(
        &|sk, ct| ServerKey::apply_lookup_table_assign(sk, ct, &acc),
        &|input_level| {
            if input_level == NoiseLevel::ZERO {
                NoiseLevel::ZERO
            } else {
                NoiseLevel::NOMINAL
            }
        },
    );
}

fn test_ct_binary_op_noise_level_propagation(sk: &ServerKey, ct1: &Ciphertext, ct2: &Ciphertext) {
    let test_fn = |op: &dyn Fn(&ServerKey, &Ciphertext, &Ciphertext) -> Ciphertext,
                   predicate: &dyn Fn(NoiseLevel, NoiseLevel) -> NoiseLevel| {
        assert_eq!(
            op(sk, ct1, ct2).noise_level(),
            predicate(ct1.noise_level(), ct2.noise_level())
        );
    };

    test_fn(&ServerKey::unchecked_add, &|ct1_noise, ct2_noise| {
        ct1_noise + ct2_noise
    });
    test_fn(&ServerKey::unchecked_sub, &|ct1_noise, ct2_noise| {
        ct1_noise + ct2_noise
    });
    test_fn(
        &|sk, ct1, ct2| ServerKey::unchecked_sub_with_correcting_term(sk, ct1, ct2).0,
        &|ct1_noise, ct2_noise| ct1_noise + ct2_noise,
    );

    let both_are_trivially_encrypted = ct1.is_trivial() && ct2.is_trivial();
    let any_trivial_zero = ct1.degree.get() == 0 || ct2.degree.get() == 0;
    test_fn(&ServerKey::unchecked_mul_lsb, &|_, _| {
        if any_trivial_zero || both_are_trivially_encrypted {
            NoiseLevel::ZERO
        } else {
            NoiseLevel::NOMINAL
        }
    });
    test_fn(&ServerKey::unchecked_mul_msb, &|_, _| {
        if any_trivial_zero || both_are_trivially_encrypted {
            NoiseLevel::ZERO
        } else {
            NoiseLevel::NOMINAL
        }
    });

    let expected_bivariate_pbs_output_noise = if both_are_trivially_encrypted {
        NoiseLevel::ZERO
    } else {
        NoiseLevel::NOMINAL
    };
    test_fn(&ServerKey::unchecked_div, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_bitand, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_bitor, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_bitxor, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_equal, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_mul_lsb_small_carry, &|_, _| {
        if both_are_trivially_encrypted {
            NoiseLevel::ZERO
        } else {
            NoiseLevel::NOMINAL * 2
        }
    });
    test_fn(&ServerKey::unchecked_greater, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_greater_or_equal, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_less, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_less_or_equal, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_not_equal, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(
        &|sk, ct1, ct2| ServerKey::unchecked_evaluate_bivariate_function(sk, ct1, ct2, |_, _| 0),
        &|_, _| expected_bivariate_pbs_output_noise,
    );
}

fn test_ct_binary_op_assign_noise_level_propagation(
    sk: &ServerKey,
    ct1: &Ciphertext,
    ct2: &Ciphertext,
) {
    let test_fn = |op: &dyn Fn(&ServerKey, &mut Ciphertext, &Ciphertext),
                   predicate: &dyn Fn(NoiseLevel, NoiseLevel) -> NoiseLevel| {
        let mut clone = ct1.clone();
        op(sk, &mut clone, ct2);
        assert_eq!(
            clone.noise_level(),
            predicate(ct1.noise_level(), ct2.noise_level())
        );
    };

    test_fn(&ServerKey::unchecked_add_assign, &|ct1_noise, ct2_noise| {
        ct1_noise + ct2_noise
    });
    test_fn(&ServerKey::unchecked_sub_assign, &|ct1_noise, ct2_noise| {
        ct1_noise + ct2_noise
    });
    test_fn(
        &|sk, ct1, ct2| {
            ServerKey::unchecked_sub_assign_with_correcting_term(sk, ct1, ct2);
        },
        &|ct1_noise, ct2_noise| ct1_noise + ct2_noise,
    );

    let both_are_trivially_encrypted = ct1.is_trivial() && ct2.is_trivial();
    let any_trivial_zero = ct1.degree.get() == 0 || ct2.degree.get() == 0;
    test_fn(&ServerKey::unchecked_mul_lsb_assign, &|_, _| {
        if any_trivial_zero || both_are_trivially_encrypted {
            NoiseLevel::ZERO
        } else {
            NoiseLevel::NOMINAL
        }
    });
    test_fn(&ServerKey::unchecked_mul_msb_assign, &|_, _| {
        if any_trivial_zero || both_are_trivially_encrypted {
            NoiseLevel::ZERO
        } else {
            NoiseLevel::NOMINAL
        }
    });

    let expected_bivariate_pbs_output_noise = if both_are_trivially_encrypted {
        NoiseLevel::ZERO
    } else {
        NoiseLevel::NOMINAL
    };
    test_fn(&ServerKey::unchecked_div_assign, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_bitand_assign, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_bitor_assign, &|_, _| {
        expected_bivariate_pbs_output_noise
    });
    test_fn(&ServerKey::unchecked_bitxor_assign, &|_, _| {
        expected_bivariate_pbs_output_noise
    });

    test_fn(&ServerKey::unchecked_mul_lsb_small_carry_assign, &|_, _| {
        if both_are_trivially_encrypted {
            NoiseLevel::ZERO
        } else {
            NoiseLevel::NOMINAL * 2
        }
    });
    test_fn(
        &|sk, ct1, ct2| {
            ServerKey::unchecked_evaluate_bivariate_function_assign(sk, ct1, ct2, |_, _| 0);
        },
        &|_, _| expected_bivariate_pbs_output_noise,
    );
}

fn test_ct_scalar_op_noise_level_propagation(sk: &ServerKey, ct: &Ciphertext, scalar: u8) {
    let test_fn = |op: &dyn Fn(&ServerKey, &Ciphertext, u8) -> Ciphertext,
                   predicate: &dyn Fn(NoiseLevel, u8) -> NoiseLevel| {
        assert_eq!(
            op(sk, ct, scalar).noise_level(),
            predicate(ct.noise_level(), scalar)
        );
    };

    test_fn(&ServerKey::unchecked_scalar_add, &|ct_noise, _| ct_noise);
    test_fn(&ServerKey::unchecked_scalar_sub, &|ct_noise, _| ct_noise);
    test_fn(&ServerKey::unchecked_scalar_mul, &|ct_noise, scalar| {
        ct_noise * u64::from(scalar)
    });
    let expected_pbs_noise = if ct.is_trivial() {
        NoiseLevel::ZERO
    } else {
        NoiseLevel::NOMINAL
    };
    if scalar != 0 {
        test_fn(&ServerKey::unchecked_scalar_div, &|_, _| expected_pbs_noise);
        test_fn(&ServerKey::unchecked_scalar_mod, &|_, _| expected_pbs_noise);
    }
    test_fn(&ServerKey::unchecked_scalar_bitand, &|_, _| {
        expected_pbs_noise
    });
    test_fn(&ServerKey::unchecked_scalar_bitor, &|_, _| {
        expected_pbs_noise
    });
    test_fn(&ServerKey::unchecked_scalar_bitxor, &|_, _| {
        expected_pbs_noise
    });
    if scalar < 8 {
        test_fn(
            &ServerKey::unchecked_scalar_left_shift,
            &|ct_noise, scalar| ct_noise * (1 << scalar as usize),
        );
    }
    test_fn(&ServerKey::unchecked_scalar_right_shift, &|_, _| {
        expected_pbs_noise
    });
}

fn test_ct_scalar_op_assign_noise_level_propagation(sk: &ServerKey, ct: &Ciphertext, scalar: u8) {
    let test_fn = |op: &dyn Fn(&ServerKey, &mut Ciphertext, u8),
                   predicate: &dyn Fn(NoiseLevel, u8) -> NoiseLevel| {
        let mut clone = ct.clone();
        op(sk, &mut clone, scalar);
        assert_eq!(clone.noise_level(), predicate(ct.noise_level(), scalar));
    };

    test_fn(&ServerKey::unchecked_scalar_add_assign, &|ct_noise, _| {
        ct_noise
    });
    test_fn(&ServerKey::unchecked_scalar_sub_assign, &|ct_noise, _| {
        ct_noise
    });
    test_fn(
        &ServerKey::unchecked_scalar_mul_assign,
        &|ct_noise, scalar| ct_noise * u64::from(scalar),
    );
    let expected_pbs_noise = if ct.is_trivial() {
        NoiseLevel::ZERO
    } else {
        NoiseLevel::NOMINAL
    };
    if scalar != 0 {
        test_fn(&ServerKey::unchecked_scalar_div_assign, &|_, _| {
            expected_pbs_noise
        });
        test_fn(&ServerKey::unchecked_scalar_mod_assign, &|_, _| {
            expected_pbs_noise
        });
    }
    test_fn(&ServerKey::unchecked_scalar_bitand_assign, &|_, _| {
        expected_pbs_noise
    });
    test_fn(&ServerKey::unchecked_scalar_bitor_assign, &|_, _| {
        expected_pbs_noise
    });
    test_fn(&ServerKey::unchecked_scalar_bitxor_assign, &|_, _| {
        expected_pbs_noise
    });
    if scalar < 8 {
        test_fn(
            &ServerKey::unchecked_scalar_left_shift_assign,
            &|ct_noise, scalar| ct_noise * (1 << scalar as usize),
        );
    }
    test_fn(&ServerKey::unchecked_scalar_right_shift_assign, &|_, _| {
        expected_pbs_noise
    });
}

#[cfg(not(tarpaulin))] // This test is ignored in coverage, it takes around 4 hours to run otherwise.
#[test]
fn test_noise_level_propagation_ci_run_filter() {
    let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    let keys = KEY_CACHE.get_from_param(params);
    let (ck, sk) = (keys.client_key(), keys.server_key());

    // The goal of this test is to check the noise level is properly propagated
    // thus it does operations in a way that is not correct noise-wise
    let mut sk = sk.clone();
    sk.max_noise_level = MaxNoiseLevel::UNKNOWN;

    let modulus: u64 = params.message_modulus.0;

    for _ in 0..10 {
        let trivial0 = sk.create_trivial(0);

        let trivial = sk.create_trivial(rand::random::<u64>() % modulus);

        let ct1 = ck.encrypt(rand::random::<u64>() % modulus);
        let ct2 = sk.unchecked_add(&ct1, &ct1);

        for ct in [&trivial0, &trivial, &ct1, &ct2] {
            test_ct_unary_op_noise_level_propagation(&sk, ct);
            test_ct_unary_op_assign_noise_level_propagation(&sk, ct);
        }

        for ct_left in [&trivial0, &trivial, &ct1, &ct2] {
            for ct_right in [&trivial0, &trivial, &ct1, &ct2] {
                test_ct_binary_op_noise_level_propagation(&sk, ct_left, ct_right);
                test_ct_binary_op_assign_noise_level_propagation(&sk, ct_left, ct_right);
            }
        }

        for ct in [&trivial0, &trivial, &ct1, &ct2] {
            for scalar in 0..params.carry_modulus.0 * params.message_modulus.0 {
                test_ct_scalar_op_noise_level_propagation(&sk, ct, scalar as u8);
                test_ct_scalar_op_assign_noise_level_propagation(&sk, ct, scalar as u8);
            }
        }
    }
}
