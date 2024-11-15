use rand::random;
use tfhe_ntt::native32::Plan32;

fn main() {
    // define suitable polynomial size. Power of two polynomial sizes up to `2^16` are supported.
    let polynomial_size = 1024;

    let lhs_poly: Vec<u32> = (0..polynomial_size).map(|_| random::<u32>()).collect();
    let rhs_poly: Vec<u32> = (0..polynomial_size).map(|_| random::<u32>()).collect();

    // method 1: schoolbook algorithm
    let add = |x: u32, y: u32| x.wrapping_add(y);
    let sub = |x: u32, y: u32| x.wrapping_sub(y);
    let mul = |x: u32, y: u32| x.wrapping_mul(y);

    let mut full_convolution = vec![0; 2 * polynomial_size];
    for i in 0..polynomial_size {
        for j in 0..polynomial_size {
            full_convolution[i + j] = add(full_convolution[i + j], mul(lhs_poly[i], rhs_poly[j]));
        }
    }

    let mut negacyclic_convolution = vec![0; polynomial_size];
    for i in 0..polynomial_size {
        negacyclic_convolution[i] = sub(full_convolution[i], full_convolution[polynomial_size + i]);
    }

    // method 2: NTT
    let plan = Plan32::try_new(polynomial_size).unwrap();
    let mut product_poly = vec![0; polynomial_size];

    // convert to NTT domain
    plan.negacyclic_polymul(&mut product_poly, &lhs_poly, &rhs_poly);

    // check that method 1 and method 2 give the same result
    assert_eq!(product_poly, negacyclic_convolution);
    println!("Success!");
}
