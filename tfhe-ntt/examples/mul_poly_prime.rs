use rand::random;
use tfhe_ntt::prime32::Plan;

fn main() {
    // define suitable NTT prime and polynomial size
    let p: u32 = 1073479681;
    let polynomial_size = 1024;

    // unwrapping is fine here because we know roots of unity exist for the combination
    // `(polynomial_size, p)`
    let lhs_poly: Vec<u32> = (0..polynomial_size).map(|_| random::<u32>() % p).collect();
    let rhs_poly: Vec<u32> = (0..polynomial_size).map(|_| random::<u32>() % p).collect();

    // method 1: schoolbook algorithm
    let add = |x: u32, y: u32| ((x as u64 + y as u64) % p as u64) as u32;
    let sub = |x: u32, y: u32| add(x, p - y);
    let mul = |x: u32, y: u32| ((x as u64 * y as u64) % p as u64) as u32;

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
    let plan = Plan::try_new(polynomial_size, p).unwrap();
    let mut lhs_ntt = lhs_poly;
    let mut rhs_ntt = rhs_poly;

    // convert to NTT domain
    plan.fwd(&mut lhs_ntt);
    plan.fwd(&mut rhs_ntt);

    // perform elementwise multiplication and normalize (result is stored in `lhs_ntt`)
    plan.mul_assign_normalize(&mut lhs_ntt, &rhs_ntt);

    // convert back to standard domain
    plan.inv(&mut lhs_ntt);

    // check that method 1 and method 2 give the same result
    assert_eq!(lhs_ntt, negacyclic_convolution);
    println!("Success!");
}
