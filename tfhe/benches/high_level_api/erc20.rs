use criterion::Criterion;
use rand::prelude::*;
use rand::thread_rng;
use std::ops::{Add, Mul, Sub};
use tfhe::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::{
    set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, FheBool, FheUint32, FheUint64,
};

fn transfer_whitepaper<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: Add<Output = FheType> + for<'a> FheOrd<&'a FheType>,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<Output = FheType> + Sub<Output = FheType>,
{
    let has_enough_funds = (from_amount).ge(amount);

    let mut new_to_amount = to_amount + amount;
    new_to_amount = has_enough_funds.if_then_else(&new_to_amount, to_amount);

    let mut new_from_amount = from_amount - amount;
    new_from_amount = has_enough_funds.if_then_else(&new_from_amount, from_amount);

    (new_from_amount, new_to_amount)
}

fn transfer<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: Add<Output = FheType> + CastFrom<FheBool> + for<'a> FheOrd<&'a FheType>,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType:
        Add<Output = FheType> + Sub<Output = FheType> + Mul<FheType, Output = FheType>,
{
    let has_enough_funds = (from_amount).ge(amount);

    let amount = amount * FheType::cast_from(has_enough_funds);

    let new_to_amount = to_amount + &amount;
    let new_from_amount = from_amount - &amount;

    (new_from_amount, new_to_amount)
}

fn transfer_overflow<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: CastFrom<FheBool> + for<'a> FheOrd<&'a FheType>,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<FheType, Output = FheType>
        + OverflowingSub<&'a FheType, Output = FheType>
        + Mul<FheType, Output = FheType>,
{
    let (new_from, did_not_have_enough) = (from_amount).overflowing_sub(amount);

    let new_from_amount = did_not_have_enough.if_then_else(from_amount, &new_from);

    let had_enough_funds = !did_not_have_enough;
    let new_to_amount = to_amount + (amount * FheType::cast_from(had_enough_funds));

    (new_from_amount, new_to_amount)
}

fn transfer_safe<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    for<'a> &'a FheType: OverflowingSub<&'a FheType, Output = FheType>
        + OverflowingAdd<&'a FheType, Output = FheType>,
    FheBool: IfThenElse<FheType>,
{
    let (new_from, did_not_have_enough_funds) = (from_amount).overflowing_sub(amount);
    let (new_to, did_not_have_enough_space) = (to_amount).overflowing_add(amount);

    let something_not_ok = did_not_have_enough_funds | did_not_have_enough_space;

    let new_from_amount = something_not_ok.if_then_else(from_amount, &new_from);
    let new_to_amount = something_not_ok.if_then_else(to_amount, &new_to);

    (new_from_amount, new_to_amount)
}

fn bench_transfer_fn<FheType, F>(
    c: &mut Criterion,
    client_key: &ClientKey,
    type_name: &str,
    fn_name: &str,
    transfer_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey>,
    F: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType),
{
    let id_name = format!("{fn_name}::{type_name}");
    c.bench_function(&id_name, |b| {
        let mut rng = thread_rng();

        let from_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
        let to_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
        let amount = FheType::encrypt(rng.gen::<u64>(), client_key);

        b.iter(|| {
            let (_, _) = transfer_func(&from_amount, &to_amount, &amount);
        })
    });
}

fn main() {
    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS, None).build();
    let cks = ClientKey::generate(config);
    let compressed_sks = CompressedServerKey::new(&cks);

    set_server_key(compressed_sks.decompress());

    let mut c = Criterion::default().configure_from_args();

    // FheUint32
    {
        bench_transfer_fn(
            &mut c,
            &cks,
            "FheUint32",
            "transfer_whitepaper",
            transfer_whitepaper::<FheUint32>,
        );
        bench_transfer_fn(&mut c, &cks, "FheUint32", "transfer", transfer::<FheUint32>);
        bench_transfer_fn(
            &mut c,
            &cks,
            "FheUint32",
            "transfer_overflow",
            transfer_overflow::<FheUint32>,
        );
        bench_transfer_fn(
            &mut c,
            &cks,
            "FheUint32",
            "transfer_safe",
            transfer_safe::<FheUint32>,
        );
    }

    // FheUint64
    {
        bench_transfer_fn(
            &mut c,
            &cks,
            "FheUint64",
            "transfer_whitepaper",
            transfer_whitepaper::<FheUint64>,
        );
        bench_transfer_fn(&mut c, &cks, "FheUint64", "transfer", transfer::<FheUint64>);
        bench_transfer_fn(
            &mut c,
            &cks,
            "FheUint64",
            "transfer_overflow",
            transfer_overflow::<FheUint64>,
        );
        bench_transfer_fn(
            &mut c,
            &cks,
            "FheUint64",
            "transfer_safe",
            transfer_safe::<FheUint64>,
        );
    }

    c.final_summary();
}
