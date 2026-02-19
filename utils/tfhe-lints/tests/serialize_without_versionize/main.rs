use serde::Serialize;

#[derive(Serialize)]
struct MyStruct {
    value: u64,
}

fn main() {
    let st = MyStruct { value: 42 };
    println!("{}", st.value);
}
