use super::*;
mod data;

#[test]
fn isc_trace_simple() {
    let bytes: Vec<u64> = vec![
        0x180000000,
        0xf1b6e5ec,
        0x2000000200001800,
        0xf1b6e608,
        0x180000000,
        0xf1b6e670,
        0x180000000,
        0xf1b6e710,
        0x180000000,
        0xf1b6e760,
        0x2000000080001c00,
        0xf1b7074c,
        0x2000000100001400,
        0xf1b70798,
        0x2000000200001800,
        0xf1b707b4,
        0x2000000080001c00,
        0xf1b728f0,
        0x2000000100001400,
        0xf1b7293c,
        0x2000000200001800,
        0xf1b72958,
        0x2000000080001c00,
        0xf1b74a94,
        0x2000000100001400,
        0xf1b74ae0,
        0x3fffe00001800,
        0xf1b74afd,
    ];

    let byte_view = bytemuck::try_cast_slice::<_, u8>(bytes.as_slice()).unwrap();
    let stream = IscTraceStream::from_bytes(byte_view);
    println!("stream: {:?}", stream);
}

#[test]
fn isc_trace_v80() {
    let bytes = &data::V80_TEST_DATA;
    let byte_view = bytemuck::try_cast_slice::<_, u8>(bytes.as_slice()).unwrap();
    let stream = IscTraceStream::from_bytes(byte_view);
    println!("stream: {:?}", stream);
}

#[test]
fn isc_trace_v80_2() {
    let bytes = &data::V80_TEST_DATA2;
    let byte_view = bytemuck::try_cast_slice::<_, u8>(bytes.as_slice()).unwrap();
    let stream = IscTraceStream::from_bytes(byte_view);
    println!("stream: {:?}", stream);
}
