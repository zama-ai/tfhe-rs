use std::collections::{HashMap, HashSet, VecDeque};

use clap::Parser;
use regex_automata::{dense, DFA};
use tfhe::shortint::Ciphertext;

#[derive(Debug, Parser)]
#[command(name = "homomorphic-regex-engine")]
#[command(author = "Jonathan L. <bukatea@gmail.com>")]
#[command(version = "0.1.0")]
#[command(about = "A homomorphic regex engine", long_about = None)]
struct Args {
    /// Plaintext regex
    regex: String,
    /// Json-Serialized Vec<tfhe::shortint::Ciphertext>, representing the encrypted test string
    encrypted_string: String,
}

const ALPHABET_LEN: u8 = 128;
const ALPHABET_LOG: u8 = 7;

// TODO: create newtypes for original dfa state ids and binary dfa state ids

fn add_binary_transitions_for_all_ascii(
    table: &mut Vec<(Option<usize>, Option<usize>)>,
    states_to_table_index: &mut HashMap<u8, usize>,
    state_index: usize,
    successor: u8,
) -> bool {
    // loop over bits, LSB first
    let mut new_state = false;
    let mut curr_state_index = state_index;
    assert_eq!(
        table[curr_state_index],
        (None, None),
        "should only be called on freshly processed states"
    );
    for bit in 0..=(ALPHABET_LOG - 1) {
        let last = bit == (ALPHABET_LOG - 1);
        let mut transitions = &mut table[curr_state_index];
        let to_state = if last {
            *states_to_table_index.entry(successor).or_insert_with(|| {
                new_state = true;
                table.push((None, None));
                table.len() - 1
            })
        } else {
            table.push((None, None));
            table.len() - 1
        };
        table[curr_state_index] = (Some(to_state), Some(to_state));
        curr_state_index = to_state;
    }
    new_state
}

// TODO: take in a slice of all bytes and construct intermediate states optimally based on how many
// can be under the same mask
// returns true if found new state
fn add_binary_transitions_for_byte(
    table: &mut Vec<(Option<usize>, Option<usize>)>,
    states_to_table_index: &mut HashMap<u8, usize>,
    state_index: usize,
    byte: u8,
    successor: u8,
) -> bool {
    // loop over bits, LSB first
    let mut new_state = false;
    let mut curr_state_index = state_index;
    for bit in 0..=(ALPHABET_LOG - 1) {
        let last = bit == (ALPHABET_LOG - 1);
        let bit = (byte & (1 << bit)) >> bit;
        let mut transitions = table[curr_state_index];
        let transition = if bit == 0 {
            let (ref mut val0, _) = transitions;
            val0
        } else if bit == 1 {
            let (_, ref mut val1) = transitions;
            val1
        } else {
            panic!("something terrible has happened")
        };
        match *transition {
            None => {
                let to_state = if last {
                    *states_to_table_index.entry(successor).or_insert_with(|| {
                        new_state = true;
                        table.push((None, None));
                        table.len() - 1
                    })
                } else {
                    table.push((None, None));
                    table.len() - 1
                };
                *transition = Some(to_state);
                table[curr_state_index] = transitions;
                curr_state_index = to_state;
            }
            Some(to_state) => {
                assert!(!last, "at least one new transition should always be added for the byte by construction");
                curr_state_index = to_state;
            }
        }
    }
    new_state
}

fn build_dfa_binary_table(
    dfa: &dense::DenseDFA<Vec<u8>, u8>,
    end_anchored: bool,
) -> (Vec<(Option<usize>, Option<usize>)>, HashSet<usize>) {
    let mut table = vec![];
    let mut final_states = HashMap::new();
    let mut queue = VecDeque::from([dfa.start_state()]);
    let mut states_to_table_index = HashMap::new();
    let mut visited = HashSet::new();
    // TODO: deal with non-ascii chars by explicitly transitioning to dead state
    while !queue.is_empty() {
        let state = queue.pop_front().unwrap();
        if visited.contains(&state) {
            continue;
        }
        let index = *states_to_table_index.entry(state).or_insert_with(|| {
            table.push((None, None));
            table.len() - 1
        });
        visited.insert(state);
        if dfa.is_match_state(state) {
            final_states.insert(index, state);
        }
        // ascii-only: 7 bits
        for input in 0..=(ALPHABET_LEN - 1) {
            let successor = dfa.next_state(state, input);
            if dfa.is_dead_state(successor) {
                continue;
            }
            if add_binary_transitions_for_byte(
                &mut table,
                &mut states_to_table_index,
                index,
                input,
                successor,
            ) {
                queue.push_back(successor);
            }
        }
    }
    // add support for $
    if !end_anchored {
        for (&final_state_index, &final_state) in &final_states {
            assert!(
                !add_binary_transitions_for_all_ascii(
                    &mut table,
                    &mut states_to_table_index,
                    final_state_index,
                    final_state
                ),
                "a new state should not be added here"
            );
        }
    }
    (table, final_states.into_keys().collect())
}

fn main() {
    let args = Args::parse();
    println!("{:#?}", args);
    let mut input_regex_bounds = (0, args.regex.len());
    let mut insensitive = false;
    let mut start_anchored = false;
    let mut end_anchored = false;

    // handle case insensitivity and / delimiters
    if args.regex.starts_with('/') {
        if args.regex.ends_with("/i") {
            insensitive = true;
            input_regex_bounds.0 += 1;
            input_regex_bounds.1 -= 2;
        } else if args.regex.ends_with('/') {
            input_regex_bounds.0 += 1;
            input_regex_bounds.1 -= 1;
        } else {
            panic!("expected closing /");
        }
    }

    // handle ^ and $
    if args.regex[input_regex_bounds.0..input_regex_bounds.1].starts_with('^') {
        start_anchored = true;
        input_regex_bounds.0 += 1
    }
    if args.regex[input_regex_bounds.0..input_regex_bounds.1].ends_with('$') {
        end_anchored = true;
        input_regex_bounds.1 -= 1
    }

    //    let encrypted_string: Vec<Ciphertext> = serde_json::from_str(&args.encrypted_string)
    //        .expect("error deserializing encrypted string as list of shortint ciphertexts");

    // build minimized ascii-only dfa
    let dfa = dense::Builder::new()
        .minimize(true)
        .unicode(false)
        .allow_invalid_utf8(true)
        .byte_classes(false)
        .premultiply(false)
        .case_insensitive(insensitive)
        .anchored(start_anchored)
        .build_with_size::<u8>(&args.regex[input_regex_bounds.0..input_regex_bounds.1])
        .expect("error building dfa from regex");
    assert!(
        matches!(dfa, dense::DenseDFA::Standard(_)),
        "expected standard dfa without premultiplication or byte classes"
    );

    // does not support $, so must inject support into the binary dfa
    let (table, final_states) = build_dfa_binary_table(&dfa, end_anchored);
    println!("table: {:#?}", table);
    println!("table_len: {}", table.len());
    println!("final_states: {:#?}", final_states);
    for final_state in &final_states {
        println!("final_state: {:#?}", table[*final_state]);
    }
    let mut state = 0;
    for c in args.encrypted_string.chars() {
        for bit in 0..=(ALPHABET_LOG - 1) {
            let bit = ((c as u8) & (1 << bit)) >> bit;
            if bit == 0 {
                state = table[state].0.unwrap();
            } else {
                state = table[state].1.unwrap();
            }
        }
    }
    assert!(final_states.contains(&state));
}

// TODO: add tests for plaintext binary dfa and encrypted binary dfa
