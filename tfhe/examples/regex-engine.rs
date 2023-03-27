use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

use base64::Engine;
use clap::{Args, Parser, Subcommand};
use dashmap::DashMap;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use rayon::str::ParallelString;
use regex_automata::{dense, DFA};
use tfhe::boolean::prelude::{
    gen_keys, BinaryBooleanGates, Ciphertext, ClientKey, CompressedCiphertext, ServerKey,
};
use tfhe::boolean::server_key::CompressedServerKey;

#[derive(Debug, Parser)]
#[command(name = "homomorphic-regex-engine")]
#[command(author = "Jonathan L. <bukatea@gmail.com>")]
#[command(version = "0.1.0")]
#[command(about = "A homomorphic regex engine", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Plaintext regex.
    regex: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Test mode. Takes a plaintext regex and test string, generates keys and encrypts the test
    /// string, homomorphically evaluates the regex checker on it, then decrypts the result and
    /// checks correctness.
    Test(TestArgs),
    /// Execution mode. Takes a plaintext regex, server key, and encrypted test string,
    /// homomorphically evaluates the regex checker on it, then prints the ciphertext and
    /// optionally decrypts and prints the result.
    Execution(ExecutionArgs),
}

#[derive(Debug, Args)]
struct TestArgs {
    /// Plaintext test string.
    plaintext_string: String,
}

#[derive(Debug, Args)]
struct ExecutionArgs {
    /// Binary file with Bincode-serialized tfhe::boolean::CompressedServerKey, public key for
    /// homomorphic computation on ciphertexts in encrypted_string.
    server_key_file: PathBuf,
    /// Binary file with Bincode-serialized Vec<tfhe::boolean::CompressedCiphertext>, representing
    /// the encrypted test string, encrypted bit by bit. Each ascii character has 7 bits. If the
    /// length of the plaintext string is n, there should be 7n
    /// tfhe::boolean::CompressedCiphertexts.
    encrypted_string_file: PathBuf,
    /// Optional binary file with Bincode-serialized tfhe::boolean::ClientKey for testing purposes.
    /// If provided, the encrypted string will be decrypted and the result will be printed.
    #[arg(short, long)]
    client_key_file: Option<PathBuf>,
}

const ALPHABET_LEN: u8 = 128;
const ALPHABET_LOG: u8 = 7;

// TODO: create newtypes for original dfa state ids and binary dfa state ids

fn u8_to_bits_le(n: u8) -> [bool; 8] {
    let mut bits = [false; 8];
    let mut mask = 0b0000_0001;

    for i in 0..8 {
        if n & mask != 0 {
            bits[i] = true;
        }
        mask <<= 1;
    }

    bits
}

fn add_binary_transitions_for_all_ascii(
    table: &mut Vec<(Option<usize>, Option<usize>)>,
    depth_slice: &mut [HashSet<usize>],
    state_to_table_index: &mut HashMap<u8, usize>,
    state_index: usize,
    successor: u8,
) {
    // loop over bits, LSB first
    let mut curr_state_index = state_index;
    for bit in 0..=(ALPHABET_LOG - 1) {
        let last = bit == (ALPHABET_LOG - 1);
        let bit_index = bit as usize;
        let to_state = if last {
            *state_to_table_index.entry(successor).or_insert_with(|| {
                table.push((None, None));
                table.len() - 1
            })
        } else {
            // check if an intermediate state already exists
            // if so, then route through the existing intermediate state
            // prefer 0-transition arbitrarily
            if let Some(to_state) = table[curr_state_index].0 {
                to_state
            } else if let Some(to_state) = table[curr_state_index].1 {
                to_state
            } else {
                table.push((None, None));
                table.len() - 1
            }
        };
        table[curr_state_index] = (Some(to_state), Some(to_state));
        depth_slice[bit_index].insert(curr_state_index);
        curr_state_index = to_state;
    }
}

// TODO: take in a slice of all bytes and construct intermediate states optimally based on how many
// can be under the same mask
fn add_binary_transitions_for_byte(
    table: &mut Vec<(Option<usize>, Option<usize>)>,
    depth_slice: &mut [HashSet<usize>],
    state_to_table_index: &mut HashMap<u8, usize>,
    state_index: usize,
    byte: u8,
    successor: u8,
) {
    // loop over bits, LSB first
    let mut curr_state_index = state_index;
    for bit in 0..=(ALPHABET_LOG - 1) {
        let last = bit == (ALPHABET_LOG - 1);
        let bit_index = bit as usize;
        let bit = ((byte & (1 << bit)) >> bit) != 0;
        let mut transitions = table[curr_state_index];
        let transition = if !bit {
            let (ref mut val0, _) = transitions;
            val0
        } else {
            let (_, ref mut val1) = transitions;
            val1
        };
        depth_slice[bit_index].insert(curr_state_index);
        curr_state_index = match *transition {
            None => {
                let to_state = if last {
                    *state_to_table_index.entry(successor).or_insert_with(|| {
                        table.push((None, None));
                        table.len() - 1
                    })
                } else {
                    table.push((None, None));
                    table.len() - 1
                };
                *transition = Some(to_state);
                table[curr_state_index] = transitions;
                to_state
            }
            Some(to_state) => to_state,
        };
    }
}

fn build_binary_dfa_tables(
    dfa: &dense::DenseDFA<Vec<u8>, u8>,
    end_anchored: bool,
    ascii_max_depth: usize,
) -> (
    (Vec<(Option<usize>, Option<usize>)>, HashSet<usize>),
    Vec<HashSet<usize>>,
) {
    let mut table = vec![];
    let mut depth_table = vec![HashSet::new(); ascii_max_depth * 7];
    let mut final_states = HashSet::new();
    let mut queue = VecDeque::from([(0, dfa.start_state())]);
    let mut state_to_table_index = HashMap::new();
    let mut visited = HashSet::new();
    // TODO: deal with non-ascii chars by explicitly transitioning to dead state
    // perform depth-limited bfs to traverse the ascii dfa
    while !queue.is_empty() {
        let elem = queue.pop_front().unwrap();
        if visited.contains(&elem) {
            continue;
        }
        visited.insert(elem);
        let (ascii_depth, state) = elem;
        let index = *state_to_table_index.entry(state).or_insert_with(|| {
            table.push((None, None));
            table.len() - 1
        });
        if dfa.is_match_state(state) {
            final_states.insert(index);
        }

        // begin processing of successors
        if ascii_depth == ascii_max_depth {
            continue;
        }
        let depth_slice = &mut depth_table[ascii_depth as usize * ALPHABET_LOG as usize
            ..ascii_depth as usize * ALPHABET_LOG as usize + ALPHABET_LOG as usize];
        // add support for no $
        if !end_anchored && dfa.is_match_state(state) {
            assert!(
                !(table[index]
                    .0
                    .filter(|state| table[index].1.filter(|other| other != state).is_some())
                    .is_some()),
                "oh shiiiiiiiiiiiiiiit"
            );
            add_binary_transitions_for_all_ascii(
                &mut table,
                depth_slice,
                &mut state_to_table_index,
                index,
                state,
            );
            queue.push_back((ascii_depth + 1, state));
            continue;
        }
        // ascii-only: 7 bits
        let mut seen_successors = [false; ALPHABET_LEN as usize];
        for input in 0..=(ALPHABET_LEN - 1) {
            let successor = dfa.next_state(state, input);
            if dfa.is_dead_state(successor) {
                continue;
            }
            add_binary_transitions_for_byte(
                &mut table,
                depth_slice,
                &mut state_to_table_index,
                index,
                // for consistent endianness across machines
                input.to_le(),
                successor,
            );
            if seen_successors[successor as usize] {
                continue;
            }
            seen_successors[successor as usize] = true;
            queue.push_back((ascii_depth + 1, successor));
        }
    }
    ((table, final_states), depth_table)
}

fn evaluate_binary_dfa(
    table: &[(Option<usize>, Option<usize>)],
    final_states: &HashSet<usize>,
    depth_table: &[HashSet<usize>],
    initial: usize,
    server_key: &ServerKey,
    bit_ciphertexts: &[Ciphertext],
) -> Ciphertext {
    // Algorithm 6 from https://eprint.iacr.org/2018/421.pdf
    let max_depth = bit_ciphertexts.len();
    assert_eq!(
        depth_table.len(),
        max_depth,
        "expected {} depth entries in depth table, got {}",
        max_depth,
        depth_table.len()
    );
    let false_ciphertext = server_key.trivial_encrypt(false);
    let mut ciphertexts: DashMap<usize, Ciphertext> = DashMap::new();
    println!("\nBit depth: accessible states");
    for depth in (0..max_depth).rev() {
        print!("{:>9}:", depth);
        let new_ciphertexts = DashMap::new();
        depth_table[depth].par_iter().for_each(|accessible_state| {
            print!(" {}", accessible_state);
            io::stdout().flush().unwrap();
            let (zero_case, one_case) = table[*accessible_state];
            let ciphertext = server_key.mux(
                &bit_ciphertexts[depth],
                &match one_case {
                    None => false_ciphertext.clone(),
                    Some(one_case) => server_key.or(
                        &ciphertexts
                            .get(&one_case)
                            .map_or(false_ciphertext.clone(), |r| r.clone()),
                        &server_key.trivial_encrypt(
                            depth == max_depth - 1 && final_states.contains(&one_case),
                        ),
                    ),
                },
                &match zero_case {
                    None => false_ciphertext.clone(),
                    Some(zero_case) => server_key.or(
                        &ciphertexts
                            .get(&zero_case)
                            .map_or(false_ciphertext.clone(), |r| r.clone()),
                        &server_key.trivial_encrypt(
                            depth == max_depth - 1 && final_states.contains(&zero_case),
                        ),
                    ),
                },
            );
            new_ciphertexts.insert(*accessible_state, ciphertext);
        });
        ciphertexts = new_ciphertexts;
        println!();
    }
    println!();
    ciphertexts.remove(&initial).unwrap().1
}

fn main() {
    let args = Cli::parse();
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
    assert!(
        input_regex_bounds.1 - input_regex_bounds.0 > 0,
        "no input regex to match against"
    );

    // handle ^ and $
    if args.regex[input_regex_bounds.0..input_regex_bounds.1].starts_with('^') {
        start_anchored = true;
        input_regex_bounds.0 += 1
    }
    if args.regex[input_regex_bounds.0..input_regex_bounds.1].ends_with('$') {
        end_anchored = true;
        input_regex_bounds.1 -= 1
    }

    // only pattern that can match an empty string is ^, $, or ^$
    let (client_key_opt, server_key, encrypted_string) = match &args.command {
        Commands::Test(test) => {
            println!("--------------------TEST MODE--------------------");
            println!("regex: {}", args.regex);
            println!("plaintext string: {}", test.plaintext_string);
            if test.plaintext_string.len() == 0 {
                println!(
                    "Trivial short circuit: only pattern that can match an empty string is ^, $, or ^$, got {}",
                    if (start_anchored || end_anchored) && input_regex_bounds.1 - input_regex_bounds.0 == 0 {
                        "match"
                    } else {
                        "no match"
                    },
                );
                return;
            }
            let (client_key, server_key) = gen_keys();
            let encrypted_string = test
                .plaintext_string
                .par_chars()
                .flat_map(|c| {
                    let c: u8 = c.try_into().expect("expected a UTF-8 value");
                    u8_to_bits_le(c)
                        .into_par_iter()
                        .take(ALPHABET_LOG.into())
                        .map(|bit| client_key.encrypt(bit))
                })
                .collect();
            (Some(client_key), server_key, encrypted_string)
        }
        Commands::Execution(execution) => {
            println!("------------------EXECUTION MODE------------------");
            println!("regex: {}", args.regex);
            println!(
                "compressed server key file: {}",
                &execution.server_key_file.display()
            );
            println!(
                "compressed encrypted string file: {}",
                &execution.encrypted_string_file.display()
            );
            if let Some(client_key_file) = &execution.client_key_file {
                println!("client key file: {}", client_key_file.display());
            }
            let encrypted_string: Vec<_> = bincode::deserialize::<Vec<CompressedCiphertext>>(
                &fs::read(&execution.encrypted_string_file)
                    .expect("error reading compressed encrypted string file"),
            )
            .expect("error deserializing list of compressed boolean ciphertexts")
            .into_iter()
            .map(Into::into)
            .collect();
            if encrypted_string.len() == 0 {
                println!(
                    "Trivial short circuit: only pattern that can match an empty string is ^, $, or ^$, got {}",
                    if (start_anchored || end_anchored) && input_regex_bounds.1 - input_regex_bounds.0 == 0 {
                        "match"
                    } else {
                        "no match"
                    },
                );
                return;
            }
            let server_key: ServerKey = bincode::deserialize::<CompressedServerKey>(
                &fs::read(&execution.server_key_file)
                    .expect("error reading compressed server key file"),
            )
            .expect("error deserializing compressed server key")
            .into();
            let client_key: Option<ClientKey> =
                execution.client_key_file.as_ref().map(|client_key_file| {
                    bincode::deserialize(
                        &fs::read(client_key_file).expect("error reading client key file"),
                    )
                    .expect("error deserializing client key")
                });

            (client_key, server_key, encrypted_string)
        }
    };

    assert_eq!(
        encrypted_string.len() % 7,
        0,
        "expected a 7-bit encryption of each character"
    );
    println!(
        "Input regex is {}, with {} LWE bit ciphertexts",
        args.regex,
        encrypted_string.len()
    );
    let ascii_depth = encrypted_string.len() / 7;

    println!("Constructing minimized ascii dfa from input regex");
    let now = Instant::now();
    // build minimized ascii-only dfa
    let dfa = dense::Builder::new()
        .minimize(true)
        .unicode(false)
        // for . to work
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

    println!("Converting to binary dfa look up table");
    // does not support $, so must inject support into the binary dfa
    // build binary dfa table (with final states) and table of states reachable by depth
    let ((table, final_states), depth_table) =
        build_binary_dfa_tables(&dfa, end_anchored, ascii_depth);
    println!(
        "Created table with {} states, and {} final states",
        table.len(),
        final_states.len()
    );
    println!("An ascii string is a match if and only if, evaluating the binary dfa on the binary decompositions of each ascii character in sequence, the end state is a final state");
    println!("Otherwise (if a dead state is reached or the end state is nonfinal), the string is not a match for the regex");

    println!("Homomorphically evaluating binary dfa on ciphertexts");
    // homomorphically evaluate binary dfa on bit-ciphertexts
    let res = evaluate_binary_dfa(
        &table,
        &final_states,
        &depth_table,
        0,
        &server_key,
        &encrypted_string,
    );
    let time = now.elapsed();
    println!(
        "Result ciphertext is {}",
        base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&res).unwrap())
    );

    match &args.command {
        Commands::Test(test) => {
            use regex::Regex;

            let client_key = client_key_opt.unwrap();
            // decrypt homomorphically computed result
            let actual_result = client_key.decrypt(&res);
            // reconstruct regex in regex::Regex format
            let regex = format!(
                "{}{}{}{}",
                if start_anchored { "^" } else { "" },
                if insensitive { "(?i)" } else { "" },
                &args.regex[input_regex_bounds.0..input_regex_bounds.1],
                if end_anchored { "$" } else { "" }
            );
            let expected_result = Regex::new(&regex).unwrap().is_match(&test.plaintext_string);
            if actual_result == expected_result {
                println!(
                    "Test passed, expected result {} matches actual result {}",
                    expected_result, actual_result
                );
            } else {
                println!(
                    "Test failed, expected result {} does not match actual result {}",
                    expected_result, actual_result
                );
            }
        }
        Commands::Execution(_) => {
            if let Some(client_key) = client_key_opt {
                // decrypt homomorphically computed result
                let res = client_key.decrypt(&res);
                println!("Result is {}", res);
            }
        }
    };

    println!("Took {} ms", time.as_millis());
}
