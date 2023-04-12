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

const ALPHABET_LEN: usize = 128;
const ALPHABET_LOG: usize = 7;

type AsciiDfaStateId = u8;
type BinaryDfaStateId = usize;

fn u8_to_bits_be(n: u8) -> [bool; 8] {
    let mut bits = [false; 8];

    for i in 0..8 {
        bits[i] = (n >> (7 - i)) & 1 != 0;
    }

    bits
}

fn add_binary_transitions_for_all_ascii(
    table: &mut Vec<(Option<BinaryDfaStateId>, Option<BinaryDfaStateId>)>,
    binary_state: BinaryDfaStateId,
    binary_successor: BinaryDfaStateId,
) -> Vec<HashSet<BinaryDfaStateId>> {
    // loop over bits
    let mut depth_slice = vec![HashSet::new(); ALPHABET_LOG];
    let mut curr_binary_state = binary_state;
    for bit in 0..ALPHABET_LOG {
        let last = bit == (ALPHABET_LOG - 1);
        let bit_index = bit;
        let to_state = if last {
            binary_successor
        } else {
            // check if an intermediate state already exists
            // if so, then route through the existing intermediate state
            // prefer 0-transition arbitrarily
            if let Some(to_state) = table[curr_binary_state].0 {
                to_state
            } else if let Some(to_state) = table[curr_binary_state].1 {
                to_state
            } else {
                table.push((None, None));
                table.len() - 1
            }
        };
        depth_slice[bit_index].insert(curr_binary_state);
        table[curr_binary_state] = (Some(to_state), Some(to_state));
        curr_binary_state = to_state;
    }

    depth_slice
}

// Hopcroft's Algorithm: O(n log n), but O(1) since n = 8
fn minimize_binary_dfa(
    dfa: Vec<(Option<BinaryDfaStateId>, Option<BinaryDfaStateId>)>,
    final_states: &HashSet<BinaryDfaStateId>,
) -> (
    Vec<(Option<BinaryDfaStateId>, Option<BinaryDfaStateId>)>,
    Vec<BinaryDfaStateId>,
) {
    let num_states = dfa.len();

    // partition states into initial groups: distinctly final and non-final states
    let mut partitions: Vec<HashSet<_>> = vec![HashSet::new()];
    for state in 0..num_states {
        if final_states.contains(&state) {
            partitions.push(HashSet::from([state]));
        } else {
            partitions[0].insert(state);
        }
    }

    // refine partitions
    let mut work_list: VecDeque<_> = (0..partitions.len()).collect();

    while let Some(partition_id) = work_list.pop_front() {
        for symbol in 0..2 {
            let mut affected_states: HashSet<usize> = HashSet::new();

            for state in 0..num_states {
                let next_state = if symbol == 0 {
                    dfa[state].0
                } else {
                    dfa[state].1
                };
                if let Some(next_state) = next_state {
                    if partitions[partition_id].contains(&next_state) {
                        affected_states.insert(state);
                    }
                }
            }

            if affected_states.is_empty() {
                continue;
            }

            let mut new_partitions = vec![];
            let work_list_set: HashSet<_> = work_list.into_iter().collect();
            let mut new_work_list = VecDeque::new();

            for (i, partition) in partitions.into_iter().enumerate() {
                let intersection: HashSet<_> =
                    partition.intersection(&affected_states).copied().collect();
                let difference: HashSet<_> =
                    partition.difference(&affected_states).copied().collect();

                if !intersection.is_empty() && !difference.is_empty() {
                    // split on symbol
                    let intersection_index = new_partitions.len();
                    let difference_index = new_partitions.len() + 1;
                    let smaller_index = if intersection.len() <= difference.len() {
                        intersection_index
                    } else {
                        difference_index
                    };
                    new_partitions.push(intersection);
                    new_partitions.push(difference);

                    if work_list_set.contains(&i) {
                        new_work_list.push_back(intersection_index);
                        new_work_list.push_back(difference_index);
                    } else {
                        new_work_list.push_back(smaller_index);
                    }
                } else {
                    // cannot split on symbol
                    new_partitions.push(partition);
                    if work_list_set.contains(&i) {
                        new_work_list.push_back(new_partitions.len() - 1);
                    }
                }
            }

            partitions = new_partitions;
            work_list = new_work_list;
        }
    }

    // pin the initial state to 0
    let initial_partition_index = find_partition_id(&partitions, 0);
    if initial_partition_index != 0 {
        partitions.swap(0, initial_partition_index);
    }

    // build the minimized dfa
    let mut minimized_dfa = vec![(None, None); partitions.len()];
    let mut state_mapping = vec![0; num_states];

    for (new_state_id, partition) in partitions.iter().enumerate() {
        let repr_state = *partition.iter().next().unwrap();

        for &original_state in partition {
            state_mapping[original_state] = new_state_id;
        }

        minimized_dfa[new_state_id] = (
            dfa[repr_state].0.map(|s| find_partition_id(&partitions, s)),
            dfa[repr_state].1.map(|s| find_partition_id(&partitions, s)),
        );
    }

    (minimized_dfa, state_mapping)
}

fn find_partition_id(
    partitions: &Vec<HashSet<BinaryDfaStateId>>,
    state: BinaryDfaStateId,
) -> usize {
    partitions
        .iter()
        .position(|part| part.contains(&state))
        .expect("state must be in one of the partitions")
}

fn combine_depth_slices(dst: &mut [HashSet<BinaryDfaStateId>], src: &[HashSet<BinaryDfaStateId>]) {
    dst.iter_mut()
        .zip(src.iter())
        .for_each(|(dst_set, src_set)| dst_set.extend(src_set.iter()));
}

fn add_new_binary_transitions_for_bytes(
    global_table: &mut Vec<(Option<BinaryDfaStateId>, Option<BinaryDfaStateId>)>,
    ascii_to_global_binary_state: &mut HashMap<AsciiDfaStateId, BinaryDfaStateId>,
    ascii_state: AsciiDfaStateId,
    byte_successors: &[(u8, AsciiDfaStateId)],
) -> Vec<HashSet<BinaryDfaStateId>> {
    // note: assumes state has not been processed before
    // create preliminary local binary dfa table
    let mut local_table = vec![(None, None)];
    let mut ascii_to_local_binary_state = HashMap::from([(ascii_state, 0)]);
    let mut binary_successors = HashSet::new();
    for &(byte, ascii_successor) in byte_successors {
        let binary_successor = *ascii_to_local_binary_state
            .entry(ascii_successor)
            .or_insert_with(|| {
                local_table.push((None, None));
                local_table.len() - 1
            });
        add_binary_transitions_for_byte(&mut local_table, 0, byte, binary_successor);
        binary_successors.insert(binary_successor);
    }

    // minimize local dfa
    // initial state is pinned to 0
    let (local_table, state_mapping) = minimize_binary_dfa(local_table, &binary_successors);

    // create rev local binary state to ascii state map with new minimized mapping
    let local_binary_to_ascii_state: HashMap<BinaryDfaStateId, AsciiDfaStateId> =
        ascii_to_local_binary_state
            .iter()
            .map(|(&ascii_state, &local_binary_state)| {
                (state_mapping[local_binary_state], ascii_state)
            })
            .collect();

    // update global table
    let mut local_binary_to_global_binary_state = HashMap::new();
    let get_global_binary_state =
        |local_binary_state,
         local_binary_to_global_binary_state: &mut HashMap<BinaryDfaStateId, BinaryDfaStateId>,
         local_binary_to_ascii_state: &HashMap<BinaryDfaStateId, AsciiDfaStateId>,
         ascii_to_global_binary_state: &mut HashMap<AsciiDfaStateId, BinaryDfaStateId>,
         global_table: &mut Vec<(Option<BinaryDfaStateId>, Option<BinaryDfaStateId>)>| {
            *local_binary_to_global_binary_state
                .entry(local_binary_state)
                .or_insert_with(|| {
                    if let Some(&state) = local_binary_to_ascii_state.get(&local_binary_state) {
                        *ascii_to_global_binary_state
                            .entry(state)
                            .or_insert_with(|| {
                                global_table.push((None, None));
                                global_table.len() - 1
                            })
                    } else {
                        global_table.push((None, None));
                        global_table.len() - 1
                    }
                })
        };
    for (local_binary_state, (transition0, transition1)) in local_table.into_iter().enumerate() {
        // do not overwrite a final state if it already exists in the table
        // exception: always overwrite initial state, because of our assumption that state has not
        // been processed before
        if local_binary_state != 0 {
            if let Some(state) = local_binary_to_ascii_state.get(&local_binary_state) {
                if ascii_to_global_binary_state.contains_key(state) {
                    continue;
                }
            }
        }

        let global_binary_state = get_global_binary_state(
            local_binary_state,
            &mut local_binary_to_global_binary_state,
            &local_binary_to_ascii_state,
            ascii_to_global_binary_state,
            global_table,
        );

        let transition0 = transition0.map(|local_binary_state| {
            get_global_binary_state(
                local_binary_state,
                &mut local_binary_to_global_binary_state,
                &local_binary_to_ascii_state,
                ascii_to_global_binary_state,
                global_table,
            )
        });
        let transition1 = transition1.map(|local_binary_state| {
            get_global_binary_state(
                local_binary_state,
                &mut local_binary_to_global_binary_state,
                &local_binary_to_ascii_state,
                ascii_to_global_binary_state,
                global_table,
            )
        });

        global_table[global_binary_state] = (transition0, transition1);
    }

    // update depth slice
    // perform bfs to update depth slice
    let mut depth_slice = vec![HashSet::new(); ALPHABET_LOG];
    let mut queue = VecDeque::from([(0, local_binary_to_global_binary_state[&0])]);
    while let Some((depth, state)) = queue.pop_front() {
        if depth >= depth_slice.len() {
            continue;
        }
        if depth_slice[depth].insert(state) {
            let (transition0, transition1) = global_table[state];
            if let Some(transition0) = transition0 {
                queue.push_back((depth + 1, transition0));
            }
            if let Some(transition1) = transition1 {
                queue.push_back((depth + 1, transition1));
            }
        }
    }

    depth_slice
}

fn add_binary_transitions_for_byte(
    table: &mut Vec<(Option<BinaryDfaStateId>, Option<BinaryDfaStateId>)>,
    binary_state: BinaryDfaStateId,
    byte: u8,
    binary_successor: BinaryDfaStateId,
) {
    // loop over bits, MSB first
    let mut curr_binary_state = binary_state;
    for bit in 0..ALPHABET_LOG {
        let last = bit == (ALPHABET_LOG - 1);
        let bit = (byte >> (ALPHABET_LOG - bit - 1)) & 1 != 0;
        let mut transitions = table[curr_binary_state];
        let transition = if !bit {
            let (ref mut val0, _) = transitions;
            val0
        } else {
            let (_, ref mut val1) = transitions;
            val1
        };
        curr_binary_state = match *transition {
            None => {
                let to_state = if last {
                    binary_successor
                } else {
                    table.push((None, None));
                    table.len() - 1
                };
                *transition = Some(to_state);
                table[curr_binary_state] = transitions;
                to_state
            }
            Some(to_state) => to_state,
        };
    }
}

// note: this produces a "piecewise-minimized" binary dfa since it minimizes each (state,
// byte_successors) pair (state is a single state, byte_successors is a list of all (byte,
// successor) transitions from state) as its own separate binary dfa before being combined with
// other states into the final binary dfa
// the reason why this is done is if we simply attempted to minimize the entire binary dfa
// at the end, it would simply collapse all of the states into 8 total states, which is not what we
// want, since we want to be able to traverse the dfa with the full length of the bit string with
// length > 8
fn build_binary_dfa_tables(
    dfa: &dense::DenseDFA<Vec<u8>, u8>,
    end_anchored: bool,
    ascii_max_depth: usize,
) -> (
    (
        Vec<(Option<BinaryDfaStateId>, Option<BinaryDfaStateId>)>,
        HashSet<BinaryDfaStateId>,
    ),
    Vec<HashSet<BinaryDfaStateId>>,
) {
    let mut table = vec![];
    let mut depth_table = vec![HashSet::new(); ascii_max_depth * ALPHABET_LOG];
    let mut final_states = HashSet::new();
    let mut queue = VecDeque::from([(0, dfa.start_state())]);
    let mut ascii_to_binary_state = HashMap::new();
    let mut ascii_state_to_depth_slice = HashMap::new();
    let mut visited = HashSet::new();
    // perform depth-limited bfs to traverse the ascii dfa
    while let Some(elem) = queue.pop_front() {
        if visited.contains(&elem) {
            continue;
        }
        visited.insert(elem);
        let (ascii_depth, ascii_state) = elem;
        let binary_state = *ascii_to_binary_state.entry(ascii_state).or_insert_with(|| {
            table.push((None, None));
            table.len() - 1
        });
        if dfa.is_match_state(ascii_state) {
            final_states.insert(binary_state);
        }

        // begin processing of successors
        if ascii_depth == ascii_max_depth {
            continue;
        }
        let depth_slice =
            &mut depth_table[ascii_depth * ALPHABET_LOG..ascii_depth * ALPHABET_LOG + ALPHABET_LOG];
        // add support for no $
        if !end_anchored && dfa.is_match_state(ascii_state) {
            queue.push_back((ascii_depth + 1, ascii_state));
            let curr_depth_slice = ascii_state_to_depth_slice
                .entry(ascii_state)
                .or_insert_with(|| {
                    add_binary_transitions_for_all_ascii(&mut table, binary_state, binary_state)
                });
            combine_depth_slices(depth_slice, &curr_depth_slice);
            continue;
        }
        // ascii-only: 7 bits
        let mut seen_successors = HashSet::new();
        let byte_successors: Vec<_> = (0..ALPHABET_LEN.try_into().unwrap())
            .filter_map(|input| {
                let ascii_successor = dfa.next_state(ascii_state, input);
                if !dfa.is_dead_state(ascii_successor) {
                    if seen_successors.insert(ascii_successor) {
                        queue.push_back((ascii_depth + 1, ascii_successor));
                    }
                    Some((input, ascii_successor))
                } else {
                    None
                }
            })
            .collect();
        let curr_depth_slice = ascii_state_to_depth_slice
            .entry(ascii_state)
            .or_insert_with(|| {
                if byte_successors.len() == ALPHABET_LEN && seen_successors.len() == 1 {
                    let binary_successor = *ascii_to_binary_state
                        .entry(seen_successors.into_iter().next().unwrap())
                        .or_insert_with(|| {
                            table.push((None, None));
                            table.len() - 1
                        });
                    add_binary_transitions_for_all_ascii(&mut table, binary_state, binary_successor)
                } else {
                    add_new_binary_transitions_for_bytes(
                        &mut table,
                        &mut ascii_to_binary_state,
                        ascii_state,
                        &byte_successors,
                    )
                }
            });
        combine_depth_slices(depth_slice, &curr_depth_slice);
    }

    ((table, final_states), depth_table)
}

fn evaluate_binary_dfa(
    table: &[(Option<BinaryDfaStateId>, Option<BinaryDfaStateId>)],
    final_states: &HashSet<BinaryDfaStateId>,
    depth_table: &[HashSet<BinaryDfaStateId>],
    initial: BinaryDfaStateId,
    server_key: &ServerKey,
    bit_ciphertexts: &[Ciphertext],
) -> Ciphertext {
    // Algorithm 6 from https://eprint.iacr.org/2018/421.pdf
    // Note: Remark 6 is used to evaluate the wfa as a dfa
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
                        // Remark 6
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
                        // Remark 6
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
            let (client_key, server_key) = gen_keys();
            let encrypted_string = test
                .plaintext_string
                .par_chars()
                .flat_map(|c| {
                    let c: u8 = c.try_into().expect("expected a UTF-8 value");
                    u8_to_bits_be(c)
                        .into_par_iter()
                        .skip(1)
                        // for correctness testing
                        // .map(|bit| server_key.trivial_encrypt(bit))
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

    println!("Constructing piecewise-minimized ascii dfa from input regex");
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

    if ascii_depth == 0 {
        println!(
            "Trivial short circuit: can evaluate regex on a \"plaintext\" empty string, got {}",
            if dfa.is_match("".as_bytes()) {
                "match"
            } else {
                "no match"
            },
        );
        return;
    }

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
