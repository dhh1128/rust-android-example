#![cfg(target_os="android")]
#![allow(non_snake_case)]

use std::ffi::{CString, CStr};
use jni::JNIEnv;
use jni::objects::{JObject, JString};
use jni::sys::{jstring};

#[no_mangle]
pub unsafe extern fn Java_com_example_android_MainActivity_hello(env: JNIEnv, _: JObject, j_recipient: JString) -> jstring {
    let recipient = CString::from(
        CStr::from_ptr(
            env.get_string(j_recipient).unwrap().as_ptr()
        )
    );

    let output = env.new_string("Hello ".to_owned() + recipient.to_str().unwrap()).unwrap();
    output.into_inner()

    //use std::time::Instant;
    //let start = Instant::now();
    //experiment(4, 0.001);
    //let summary = format!("Experiment ran in {} millis, ", start.elapsed().as_millis());
    //let output = env.new_string(summary + recipient.to_str().unwrap()).unwrap();
    //output.into_inner()
}

use bulletproofs_amcl::{
    r1cs::gadgets::{
        helper_constraints::{
            sparse_merkle_tree_8_ary::{VanillaSparseMerkleTree8, DbVal8ary},
            poseidon::{PoseidonParams, SboxType}
        },
        merkle_tree_hash::PoseidonHash8
    },
    utils::hash_db::InMemoryHashDb
};
use amcl_wrapper::field_elem::FieldElement;
use std::io;
use std::io::Write;

mod bitmap;

//extern crate jemalloc_ctl;
//extern crate jemallocator;

fn byte_count_to_friendly(byte_count: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * KB;
    const GB: f64 = KB * MB;
    let fbyte_count = byte_count as f64;

    if fbyte_count > GB {
        format!("{:.1} GB", fbyte_count / GB)
    } else if fbyte_count > MB {
        format!("{:.1} MB", fbyte_count / MB)
    } else if fbyte_count > KB {
        format!("{:.1} KB", fbyte_count / KB)
    } else {
        format!("{} bytes", byte_count)
    }
}

pub fn get_net_allocated_memory(relative_to_base: usize) -> usize {
    2000000
    // Force an updated of cached statistics.
//    jemalloc_ctl::epoch::advance().unwrap();
//    let a = jemalloc_ctl::stats::allocated::read().unwrap() - relative_to_base;
//    a
}

pub fn get_allocated_memory() -> usize {
    get_net_allocated_memory(0)
}

pub fn memdump(milestone: &str, base_value: usize) -> usize {
    let a = get_net_allocated_memory(base_value);
    println!("At {}, using {} of memory.", milestone, &byte_count_to_friendly(a));
    a
}

pub fn experiment(depth: usize, fill_ratio: f64) {

    let start_allocated = memdump("start of experiment", 0);

    let mut db = make_db();

    let hash_params = make_hash_params();

    let hash_func = PoseidonHash8 {
        params: &hash_params,
        sbox: &SboxType::Quint,
    };
    let mut tree = VanillaSparseMerkleTree8::new(&hash_func, depth as usize, &mut db).unwrap();

    // How many leaf nodes does this tree have?
    let capacity = (8 as u64).pow(depth as u32);
    // So, given the desired fill ratio, how many inserts should we do?
    let insert_count = (capacity as f64 * fill_ratio) as u64;
    use rand::distributions::{Distribution, Uniform};
    let dist = Uniform::from(0..capacity);

    println!("Capacity of tree = {}; filling {}% or {}.", capacity, fill_ratio * 100.0, insert_count);

    use std::time::Instant;
    let now = Instant::now();
    let mut rng = rand::thread_rng();
    for i in 0..insert_count {
        let s = FieldElement::from(dist.sample(&mut rng));
        tree.update(&s, FieldElement::one(), &mut db).unwrap();
        io::stdout().write_all(b".").ok();
        if i % 100 == 99 {
            io::stdout().write_all(b"\n").ok();
            memdump(&format!("{} nodes inserted", i + 1), start_allocated);
        }
        io::stdout().flush().ok();
    }

    let elapsed = now.elapsed().as_millis();
    println!("\nFill experiment completed after {} milliseconds ({} millis / insert).",
             elapsed, (elapsed as f64) / (insert_count as f64));
    println!("{} nodes now in tree.", db.len());
    memdump("end of fill experiment", start_allocated);

    use std::path::Path;
    let path = Path::new("/tmp/x.zip");
    let now = Instant::now();
    db.save(path, &tree.root).ok();
    let elapsed = now.elapsed().as_millis();
    println!("Saved and compressed file in {} millis.", elapsed);

    use std::fs;
    let uncompressed_size = 432 * db.len();
    let compressed_size = fs::metadata(path).unwrap().len();
    let compression_ratio = 1.0 - (compressed_size as f64 / uncompressed_size as f64);

    println!("Saved hashdb ({} bytes) to compressed file {} ({} bytes; {:.1}% compression).",
             uncompressed_size, path.display(), compressed_size, compression_ratio * 100.0);

    let mut db2 = Db::new();
    let now = Instant::now();
    let root2 = db2.load(path).unwrap();
    let elapsed = now.elapsed().as_millis();
    println!("Loading db back from disk took {} millis.", elapsed);
    if root2.eq(&tree.root) {
        if db2.len() == db.len() {
            println!("Integrity check passed.");
        } else {
            println!("Databases aren't the same size (original={}, reconstituted={}).",
                     db.len(), db2.len());
        }
    } else {
        println!("Roots changed.");
    }

    let now = Instant::now();
    let mut revlist = bitmap::Bitmap::new(capacity as usize).unwrap();
    for _ in 0..insert_count {
        revlist.set_bit(dist.sample(&mut rng) as usize);
    }
    let elapsed = now.elapsed().as_millis();
    println!("Set {} bits in bitmap in {} millis.", insert_count, elapsed);

    let mut db = make_db();
    let hash_params = make_hash_params();
    let hash_func = PoseidonHash8 {
        params: &hash_params,
        sbox: &SboxType::Quint,
    };
    let now = Instant::now();
    let _tree2 = build_tree_from_bitmap(depth, &revlist, &hash_func, &mut db);
    println!("Built tree from bitmap in {} millis.", now.elapsed().as_millis());
}

fn build_tree_from_bitmap<'a>(
    depth: usize, b: &bitmap::Bitmap,
    hash_func: &'a PoseidonHash8,
    db: &mut Db) -> Tree<'a> {

    use bulletproofs_amcl::r1cs::gadgets::merkle_tree_hash::Arity8MerkleTreeHash;
    use bulletproofs_amcl::utils::hash_db::HashDb;

    // Create a tree of the right depth. This will prepopulate the hash db with the hashes
    // of the 1- and 0-bit leaf nodes, plus all parents of those up to root.
    let mut tree = VanillaSparseMerkleTree8::new(
        hash_func, depth as usize, db).unwrap();

    //struct PossiblyOwnedFieldElement {
    //    FieldElement *;
    //    owned;
    //}
    let capacity: usize = 8_u32.pow((depth - 1) as u32) as usize;
    let mut children_at_prev_level: Vec<FieldElement> = Vec::with_capacity(capacity);
    // Create the value that represents 1 set bit.
    let one = FieldElement::one();
    // Create the most common set of children we're going to see.
    let all_zeros: DbVal8ary = [
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
    ];
    // Figure out what the hash of all zeros is. We'll use this so often that it's
    // worth caching.
    let hash_all_zeros = hash_func.hash(all_zeros.to_vec()).unwrap();
    let mut i = 0;
    loop {
        let next8 = b.get_byte_for_bit(i);
        // If any bits are set...
        if next8 > 0 {
            let mut siblings = all_zeros.clone();
            let mut sibling_index = 0;
            for j in i..i+8 {
                if b.get_bit(j) {
                    siblings[sibling_index] = one.clone();
                }
                sibling_index += 1;
            }
            let this_hash = hash_func.hash(siblings.to_vec()).unwrap();
            children_at_prev_level.push(this_hash.clone());
            let this_hash_bytes = this_hash.to_bytes();
            if !db.contains_key(&this_hash_bytes) {
                db.insert(this_hash_bytes, siblings);
            }
        } else {
            // Nothing to do. All vacant leaf nodes already exist in the sparse tree.
            children_at_prev_level.push(hash_all_zeros.clone());
        }
        i += 8;
        if i >= b.len() {
            break;
        }
    }

    for _level in (2..depth).rev() {
        let children_at_this_level = children_at_prev_level;
        children_at_prev_level = Vec::new();
        let mut i = children_at_this_level.len() - 8;
        loop {
            let siblings = &children_at_this_level.as_slice()[i..i+8];
            let this_hash = hash_func.hash(siblings.to_vec()).unwrap();
            children_at_prev_level.push(this_hash.clone());
            let this_hash_bytes = this_hash.to_bytes();
            if !db.contains_key(&this_hash_bytes) {
                let array: DbVal8ary = [
                    siblings[0].clone(),
                    siblings[1].clone(),
                    siblings[2].clone(),
                    siblings[3].clone(),
                    siblings[4].clone(),
                    siblings[5].clone(),
                    siblings[6].clone(),
                    siblings[7].clone(),
                ];
                db.insert(this_hash_bytes, array);
            }
            if i == 0 {
                break;
            }
            i -= 8;
        }
    }
    tree.root = hash_func.hash(children_at_prev_level).unwrap();
    tree
    //Tree::new_from_precomputed(&hash_func, depth, &root).unwrap()
}

// ------------------------------------------------------------------
// The functions below are mainly used for benchmarking. They're designed
// to isolate particular pieces of logic that might perform in interesting
// ways. They are NOT very good functions to use for general merkle tree
// coding, because they encapsulate things in odd ways to make performance
// tests as crisp as possible.

/// The type used to store leaves of the merkle tree.
pub type Db = InMemoryHashDb::<DbVal8ary>;
pub type El = FieldElement;

pub type Tree<'a> = VanillaSparseMerkleTree8<'a, PoseidonHash8<'a>>;

// Very fast. Profiler says average 15 nanoseconds.
pub fn make_db() -> Db {
    Db::new()
}

// Comparatively slow. Profiler says average 2 milliseconds.
pub fn make_hash_params() -> PoseidonParams {
    let width = 9;
    // The following values are appropriate for any of the following curves:
    // bls381, bn254, secp256k1, and ed25519.
    let (full_b, full_e, partial_rounds) = (4, 4, 56);
    PoseidonParams::new(width, full_b, full_e, partial_rounds).unwrap()
}

// Super fast. Profiler says average 2 nanoseconds.
pub fn make_hash_func(hash_params: &PoseidonParams) -> PoseidonHash8 {
    let hf = PoseidonHash8 {
        params: &hash_params,
        sbox: &SboxType::Quint,
    };
    hf
}

// Pretty slow. Profiler says average 23 milliseconds when depth = 12.
// Time increase is linear with depth of tree:
// depth = 3 -- ave time = 6 ms
// depth = 6 -- ave time = 12 ms
// depth = 9 -- ave time = 18 ms
// depth = 12 -- ave time = 24 ms
pub fn make_tree(hash_func: &PoseidonHash8, tree_depth: usize, db: &mut Db) -> i32 {
    let _x = VanillaSparseMerkleTree8::new(hash_func, tree_depth, db).unwrap();
    0
}
