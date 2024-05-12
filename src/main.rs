fn main() {
    
}

// Merkle Tree implementation
mod utils;
mod bench;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::fmt;

const LEAF_SIG: u8 = 0u8;
const INTERNAL_SIG: u8 = 1u8;

type Hash = Vec<u8>;

#[derive(Debug)]
pub struct MerkleTree<H = DefaultHasher> {
    hasher: H,
    nodes: Vec<Hash>,
    count_internal_nodes: usize,
    count_leaves: usize,
}

fn hash_leaf<T, H>(value: &T, hasher: &mut H) -> Hash
where
    T: AsBytes,
    H: Digest,
{
    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[LEAF_SIG]);
    hasher.input(value.as_bytes());
    hasher.result(result.as_mut_slice());

    result
}

fn hash_internal_node<H>(left: &Hash, right: Option<&Hash>, hasher: &mut H) -> Hash
where
    H: Digest,
{
    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[INTERNAL_SIG]);
    hasher.input(left.as_slice());
    if let Some(r) = right {
        hasher.input(r.as_slice());
    } else {
        hasher.input(left.as_slice());
    }
    hasher.result(result.as_mut_slice());

    result
}

fn build_upper_level<H>(nodes: &[Hash], hasher: &mut H) -> Vec<Hash>
where
    H: Digest,
{
    let mut row = Vec::with_capacity((nodes.len() + 1) / 2);
    let mut i = 0;
    while i < nodes.len() {
        if i + 1 < nodes.len() {
            row.push(hash_internal_node(&nodes[i], Some(&nodes[i + 1]), hasher));
            i += 2;
        } else {
            row.push(hash_internal_node(&nodes[i], None, hasher));
            i += 1;
        }
    }

    if row.len() > 1 && row.len() % 2 != 0 {
        let last_node = row.last().unwrap().clone();
        row.push(last_node);
    }

    row
}

fn build_internal_nodes<H>(nodes: &mut Vec<Hash>, count_internal_nodes: usize, hasher: &mut H)
where
    H: Digest,
{
    let mut parents = build_upper_level(&nodes[count_internal_nodes..], hasher);

    let mut upper_level_start = count_internal_nodes - parents.len();
    let mut upper_level_end = upper_level_start + parents.len();
    nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);

    while parents.len() > 1 {
        parents = build_upper_level(parents.as_slice(), hasher);

        upper_level_start -= parents.len();
        upper_level_end = upper_level_start + parents.len();
        nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);
    }
    nodes[0] = parents.remove(0);
}

fn calculate_internal_nodes_count(count_leaves: usize) -> usize {
    utils::next_power_of_2(count_leaves) - 1
}

fn _build_from_leaves_with_hasher<H>(leaves: &[Hash], mut hasher: H) -> MerkleTree<H>
where
    H: Digest,
{
    let count_leaves = leaves.len();
    let count_internal_nodes = calculate_internal_nodes_count(count_leaves);
    let mut nodes = vec![Vec::new(); count_internal_nodes + count_leaves];

    nodes[count_internal_nodes..].clone_from_slice(leaves);

    build_internal_nodes(&mut nodes, count_internal_nodes, &mut hasher);

    MerkleTree {
        nodes: nodes,
        count_internal_nodes: count_internal_nodes,
        count_leaves: count_leaves,
        hasher: hasher,
    }
}

impl<H> MerkleTree<H>
where
    H: Digest,
{
    pub fn build<T>(values: &[T]) -> MerkleTree<H>
    where
        H: Default,
        T: AsBytes,
    {
        let hasher = Default::default();
        MerkleTree::build_with_hasher(values, hasher)
    }

    pub fn build_with_hasher<T>(values: &[T], mut hasher: H) -> MerkleTree<H>
    where
        T: AsBytes,
    {
        let count_leaves = values.len();
        assert!(
            count_leaves > 1,
            "expected more then 1 value, received {}",
            count_leaves
        );

        let leaves: Vec<Hash> = values.iter().map(|v| hash_leaf(v, &mut hasher)).collect();

        _build_from_leaves_with_hasher(leaves.as_slice(), hasher)
    }

    pub fn build_from_leaves(leaves: &[Hash]) -> MerkleTree<H>
    where
        H: Default,
    {
        let hasher = Default::default();
        MerkleTree::build_from_leaves_with_hasher(leaves, hasher)
    }

    pub fn build_from_leaves_with_hasher(leaves: &[Hash], hasher: H) -> MerkleTree<H>
    where
        H: Digest,
    {
        let count_leaves = leaves.len();
        assert!(
            count_leaves > 1,
            "expected more than 1 leaf, received {}",
            count_leaves
        );

        _build_from_leaves_with_hasher(leaves, hasher)
    }

    pub fn root_hash(&self) -> &Hash {
        &self.nodes[0]
    }

    pub fn root_hash_str(&self) -> String {
        use rustc_serialize::hex::ToHex;
        self.nodes[0].as_slice().to_hex()
    }

    pub fn leaves(&self) -> &[Hash] {
        &self.nodes[self.count_internal_nodes..]
    }

    pub fn verify<T>(&mut self, position: usize, value: &T) -> bool
    where
        T: AsBytes,
    {
        assert!(
            position < self.count_leaves,
            "position does not relate to any leaf"
        );

        self.nodes[self.count_internal_nodes + position].as_slice()
            == hash_leaf(value, &mut self.hasher).as_slice()
    }
}

#[derive(Copy, Clone)]
pub struct DefaultHasher(Sha256);

impl DefaultHasher {
    pub fn new() -> DefaultHasher {
        DefaultHasher(Sha256::new())
    }
}

impl Default for DefaultHasher {
    fn default() -> DefaultHasher {
        DefaultHasher::new()
    }
}

impl Digest for DefaultHasher {
    fn input(&mut self, d: &[u8]) {
        self.0.input(d)
    }

    fn reset(&mut self) {
        self.0.reset();
    }

    fn result(&mut self, out: &mut [u8]) {
        self.0.result(out)
    }

    fn output_bits(&self) -> usize {
        self.0.output_bits()
    }

    fn block_size(&self) -> usize {
        self.0.block_size()
    }
}

impl fmt::Debug for DefaultHasher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DefaultHasher {{ Sha256 }}")
    }
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl<'a> AsBytes for &'a str {
    fn as_bytes(&self) -> &[u8] {
        str::as_bytes(self)
    }
}

impl AsBytes for String {
    fn as_bytes(&self) -> &[u8] {
        String::as_bytes(self)
    }
}

impl<'a> AsBytes for &'a [u8] {
    fn as_bytes(&self) -> &[u8] {
        *self
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleTree;

    #[test]
    fn test_build_with_0_values() {
        let _t: MerkleTree = MerkleTree::build::<String>(&[]);
    }

    #[test]
    fn test_build_with_odd_number_of_values() {
        let block = "Hello World";
        let _t: MerkleTree = MerkleTree::build(&[block, block, block]);
    }

    #[test]
    fn test_root_hash_stays_the_same_if_data_hasnt_been_change() {
        let block = "Hello World";
        let t: MerkleTree = MerkleTree::build(&[block, block]);

        assert_eq!(
            "c9978dc3e2d729207ca4c012de993423f19e7bf02161f7f95cdbf28d1b57b88a",
            t.root_hash_str()
        );
    }

    #[test]
    fn test_root_children_have_the_same_hash_if_blocks_were_the_same() {
        let block = "Hello World";
        let t: MerkleTree = MerkleTree::build(&[block, block, block, block, block]);

        assert_eq!(t.nodes[1].as_slice(), t.nodes[2].as_slice());
    }

    #[test]
    fn test_root_childen_have_the_different_hash_if_blocks_were_the_different() {
        let block1 = "Hello World";
        let block2 = "Bye Bye";
        let t: MerkleTree = MerkleTree::build(&[block1, block1, block2, block2]);

        assert_ne!(t.nodes[1].as_slice(), t.nodes[2].as_slice());
    }

    #[test]
    fn test_building_a_tree_from_existing_tree() {
        let block = "Hello World";
        let existing_tree: MerkleTree = MerkleTree::build(&[block, block]);

        let new_tree: MerkleTree = MerkleTree::build_from_leaves(existing_tree.leaves());

        assert_eq!(new_tree.root_hash_str(), existing_tree.root_hash_str());
        assert_eq!(new_tree.leaves().len(), existing_tree.leaves().len());
        assert_eq!(new_tree.leaves(), existing_tree.leaves());
    }
}




