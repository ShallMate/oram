use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashMap;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};

// ----------------------------
// Basic types
// ----------------------------
type BlockId = u64;
type Leaf = u32;

// 客户端可见的明文块（服务端永远只存密文槽位）
#[derive(Clone, Debug)]
struct PlainBlock {
    id: BlockId,
    leaf: Leaf,      // 当前分配的叶子（position label）
    is_dummy: bool,  // dummy 标记（仅客户端可见）
    data: Vec<u8>,   // 固定长度 block_size
}

impl PlainBlock {
    fn dummy(block_size: usize) -> Self {
        Self {
            id: 0,
            leaf: 0,
            is_dummy: true,
            data: vec![0u8; block_size],
        }
    }

    fn real(id: BlockId, leaf: Leaf, data: Vec<u8>) -> Self {
        Self {
            id,
            leaf,
            is_dummy: false,
            data,
        }
    }
}

// ----------------------------
// Serialization (fixed-length plaintext)
// Plaintext = header(16 bytes) || data(block_size bytes)
// header layout:
//   [0..8)   id (u64 LE)
//   [8..12)  leaf (u32 LE)
//   [12]     flags bit0 = is_dummy
//   [13..16) reserved (0)
// ----------------------------
fn encode_block(b: &PlainBlock, block_size: usize) -> Vec<u8> {
    assert_eq!(b.data.len(), block_size);
    let mut out = vec![0u8; 16 + block_size];
    out[0..8].copy_from_slice(&b.id.to_le_bytes());
    out[8..12].copy_from_slice(&b.leaf.to_le_bytes());
    out[12] = if b.is_dummy { 1u8 } else { 0u8 };
    out[16..16 + block_size].copy_from_slice(&b.data);
    out
}

fn decode_block(buf: &[u8], block_size: usize) -> PlainBlock {
    assert_eq!(buf.len(), 16 + block_size);

    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&buf[0..8]);
    let id = u64::from_le_bytes(id_bytes);

    let mut leaf_bytes = [0u8; 4];
    leaf_bytes.copy_from_slice(&buf[8..12]);
    let leaf = u32::from_le_bytes(leaf_bytes);

    let is_dummy = (buf[12] & 1u8) == 1u8;
    let data = buf[16..16 + block_size].to_vec();

    PlainBlock { id, leaf, is_dummy, data }
}

// ----------------------------
// Ciphertext slot format (fixed length):
//   slot = nonce(24) || ct(plaintext_len + tag_len)
// tag_len = 16 (Poly1305)
// ----------------------------
struct CryptoCtx {
    aead: XChaCha20Poly1305,
    rng: StdRng,
    block_size: usize,
}

impl CryptoCtx {
    fn new(key_bytes_32: [u8; 32], seed: u64, block_size: usize) -> Self {
        let key = Key::from_slice(&key_bytes_32);
        let aead = XChaCha20Poly1305::new(key);
        Self {
            aead,
            rng: StdRng::seed_from_u64(seed),
            block_size,
        }
    }

    fn plaintext_len(&self) -> usize {
        16 + self.block_size
    }

    fn slot_len(&self) -> usize {
        // nonce 24 + (pt + tag 16)
        24 + self.plaintext_len() + 16
    }

    fn aad_for_slot(node_index: usize, slot_index: usize) -> [u8; 16] {
        // 绑定位置：防止服务端把密文从一个槽位挪到另一个槽位仍通过认证
        let mut aad = [0u8; 16];
        aad[0..8].copy_from_slice(&(node_index as u64).to_le_bytes());
        aad[8..16].copy_from_slice(&(slot_index as u64).to_le_bytes());
        aad
    }

    fn encrypt_block_to_slot(&mut self, b: &PlainBlock, node_index: usize, slot_index: usize) -> Vec<u8> {
        let pt = encode_block(b, self.block_size);

        let mut nonce_bytes = [0u8; 24];
        self.rng.fill(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let aad = Self::aad_for_slot(node_index, slot_index);

        let ct = self
            .aead
            .encrypt(nonce, Payload { msg: &pt, aad: &aad })
            .expect("encrypt should not fail");

        let mut slot = Vec::with_capacity(24 + ct.len());
        slot.extend_from_slice(&nonce_bytes);
        slot.extend_from_slice(&ct);
        slot
    }

    fn decrypt_slot_to_block(&self, slot: &[u8], node_index: usize, slot_index: usize) -> PlainBlock {
        assert!(slot.len() >= 24 + 16);

        let (nonce_part, ct_part) = slot.split_at(24);
        let nonce = XNonce::from_slice(nonce_part);

        let aad = Self::aad_for_slot(node_index, slot_index);

        let pt = self
            .aead
            .decrypt(nonce, Payload { msg: ct_part, aad: &aad })
            .expect("auth failed: tamper/swap/replay?");

        decode_block(&pt, self.block_size)
    }
}

// ----------------------------
// ORAM Server: stores only ciphertext slots
// ----------------------------
#[derive(Clone)]
struct EncBucket {
    slots: Vec<Vec<u8>>, // z slots, each fixed length
}

impl EncBucket {
    fn new(slots: Vec<Vec<u8>>) -> Self {
        Self { slots }
    }
}

struct OramServer {
    num_leaves: usize, // power of two
    z: usize,
    tree: Vec<EncBucket>, // complete binary tree, 0-based heap indexing
}

impl OramServer {
    fn num_nodes(num_leaves: usize) -> usize {
        2 * num_leaves - 1
    }

    fn new(num_leaves: usize, z: usize, tree: Vec<EncBucket>) -> Self {
        assert!(num_leaves.is_power_of_two());
        assert_eq!(tree.len(), Self::num_nodes(num_leaves));
        Self { num_leaves, z, tree }
    }

    fn leaf_base(&self) -> usize {
        self.num_leaves - 1
    }

    fn leaf_node_index(&self, leaf: Leaf) -> usize {
        self.leaf_base() + (leaf as usize)
    }

    fn path_nodes(&self, leaf: Leaf) -> Vec<usize> {
        // root(0) -> leaf node
        let mut nodes = Vec::new();
        let mut idx = self.leaf_node_index(leaf);
        nodes.push(idx);
        while idx != 0 {
            idx = (idx - 1) / 2;
            nodes.push(idx);
        }
        nodes.reverse();
        nodes
    }

    fn read_path(&self, leaf: Leaf) -> (Vec<usize>, Vec<EncBucket>) {
        let nodes = self.path_nodes(leaf);
        let buckets = nodes.iter().map(|&i| self.tree[i].clone()).collect();
        (nodes, buckets)
    }

    fn write_path(&mut self, nodes_root_to_leaf: &[usize], buckets_root_to_leaf: Vec<EncBucket>) {
        assert_eq!(nodes_root_to_leaf.len(), buckets_root_to_leaf.len());
        for (&node, bucket) in nodes_root_to_leaf.iter().zip(buckets_root_to_leaf.into_iter()) {
            self.tree[node] = bucket;
        }
    }

    fn is_ancestor(&self, node: usize, leaf: Leaf) -> bool {
        // node 是否为 leaf_node 的祖先（含自身）
        let mut x = self.leaf_node_index(leaf);
        loop {
            if x == node {
                return true;
            }
            if x == 0 {
                return false;
            }
            x = (x - 1) / 2;
        }
    }
}

// ----------------------------
// ORAM Client: pos_map + stash + crypto + access logic
// ----------------------------
struct OramClient {
    server: OramServer,
    crypto: CryptoCtx,

    pos_map: HashMap<BlockId, Leaf>,
    stash: Vec<PlainBlock>, // 仅 real 块
}

#[derive(Clone, Copy)]
enum Op {
    Read,
    Write,
}

impl OramClient {
    fn new(num_leaves: usize, z: usize, block_size: usize, master_seed: u64) -> Self {
        // 演示用：用 seed 派生 32B key。真实系统建议用 OS RNG + KDF。
        let mut k_rng = StdRng::seed_from_u64(master_seed ^ 0xA5A5_A5A5_A5A5_A5A5);
        let mut key_bytes = [0u8; 32];
        k_rng.fill(&mut key_bytes);

        let mut crypto = CryptoCtx::new(key_bytes, master_seed ^ 0x5A5A_5A5A_5A5A_5A5A, block_size);

        // 初始化服务端整棵树：每个 (node_index, slot_index) 都生成一个“位置绑定”的 dummy 密文
        assert!(num_leaves.is_power_of_two());
        let num_nodes = OramServer::num_nodes(num_leaves);
        let dummy_plain = PlainBlock::dummy(block_size);

        let mut tree: Vec<EncBucket> = Vec::with_capacity(num_nodes);
        for node_index in 0..num_nodes {
            let mut slots: Vec<Vec<u8>> = Vec::with_capacity(z);
            for slot_index in 0..z {
                let ct_slot = crypto.encrypt_block_to_slot(&dummy_plain, node_index, slot_index);
                slots.push(ct_slot);
            }
            tree.push(EncBucket::new(slots));
        }

        let server = OramServer::new(num_leaves, z, tree);

        Self {
            server,
            crypto,
            pos_map: HashMap::new(),
            stash: Vec::new(),
        }
    }

    fn num_leaves(&self) -> usize {
        self.server.num_leaves
    }

    fn random_leaf(&mut self) -> Leaf {
        self.crypto.rng.gen_range(0..self.num_leaves()) as Leaf
    }

    fn read(&mut self, id: BlockId) -> Vec<u8> {
        self.access(Op::Read, id, None)
    }

    fn write(&mut self, id: BlockId, data: Vec<u8>) -> Vec<u8> {
        assert_eq!(data.len(), self.crypto.block_size);
        self.access(Op::Write, id, Some(data))
    }

    fn access(&mut self, op: Op, id: BlockId, new_data: Option<Vec<u8>>) -> Vec<u8> {
        // 1) old_leaf：避免 entry().or_insert_with(|| self.random_leaf()) 的借用冲突
        let old_leaf = if let Some(&l) = self.pos_map.get(&id) {
            l
        } else {
            let l = self.random_leaf();
            self.pos_map.insert(id, l);
            l
        };

        // 2) new_leaf：每次访问重定位
        let new_leaf = self.random_leaf();
        self.pos_map.insert(id, new_leaf);

        // 3) 从服务端读整条路径（密文）
        let (nodes, enc_path) = self.server.read_path(old_leaf);

        // 4) 解密路径上所有槽位：real 放 stash，dummy 丢弃
        for (lvl, bucket) in enc_path.iter().enumerate() {
            let node_index = nodes[lvl];
            for (slot_idx, slot) in bucket.slots.iter().enumerate() {
                let blk = self.crypto.decrypt_slot_to_block(slot, node_index, slot_idx);
                if !blk.is_dummy {
                    self.stash.push(blk);
                }
            }
        }

        // 5) stash 中找目标块；不存在则按“全0块”处理
        let mut old_value = vec![0u8; self.crypto.block_size];
        let mut found_idx: Option<usize> = None;

        for (i, blk) in self.stash.iter().enumerate() {
            if blk.id == id {
                old_value = blk.data.clone();
                found_idx = Some(i);
                break;
            }
        }

        match op {
            Op::Read => {
                if let Some(i) = found_idx {
                    self.stash[i].leaf = new_leaf;
                } else {
                    self.stash.push(PlainBlock::real(id, new_leaf, old_value.clone()));
                }
            }
            Op::Write => {
                let nd = new_data.expect("write needs data");
                if let Some(i) = found_idx {
                    self.stash[i].data = nd;
                    self.stash[i].leaf = new_leaf;
                } else {
                    self.stash.push(PlainBlock::real(id, new_leaf, nd));
                }
            }
        }

        // 6) 回填（eviction）：沿 old_leaf 路径，从叶到根贪心放回；剩余留在 stash
        self.evict_to_path(old_leaf);

        old_value
    }

    fn evict_to_path(&mut self, leaf: Leaf) {
        let nodes = self.server.path_nodes(leaf); // root->leaf
        let dummy_plain = PlainBlock::dummy(self.crypto.block_size);

        // 先构建全 dummy 的新路径（每个槽位都新随机 nonce 加密，并用位置绑定 AAD）
        let mut new_path: Vec<EncBucket> = Vec::with_capacity(nodes.len());
        for (lvl, &node_index) in nodes.iter().enumerate() {
            let mut slots: Vec<Vec<u8>> = Vec::with_capacity(self.server.z);
            for slot_idx in 0..self.server.z {
                let s = self.crypto.encrypt_block_to_slot(&dummy_plain, node_index, slot_idx);
                slots.push(s);
            }
            let _ = lvl;
            new_path.push(EncBucket::new(slots));
        }

        // 从叶到根：每个桶最多放 Z 个可放置块（node 是 block.leaf 对应叶节点的祖先）
        for lvl_rev in (0..nodes.len()).rev() {
            let node_index = nodes[lvl_rev];

            // 选最多 Z 个可放到该 node 的块
            let mut chosen_indices: Vec<usize> = Vec::new();
            for (i, blk) in self.stash.iter().enumerate() {
                if chosen_indices.len() >= self.server.z {
                    break;
                }
                if self.server.is_ancestor(node_index, blk.leaf) {
                    chosen_indices.push(i);
                }
            }

            // 收集并从 stash 删除（倒序删）
            let mut chosen_blocks: Vec<PlainBlock> = Vec::new();
            for &i in chosen_indices.iter() {
                chosen_blocks.push(self.stash[i].clone());
            }
            chosen_indices.sort_unstable_by(|a, b| b.cmp(a));
            for i in chosen_indices {
                self.stash.remove(i);
            }

            // 写入 bucket 的前若干槽位
            for (slot_idx, blk) in chosen_blocks.into_iter().enumerate() {
                let ct_slot = self.crypto.encrypt_block_to_slot(&blk, node_index, slot_idx);
                new_path[lvl_rev].slots[slot_idx] = ct_slot;
            }
        }

        // 写回服务端
        self.server.write_path(&nodes, new_path);
    }
}

// ----------------------------
// Demo + regression test
// ----------------------------
fn main() {
    let n_blocks = 64usize;
    let z = 4usize;
    let block_size = 32usize;
    let num_leaves = next_power_of_two(n_blocks);

    let mut oram = OramClient::new(num_leaves, z, block_size, 0xC0FF_EE_u64);

    // 应用层镜像（明文验证用）
    let mut mirror: HashMap<u64, Vec<u8>> = (1..=(n_blocks as u64))
        .map(|i| (i, vec![0u8; block_size]))
        .collect();

    // 初始化：把 1..=N 全部写入全0，避免“首次 read 是否存在”的语义问题
    for id in 1..=(n_blocks as u64) {
        let old = oram.write(id, vec![0u8; block_size]);
        assert_eq!(old, vec![0u8; block_size]);
    }

    // 随机读写回归测试
    let mut app_rng = StdRng::seed_from_u64(12345);
    for _ in 0..1000 {
        let bid = app_rng.gen_range(1..=(n_blocks as u64));
        if app_rng.gen_bool(0.5) {
            let got = oram.read(bid);
            assert_eq!(got, mirror[&bid]);
        } else {
            let mut v = vec![0u8; block_size];
            app_rng.fill(&mut v[..]);
            let _old = oram.write(bid, v.clone());
            mirror.insert(bid, v);
        }
    }

    println!(
        "Private Path ORAM OK. stash_len={} (client-only), server_nodes={}, slot_len={}",
        oram.stash.len(),
        oram.server.tree.len(),
        oram.crypto.slot_len()
    );
}

fn next_power_of_two(n: usize) -> usize {
    if n <= 1 { 1 } else { n.next_power_of_two() }
}
