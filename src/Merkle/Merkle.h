#pragma once
#include <vector>
#include <optional>
#include <stdexcept>
#include <cmath>
#include <cstring>
#include <algorithm>
#include "../Crypt/Crypt.h"

// Compute the Merkle parent of two 32-byte hashes by concatenating and HASH256-ing.
inline std::vector<uint8_t> merkle_parent(const std::vector<uint8_t>& left, const std::vector<uint8_t>& right) {
	std::vector<uint8_t> combined;
	combined.reserve(left.size() + right.size());
	combined.insert(combined.end(), left.begin(), left.end());
	combined.insert(combined.end(), right.begin(), right.end());
	return DigestStream<HASH256_tag>::digest(combined);
}

// Given a level of hashes, compute the parent level.
// If the number of hashes is odd, duplicate the last one.
inline std::vector<std::vector<uint8_t>> merkle_parent_level(const std::vector<std::vector<uint8_t>>& hashes) {
	if (hashes.size() < 2) {
		throw std::runtime_error("merkle_parent_level requires at least 2 hashes");
	}
	std::vector<std::vector<uint8_t>> parent_level;
	parent_level.reserve((hashes.size() + 1) / 2);

	for (size_t i = 0; i < hashes.size(); i += 2) {
		if (i + 1 < hashes.size()) {
			parent_level.push_back(merkle_parent(hashes[i], hashes[i + 1]));
		} else {
			// Odd number: duplicate last hash.
			parent_level.push_back(merkle_parent(hashes[i], hashes[i]));
		}
	}
	return parent_level;
}

// Compute the Merkle root from a list of transaction hashes.
inline std::vector<uint8_t> merkle_root(std::vector<std::vector<uint8_t>> hashes) {
	if (hashes.empty()) {
		throw std::runtime_error("merkle_root requires at least 1 hash");
	}
	while (hashes.size() > 1) {
		hashes = merkle_parent_level(hashes);
	}
	return hashes[0];
}

// MerkleTree implements depth-first traversal for parsing Merkle proofs
// from MerkleBlock messages (BIP37). It reconstructs the Merkle root
// from flag bits and a partial set of hashes.
class MerkleTree {
  public:
	MerkleTree(uint32_t total_leaves) : total(total_leaves) {
		max_depth = static_cast<uint32_t>(std::ceil(std::log2(total_leaves == 0 ? 1 : total_leaves)));
		// Build empty tree: each level has ceil(count / 2^(max_depth - depth)) nodes.
		nodes.resize(max_depth + 1);
		for (uint32_t depth = 0; depth <= max_depth; ++depth) {
			uint32_t num_items = (total + (1u << (max_depth - depth)) - 1) / (1u << (max_depth - depth));
			nodes[depth].resize(num_items);
		}
		current_depth = 0;
		current_index = 0;
	}

	// Populate the tree from flag bits and hashes (as provided in a MerkleBlock message).
	// Returns true if the proof is valid (all hashes consumed, all flags used, root computed).
	bool populate_tree(const std::vector<uint8_t>& flag_bytes, const std::vector<std::vector<uint8_t>>& hashes) {
		// Convert flag bytes to bits.
		std::vector<bool> flags;
		for (auto byte : flag_bytes) {
			for (int bit = 0; bit < 8; ++bit) {
				flags.push_back((byte >> bit) & 1);
			}
		}

		size_t hash_idx = 0;
		size_t flag_idx = 0;

		current_depth = 0;
		current_index = 0;

		populate_node(flags, flag_idx, hashes, hash_idx);

		// Validate that all hashes and flags were consumed.
		if (hash_idx != hashes.size()) {
			return false;
		}
		// Not all flag bits need to be consumed (trailing zeros from byte padding are OK).
		return true;
	}

	// Get the computed Merkle root (node at depth 0, index 0).
	std::vector<uint8_t> root() const {
		if (nodes.empty() || nodes[0].empty() || nodes[0][0].empty()) {
			return {};
		}
		return nodes[0][0];
	}

	// Validate against an expected Merkle root.
	bool is_valid(const std::vector<uint8_t>& expected_root) const { return root() == expected_root; }

	// Validate using a raw 32-byte array (as stored in Block header).
	bool is_valid(const std::array<uint8_t, 32>& expected_root) const {
		auto r = root();
		if (r.size() != 32)
			return false;
		return std::memcmp(r.data(), expected_root.data(), 32) == 0;
	}

  private:
	uint32_t total;     // Total number of leaves (transactions).
	uint32_t max_depth; // Height of the tree.
	uint32_t current_depth;
	uint32_t current_index;

	// nodes[depth][index] = 32-byte hash. Empty vector means not yet computed.
	std::vector<std::vector<std::vector<uint8_t>>> nodes;

	bool is_leaf() const { return current_depth == max_depth; }

	// Whether the right child exists at the current position.
	bool right_exists() const { return (current_index * 2 + 1) < nodes[current_depth + 1].size(); }

	const std::vector<uint8_t>& left() const { return nodes[current_depth + 1][current_index * 2]; }

	const std::vector<uint8_t>& right() const { return nodes[current_depth + 1][current_index * 2 + 1]; }

	void set_current_node(const std::vector<uint8_t>& value) { nodes[current_depth][current_index] = value; }

	void go_left() {
		current_depth++;
		current_index *= 2;
	}

	void go_right() {
		current_depth++;
		current_index = current_index * 2 + 1;
	}

	void go_up() {
		current_depth--;
		current_index /= 2;
	}

	void populate_node(const std::vector<bool>& flags, size_t& flag_idx,
	                   const std::vector<std::vector<uint8_t>>& hashes, size_t& hash_idx) {
		if (flag_idx >= flags.size())
			return;

		bool flag = flags[flag_idx];
		flag_idx++;

		if (is_leaf()) {
			// Leaf node: always consume a hash.
			if (hash_idx < hashes.size()) {
				set_current_node(hashes[hash_idx]);
				hash_idx++;
			}
			return;
		}

		if (!flag) {
			// Not a parent of a matched tx: consume a hash for this node directly.
			if (hash_idx < hashes.size()) {
				set_current_node(hashes[hash_idx]);
				hash_idx++;
			}
			return;
		}

		// flag == 1 and not a leaf: descend into children.
		// Go left.
		go_left();
		populate_node(flags, flag_idx, hashes, hash_idx);
		go_up();

		if (right_exists()) {
			// Go right.
			go_right();
			populate_node(flags, flag_idx, hashes, hash_idx);
			go_up();
			// Compute this node from children.
			set_current_node(merkle_parent(left(), right()));
		} else {
			// No right child: duplicate left.
			set_current_node(merkle_parent(left(), left()));
		}
	}
};