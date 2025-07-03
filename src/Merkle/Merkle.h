#pragma once
#include <unordered_map>
#include <vector>
#include <optional>
#include <bitset>
#include <stdexcept>
#include <span>
#include "../Crypt/Crypt.h"

class Merkle {
public:

    explicit Merkle(std::unordered_map<uint32_t, std::vector<uint8_t>> map, uint8_t max_tree_level = 64):
    max_tree_level( std::min(max_tree_level, static_cast<uint8_t>(64))), tree_map(map){

    }

    Merkle(const std::bitset<32>& bitset, const std::vector<std::vector<uint8_t>>& nodes):
    max_tree_level(64){
       
        auto nodes_iterator = nodes.begin();
        for (uint32_t counter = 0; counter < bitset.size(); ++counter) {
            // Only the bits marked with a one are actually present in the array.
            if (bitset.test(counter)) {
                tree_map.insert(std::make_pair(bitset[counter], *nodes_iterator));
                nodes_iterator++;
            }
        }
    }

    Merkle(){

    }

    ~Merkle(){

    }

    Merkle& operator=(const Merkle& tree){
        this->max_tree_level = tree.max_tree_level;
        this->tree_map = tree.tree_map;
        return *this;
    }

    Merkle& operator=(Merkle&& tree){
        this->max_tree_level = tree.max_tree_level;
        this->tree_map = std::move(tree.tree_map);
        return *this;
    }



    std::optional<std::vector<uint8_t>> index(uint64_t idx, uint64_t& max_index_seen, uint8_t& level_reached) const {
        
        if(level_reached > max_tree_level){
            return std::nullopt;
        }

        auto it = tree_map.find(idx);

        if (it != tree_map.end()) {
            max_index_seen = std::max(max_index_seen, idx);
            level_reached--;
            return it->second;
        }

        level_reached++;
        // Find left;
        auto left = index(max_index_seen + 1, max_index_seen, level_reached);

        // Find right;
        auto right = index(max_index_seen + 1, max_index_seen, level_reached);
        level_reached--;

        if(!left.has_value() || !left.has_value()){
            return std::nullopt;
        }

        auto left_node = left.value();

        auto right_node = right.value();

        left_node.insert(left_node.begin(), right_node.begin(), right_node.end());

        return DigestStream<HASH256_tag>::digest(left_node);
    }

    // Function to check if the root (index 0) is valid
    bool is_valid(const std::vector<uint8_t>& root_bytes) const {
        uint8_t level_reached = 0;
        uint64_t max_index = 0;
        auto root = index(0, max_index, level_reached);
        return root.has_value() && root.value() == root_bytes;
    }

private:
    std::unordered_map<uint32_t, std::vector<uint8_t>> tree_map; // Map of tree nodes, each node stores some data which in this 
                                                                 // case is expected to be a hash.
    uint8_t max_tree_level; // As deep as the tree goes. 
};