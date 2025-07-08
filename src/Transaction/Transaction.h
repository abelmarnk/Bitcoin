#pragma once
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <nlohmann/json.hpp>  
#include <unordered_map>
#include "../Crypt/Crypt.h"
#include "../Script/Script.h"
#include "../Varint/Varint.h"

class TxInfoFetcher;

class TxIn {
public:

	TxIn(const std::array<uint8_t, 32>& tx_id, uint32_t  tx_index, const Script& script_sig, uint32_t sequence) :
		tx_id(tx_id), tx_index(tx_index), script_sig(script_sig), sequence(sequence) {
	}

	TxIn():tx_index(), sequence(0xffffffff){
	}

	TxIn(std::vector<uint8_t>::const_iterator&& start) :tx_index(), sequence() {
		parse(std::forward<std::vector<uint8_t>::const_iterator>(start));
	}

	TxIn(const TxIn& MyInput): 
		tx_id(MyInput.tx_id), tx_index(MyInput.tx_index),
		script_sig(MyInput.script_sig),sequence(MyInput.sequence) {
	}

	TxIn(TxIn&& MyInput) noexcept:
		tx_id(std::move(MyInput.tx_id)), tx_index(MyInput.tx_index),
		script_sig(std::move(MyInput.script_sig)), sequence(MyInput.sequence) {
	}

	TxIn& operator=(const TxIn& MyInput);

	TxIn& operator=(TxIn&& MyInput);

	void parse(std::vector<uint8_t>::const_iterator &&start);

	void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const;

	void serialize(std::vector<uint8_t>& result, bool should_adjust_iterator = true) const{
		auto iterator = result.begin();
		serialize(iterator, result, should_adjust_iterator);
	}

	const uint32_t get_sequence() const{
		return sequence;
	}

	Script& get_script(){
		return script_sig;
	}

	void set_script(const Script& NewScript) {
		script_sig = NewScript;
	}

	void set_script(Script&& NewScript) {
		script_sig = std::move(NewScript);
	}

	void set_script_from_index_and_id(bool is_testnet);

	void set_script_from_index_and_id(const std::array<uint8_t, 32>& tx_id, uint32_t tx_index, bool is_testnet);

	std::vector<std::vector<uint8_t>>& get_witness_data(){
		return witness_data;
	}

	const std::vector<std::vector<uint8_t>>& get_witness_data() const{
		return witness_data;
	}

	void set_witness_data(const std::vector<std::vector<uint8_t>>& witness_data){
		this->witness_data = witness_data;
	}

	const std::array<uint8_t, 32>& get_tx_id() const{
		return tx_id;
	}

	std::array<uint8_t, 32>& get_tx_id(){
		return tx_id;
	}

	void set_tx_id(const std::array<uint8_t, 32>& tx_id) {
		this->tx_id = tx_id;
	}

	uint32_t get_tx_index() const{
		return tx_index;
	}

	void set_tx_index(uint32_t tx_index) {
		this->tx_index = tx_index;
	}

	// Get the size in bytes of the serialization of the input(excludes the witness).
    uint32_t get_legacy_size() const {
		uint32_t script_sig_size = script_sig.get_size();
        return sizeof(tx_id) + sizeof(tx_index) + get_varint_byte_size(script_sig_size) + script_sig_size + sizeof(sequence);
    }

	uint32_t get_witness_data_size() const{
		uint32_t witness_data_size = std::accumulate(witness_data.begin(), witness_data.end(), 0LL,
		[](uint64_t sum, const std::vector<uint8_t>& witness){
			return sum + get_varint_byte_size(witness.size()) + witness.size();
		});

		return witness_data_size;
	}


private:
	std::array<uint8_t, 32> tx_id; 
	uint32_t tx_index;
	Script script_sig; // This stores the unlocking script sig.
	std::vector<std::vector<uint8_t>> witness_data; // This is used to store the witness data for SegWit transactions. 
	uint32_t sequence; // Used for ordering offline transactions.
};

class TxOut {
public:

	TxOut(uint64_t  amount, Script script_pubkey) :
		amount(amount), script_pubkey(script_pubkey) {
	}

	TxOut() :amount() {
	}

	TxOut(std::vector<uint8_t>::const_iterator&& start) {
		parse(std::forward<std::vector<uint8_t>::const_iterator>(start));
	}

	TxOut(const TxOut& my_output) :
		amount(my_output.amount),script_pubkey(my_output.script_pubkey){
	}

	TxOut(TxOut&& my_output) :
		amount(my_output.amount), script_pubkey(std::move(my_output.script_pubkey)){
	}

	TxOut& operator=(const TxOut& my_output);

	TxOut& operator=(TxOut&& my_output);

	void parse(std::vector<uint8_t>::const_iterator &&start);

	void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const;

	uint64_t get_amount() const{
		return amount;
	}

	void set_amount(uint64_t amount) {
		this->amount = amount;
	}

	void set_script(const Script& script_pubkey) {
		this->script_pubkey = script_pubkey;
	}

	void set_script(Script&& script_pubkey) {
		this->script_pubkey = std::move(script_pubkey);
	}

	const Script& get_script() const{
		return script_pubkey;
	}

	// Get the size in bytes of the serialization of the output.
    uint64_t get_size() const {
		uint32_t script_pubkey_size =  script_pubkey.get_size(); 
        return sizeof(amount) + get_varint_byte_size(script_pubkey_size) + script_pubkey_size;
    }

private:
	uint64_t amount;
	Script script_pubkey; // Stores the locking keyhole for this output to be spent. 
};

class Tx {
public:

	static const std::array<uint8_t, 4> SIGHASH_ALL; // This the only signature hash type supported by this program.

	Tx(uint64_t version, const std::vector<TxIn> &input_txs, const std::vector<TxOut>& output_txs,
		uint32_t locktime, bool testnet, bool segwit) :
		version(version), input_txs(input_txs), output_txs(output_txs), 
		locktime(locktime), testnet(testnet){
	}

	Tx():version(), locktime(), testnet() {
	}

	Tx(std::vector<uint8_t>::const_iterator&& input){
		parse(std::forward<std::vector<uint8_t>::const_iterator>(input)) ;
	}

	Tx(const Tx& my_tx) :
		version(my_tx.version),
		input_txs(my_tx.input_txs), output_txs(my_tx.output_txs),
		locktime(my_tx.locktime), testnet(my_tx.testnet) {

	}

	Tx(Tx&& my_tx) noexcept:
		version(my_tx.version),
		input_txs(std::move(my_tx.input_txs)), output_txs(std::move(my_tx.output_txs)),
		locktime(my_tx.locktime), testnet(my_tx.testnet){

	}

	Tx& operator=(const Tx& my_tx);

	Tx& operator=(Tx&& my_tx) noexcept;

	void parse(std::vector<uint8_t>::const_iterator&& input);

	void parse_legacy(std::vector<uint8_t>::const_iterator&& input);

	void parse_segwit(std::vector<uint8_t>::const_iterator&& input);

	void serialize(std::vector<uint8_t>& input, std::vector<uint8_t>::iterator& start, bool should_adjust_iterator = true) const;

	void serialize(std::vector<uint8_t>& result, bool should_adjust_iterator = true) const{
		auto iterator = result.begin();
		serialize(result, iterator, should_adjust_iterator);
	}

	void serialize_legacy(std::vector<uint8_t>& input, std::vector<uint8_t>::iterator& start, bool should_adjust_iterator = true) const;

	void serialize_segwit(std::vector<uint8_t>& input, std::vector<uint8_t>::iterator& start, bool should_adjust_iterator = true) const;

	std::vector<TxIn>& get_in_txs(){
		return input_txs;
	}

	void set_in_txs(const std::vector<TxIn>& input_txs) {
		this->input_txs = input_txs;
	}

	void set_in_txs(std::vector<TxIn>&& input_txs) {
		this->input_txs = std::move(input_txs);
	}

	std::vector<TxOut>& get_out_txs()  {
		return output_txs;
	}
	
	void set_out_txs(const std::vector<TxOut>& NewOutputTx) {
		output_txs = NewOutputTx;
	}

	void set_out_txs(std::vector<TxOut>&& NewOutputTxs) {
		output_txs = std::move(NewOutputTxs);
	}

	uint64_t get_version() const{
		return version;
	}

	void set_version(uint64_t NewVersion){
		 version = NewVersion;
	}

	uint32_t get_locktime() const {
		return locktime;
	}

	void set_locktime(uint32_t NewLocktime) {
		locktime = NewLocktime;
	}

	bool is_testnet() const{
		return testnet;
	}

	void set_testnet(bool NewTestnet) {
		testnet = NewTestnet;
	}

	// Get the total amount being locked(sent out).
	int64_t get_output_sum() const;

	// Get the total amount being unlocked(spend)
	int64_t get_input_sum() const;

	// The fee is the difference between the amount sent out and the amount spent.
	int64_t get_total_fee() const {
		return get_input_sum() - get_output_sum();
	}

	// Get the transaction hash for legacy inputs.
	std::vector<uint8_t> get_transaction_hash(uint64_t Index, Script& script);

	// Get the hash of inputs required for the segwit hash.
	std::array<uint8_t, 32>& hash_inputs();

	// Get the hash of all the input sequences required for the segwit hash.
	std::array<uint8_t, 32>& hash_sequence();

	// Get the hash of all the outputs required for the segwit hash.
	std::array<uint8_t, 32>& hash_outputs();

	std::vector<uint8_t> get_bip143_transaction_hash(uint64_t input_index, std::vector<uint8_t>& script_code, int64_t script_size = -1);

	// This function is used to check if an input at a given index is valid.
	bool is_valid(uint32_t index);
	
	// This function does not check for double spends, just the script sig and the amount.
	bool is_valid();

	bool is_coinbase();

	void clear_segwit_hashes() {
		outputs_hash.fill(0);
		inputs_hash.fill(0);
		sequence_hash.fill(0);
	}

	bool is_segwit() const{
		auto witness_data_size = std::accumulate(input_txs.begin(), input_txs.end(), 0ULL, // Add witness data.
			[](uint64_t sum, const TxIn& input) { 
				return sum + input.get_witness_data_size(); });

		return witness_data_size > 0;
	}

	std::optional<uint32_t> extract_coinbase_block_height();

	// Get the size in bytes of the serialization of the block.
    uint64_t get_legacy_size() const {
        return 
			sizeof(version) +
			get_varint_byte_size(input_txs.size()) + // Size of the varint for the number of inputs
			std::accumulate(input_txs.begin(), input_txs.end(), 0ULL, 
			[](uint64_t sum, const TxIn& input) { return sum + input.get_legacy_size(); }) +
			get_varint_byte_size(output_txs.size()) + // Size of the varint for the number of outputs
			std::accumulate(output_txs.begin(), output_txs.end(), 0ULL, 
			[](uint64_t sum, const TxOut& output) { return sum + output.get_size(); }) +
			sizeof(locktime);
    }

	uint64_t get_segwit_size() const{
		return 
			get_legacy_size() +
			1 + // Segwit indicator.
			1 + // Segwit marker.
			std::accumulate(input_txs.begin(), input_txs.end(), 0ULL, // Add witness data.
			[](uint64_t sum, const TxIn& input) { 
				auto witness_data_size = input.get_witness_data_size();
				return sum + (witness_data_size == 0 ? 1 : witness_data_size); }); // If the input has no witness set it to zero.
	}

private:

	uint32_t version;
	std::vector<TxIn> input_txs;
	std::vector<TxOut> output_txs;
	uint32_t locktime;
	bool testnet;
	std::array<uint8_t, 32> outputs_hash;  // This is used to store the hashes of the outputs for SegWit transactions.
	std::array<uint8_t, 32> inputs_hash; // This is used to store the hashes of the inputs for SegWit transactions.
	std::array<uint8_t, 32> sequence_hash; // This is used to store the hash of the sequence for SegWit transactions.
};


using json = nlohmann::json;
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;


class TxInfoFetcher {
private:
    static std::unordered_map<std::string, std::pair<nlohmann::json_abi_v3_12_0::json, uint32_t>> cache;
    static constexpr uint32_t MAX_CACHE_AGE = 10;   // Remove after 10 fetches.


    static void update_cache_counts() {
        for (auto iterator = cache.begin(); iterator != cache.end();) {
            iterator->second.second++;
            if (iterator->second.second >= MAX_CACHE_AGE) {
                iterator = cache.erase(iterator); 
            }
			else{
				iterator++;
			}
        }
    }

	// Todo: Make adjustments for testnet4.
    static const nlohmann::json_abi_v3_12_0::json& fetch_tx(std::string&& tx_id, bool IsTestnet = true);

public:
    static int64_t fetch_input(std::string&& tx_id, bool IsTestnet = true);

    static std::string fetch_script_pubkey(std::string&& tx_id, uint64_t tx_index, bool IsTestnet = true);

    static uint64_t fetch_output_amount(std::string&& tx_id, uint64_t tx_index, bool IsTestnet = true);
};

