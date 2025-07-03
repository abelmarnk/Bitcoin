#include "../Debug functions/Debug functions.h"
#include "Transaction.h"
#include "../Serial/Serial.h"
#include <iostream>

TxIn& TxIn::operator=(const TxIn& input_tx) {
	tx_id = input_tx.tx_id;
	tx_index = (input_tx.tx_index);
	script_sig = input_tx.script_sig;
	sequence = input_tx.sequence;
	return *this;
}

TxIn& TxIn::operator=(TxIn&& input_tx) {
	tx_id = std::move(input_tx.tx_id);
	tx_index = (input_tx.tx_index);
	script_sig = std::move(input_tx.script_sig);
	sequence = input_tx.sequence;
	return *this;
}


void TxIn::parse(std::vector<uint8_t>::const_iterator &&start) {
	// The bytes in "start" are expected to be in little endian.

	// Read the transation id and advance the iterator.
	std::copy(start, start + tx_id.size(), tx_id.begin());
	start += tx_id.size();

	// Read the transation index and advance the iterator.
	read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), tx_index);

	// Read the script sig and advance the iterator.
	script_sig.parse(std::forward<std::vector<uint8_t>::const_iterator>(start));

	// Read the sequence.
	read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), sequence);
}

void TxIn::serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator) const {
	// The bytes are serialized in little endian order.

	// Make space if necessary.
	if(should_adjust_iterator){
		adjust_bytes(start, input, get_legacy_size()); // We always serialize the transaction separate from it's witness data so 
													   // can call get_legacy_size safely here.
	}

	// Write the transaction id and advance the iterator.
	start = std::copy(tx_id.begin(), tx_id.end(), start);

	// Write the transaction index and advance the iterator.
	write_int_as_little_endian_bytes(tx_index, start, input);

	// Write script_sig and advance the iterator.
	script_sig.serialize(input, start, false);

	// Write the transaction index and advance the iterator.
	write_int_as_little_endian_bytes(sequence, start, input);
}

void TxIn::set_script_from_index_and_id(bool is_testnet){
	// Fetch the script pubkey.
	std::vector<uint8_t> script_pubkey = hex_to_std_vec(TxInfoFetcher::fetch_script_pubkey(std_array_to_hex(get_tx_id()), get_tx_index(), is_testnet));

	set_script(std::move(Script(script_pubkey.cbegin(), script_pubkey.size())));
}

void TxIn::set_script_from_index_and_id(const std::array<uint8_t, 32>& tx_id, uint32_t tx_index, bool is_testnet) {
	// Fetch the script pubkey.
	std::vector<uint8_t> script_pubkey = hex_to_std_vec(TxInfoFetcher::fetch_script_pubkey(std_array_to_hex(tx_id), tx_index, is_testnet));

	set_script(std::move(Script(script_pubkey.cbegin(), script_pubkey.size())));
}


TxOut& TxOut::operator=(const TxOut& MyOutput) {
	amount = MyOutput.amount;
	script_pubkey = MyOutput.script_pubkey;
	return *this;
}

TxOut& TxOut::operator=(TxOut&& MyOutput) {
	amount = MyOutput.amount;
	script_pubkey = std::move(MyOutput.script_pubkey);
	return *this;
}


void TxOut::parse(std::vector<uint8_t>::const_iterator&&start) {
	// The bytes are expected to be in little endian order.

	// Read the amount and advance the iterator.
	read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), amount); 

	// Read the script pubkey and advance the iterator.
	script_pubkey.parse(std::forward<std::vector<uint8_t>::const_iterator>(start)); 
}

void TxOut::serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator) const {
	// The bytes are serialized in little endian order.

	// Make space if necessary.
	if(should_adjust_iterator) {
		adjust_bytes(start, input, get_size());
	}

	// Write the amount and advance the iterator.
	write_int_as_little_endian_bytes(amount, start, input); 

	// Write the script pubkey and advance the iterator.
	script_pubkey.serialize(input, start, false);
}
// This program only supports the sighash_all  type.
const std::array<uint8_t, 4> Tx::SIGHASH_ALL{ 0x01,0x00,0x00,0x00 };


Tx& Tx::operator=(const Tx& my_tx) {
	version = my_tx.version;
	input_txs = my_tx.input_txs;
	output_txs = my_tx.output_txs;
	locktime = my_tx.locktime;
	testnet = my_tx.testnet;
	return *this;
}

Tx& Tx::operator=(Tx&& my_tx) noexcept {
	version = my_tx.version;
	input_txs = std::move(my_tx.input_txs);
	output_txs = std::move(my_tx.output_txs);
	locktime = my_tx.locktime;
	testnet = my_tx.testnet;
	return *this;
}

void Tx::parse(std::vector<uint8_t>::const_iterator&& input){
	// Check for segwit marker.
	if(*(input + 4) == 0x00){ 
		parse_segwit(std::forward<std::vector<uint8_t>::const_iterator>(input));
	}
	else {
		parse_legacy(std::forward<std::vector<uint8_t>::const_iterator>(input));
	}
}

void Tx::parse_legacy(std::vector<uint8_t>::const_iterator&& start) {
	// The bytes are expected to be in little endian order.

	// Read the version.
	read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), version);

	// Read the input size and advance the iterator.
	size_t InputSize = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start)); 
	
	while (InputSize > 0) {
		// Read the inputs and advance the iterator.
		input_txs.push_back(TxIn(std::forward<std::vector<uint8_t>::const_iterator>(start))); 
		InputSize--;
	}

	// Read the output size and advance the iterator.
	size_t OutputSize = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start)); 

	while (OutputSize > 0) {
		// Read the outputs and advance the iterator.
		output_txs.push_back(TxOut(std::forward<std::vector<uint8_t>::const_iterator>(start)));
		OutputSize--;
	}

	// Read the locktime and advance the iterator.
	read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), locktime);

	testnet = false;
}

void Tx::parse_segwit(std::vector<uint8_t>::const_iterator&& start) {

	// Read the version and advance the iterator.
	read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), version);

	start += 2; // Skip the segwit marker and flag bytes.

	// Read the input size and advance the iterator.
	size_t InputSize = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start)); // The call to get_unsigned_small is valid as a variant is always less than
																// std::numeric_limits<uint64_t>::max().
	while (InputSize > 0) {
		// Read the inputs and advance the iterator.
		input_txs.push_back(TxIn(std::forward<std::vector<uint8_t>::const_iterator>(start))); 
		InputSize--;
	}

	// Read the output size and advance the iterator.
	size_t OutputSize = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start)); // The call to get_unsigned_small is valid as a variant is always less than
																// std::numeric_limits<uint64_t>::max().
	while (OutputSize > 0) {
		// Read the outputs and advance the iterator.
		output_txs.push_back(TxOut(std::forward<std::vector<uint8_t>::const_iterator>(start)));
		OutputSize--;
	}

	// Read the witness data for each input.
	for (auto& input_tx : input_txs) {
		size_t witness_count = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start)); // Get the number of witness items.

		for (size_t i = 0; i < witness_count; ++i) {
			size_t witness_size = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start)); // Get the size of each witness item.
			std::vector<uint8_t> witness_data(witness_size);
			std::copy_n(start, witness_size, witness_data.begin());
			start += witness_size;
			input_tx.get_witness_data().push_back(std::move(witness_data)); // Add the witness data to the input transaction.
		}				
	}

	// Read the locktime and advance the iterator.
	read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), locktime);

	testnet = false;
}

void Tx::serialize(std::vector<uint8_t>& input, std::vector<uint8_t>::iterator& start, bool should_adjust_iterator) const {

	if(is_segwit()) {
		serialize_segwit(input, start, should_adjust_iterator);
	} 
	else{

		serialize_legacy(input, start, should_adjust_iterator);
	}
}

void Tx::serialize_legacy(std::vector<uint8_t>& input, std::vector<uint8_t>::iterator& start, bool should_adjust_iterator) const {

	if(should_adjust_iterator) {
		adjust_bytes(start, input, get_legacy_size());
 	}
	
	write_int_as_little_endian_bytes(version, start, input); // Write the version and advance the iterator.

	serialize_varint(input_txs.size(), start, input, false); // Write a varint(Number of Tx inputs) and advance the iterator.

	// Write the inputs and advance the iterator.
	auto Iterator = input_txs.begin();

	while (Iterator != input_txs.end()) {
		Iterator->serialize(start, input, false); 
		Iterator++;
	}

	serialize_varint(output_txs.size(), start, input, false); // Write a number of Tx outputs and advance the iterator.

	// Write the outputs and advance the iterator.
	auto OutputIterator = output_txs.begin();

	while (OutputIterator != output_txs.end()) {
		OutputIterator->serialize(start, input, false); 
		OutputIterator++;
	}

	// Write the version and advance the iterator.
	write_int_as_little_endian_bytes(locktime, start, input); 
}

void Tx::serialize_segwit(std::vector<uint8_t>& input, std::vector<uint8_t>::iterator& start, bool should_adjust_iterator) const {

	if(should_adjust_iterator) {
		adjust_bytes(start, input, get_segwit_size());
 	}
	
	write_int_as_little_endian_bytes(version, start, input); // Write the version and advance the iterator.

	*start = 0x00; // Insert the segwit marker.
	start++; // Advance the iterator.
	*start = 0x01; // Insert the segwit flag.
	start++; // Advance the iterator.

	serialize_varint(input_txs.size(), start, input, false); // Write a varint(Number of Tx inputs) and advance the iterator.

	// Write the inputs and advance the iterator.
	auto Iterator = input_txs.begin();

	while (Iterator != input_txs.end()) {
		Iterator->serialize(start, input, false); 
		Iterator++;
	}

	serialize_varint(output_txs.size(), start, input, false); // Write a number of Tx outputs and advance the iterator.

	// Write the outputs and advance the iterator.
	auto OutputIterator = output_txs.begin();

	while (OutputIterator != output_txs.end()) {
		OutputIterator->serialize(start, input, false); 
		OutputIterator++;
	}

	// Write the witness data for each input.
	 for (auto& input_tx : input_txs) {
			std::vector<uint8_t> WitnessData;
			std::vector<uint8_t>::iterator WitnessDataIterator = WitnessData.begin();

			serialize_varint(input_tx.get_witness_data().size(), start, input, false); // Write a number of witness data and advance the iterator.

			for (const auto& witness : input_tx.get_witness_data()) {
				start = std::copy(witness.begin(), witness.end(), start); // Write the witness data.
			}
	}

	// Write the version and advance the iterator.
	write_int_as_little_endian_bytes(locktime, start, input); 

}

int64_t Tx::get_output_sum() const {
	int64_t output_tx_sum = 0;

	for (auto& OutputTx : output_txs) {
		output_tx_sum += OutputTx.get_amount();
	}

	return output_tx_sum;
}

int64_t Tx::get_input_sum() const {
	int64_t input_tx_sum = 0;

	for (auto& input_tx : input_txs) {
		input_tx_sum += TxInfoFetcher::fetch_input(std_array_to_hex(input_tx.get_tx_id()), testnet);
	}
	return input_tx_sum;
}

std::vector<uint8_t> Tx::get_transaction_hash(uint64_t index, Script& script) {
	// This is a private function so it shouldn't have a wrong index.

	std::vector<Script> old_scripts;
	
	for (auto& InputTransaction : input_txs) { // Move the old scripts.
		old_scripts.push_back(std::move(InputTransaction.get_script()));
		InputTransaction.get_script().clear();
	}

	// Set the script to be replaced with, in the case of p2pkh it is the script pubkey, 
	// in the case of p2sh it is the redeem script.
	input_txs[index].set_script(std::move(script));

	// Serialize the transaction using the legacy method.
	std::vector<uint8_t> tx_serialization(get_legacy_size() + sizeof(SIGHASH_ALL));// Transaction serialization size + 
														  //  type size
	std::vector<uint8_t>::iterator tx_serialization_iterator = tx_serialization.begin();

	serialize_legacy(tx_serialization, tx_serialization_iterator, false);

	script = std::move(input_txs[index].get_script()); // Restore the script we took.

	for (size_t counter = 0; counter < old_scripts.size(); ++counter) { // Return the old scripts.
		input_txs[counter].set_script(std::move(old_scripts[counter]));
	}

	// Insert the  type.
	std::copy(SIGHASH_ALL.begin(), SIGHASH_ALL.end(), tx_serialization_iterator);

	return DigestStream<HASH256_tag>::digest(tx_serialization);
}

std::vector<uint8_t> Tx::get_bip143_transaction_hash(uint64_t input_index, std::vector<uint8_t>& script_code, int64_t script_size) {
	// Serialize the data for BIP143  hash.
	uint32_t size = sizeof(version) + 
	sizeof(inputs_hash) +
		sizeof(sequence_hash) + 
	32 + 4 + // Size of the transaction id and transaction index we are signing.
	(script_size == -1 ? 0 : get_varint_byte_size(script_size)) + script_code.size() + 
	8 + // Size of the input amount.
	4 + // Size of the input sequence.
	sizeof(outputs_hash) +
	4 + // Size of the locktime.
	4; // Size of the  type.


	std::vector<uint8_t> serialization(size);
	auto serialization_iterator = serialization.begin();

	// Write the version.
	write_int_as_little_endian_bytes(version, serialization_iterator, serialization);

	// Write the hash of inputs.
	auto& inputs_hash = hash_inputs();
	serialization_iterator = std::copy(inputs_hash.cbegin(), inputs_hash.cend(), serialization_iterator);

	// Write the hash of sequences.
	auto& sequence_hash = hash_sequence();
	serialization_iterator = std::copy(sequence_hash.cbegin(), sequence_hash.cend(), serialization_iterator);

	// Write outpoint (txid + index) of the input being signed.
	const auto& tx_in = input_txs[input_index];
	serialization_iterator = std::copy(tx_in.get_tx_id().cbegin(), 
	tx_in.get_tx_id().cend(), serialization_iterator);
	write_int_as_little_endian_bytes(tx_in.get_tx_index(), serialization_iterator, serialization);

	// Write the script code for the input with index "input_index".
	if(script_size != -1){
		serialize_varint(script_size, serialization_iterator, serialization, false);
	}

	serialization_iterator = std::copy(script_code.cbegin(), script_code.cend(), serialization_iterator);

	// Write the amount for the input with index "input_index".
	uint64_t amount = TxInfoFetcher::fetch_output_amount(std_array_to_hex(input_txs[input_index].
										get_tx_id()), input_txs[input_index].get_tx_index(), testnet);
	write_int_as_little_endian_bytes(amount, serialization_iterator, serialization);

	// Write the sequence for the input with index "input_index".
	write_int_as_little_endian_bytes(tx_in.get_sequence(), serialization_iterator, serialization);

	// Write the hash of outputs.
	auto outputs_hash = hash_outputs();
	serialization_iterator = std::copy(outputs_hash.cbegin(), outputs_hash.cend(), serialization_iterator);

	// Write locktime.
	write_int_as_little_endian_bytes(locktime, serialization_iterator, serialization);

	// Write SIGHASH_ALL.
	serialization_iterator = std::copy(SIGHASH_ALL.begin(), SIGHASH_ALL.end(), serialization_iterator);

	// Compute and return the hash.
	return get_hash_256(serialization);
}




// Get the hash of inputs required for the segwit hash.
std::array<uint8_t, 32>& Tx::hash_inputs() {
// Serialize all previous transaction outputs and sequences.

	bool is_empty = std::all_of(inputs_hash.begin(), inputs_hash.end(),
		[](uint8_t byte) { return byte == 0; });

	if(is_empty){
				DigestStream<HASH256_tag> digestor;

		std::vector<uint8_t> all_inputs((32 + 4));
		auto all_ins_iterator = all_inputs.begin();
		
		for (const auto& tx_in : input_txs) {
			// Serialize previous transaction ID and index.
			all_ins_iterator = std::copy(tx_in.get_tx_id().begin(), tx_in.get_tx_id().end(), all_ins_iterator);
			
			write_int_as_little_endian_bytes(tx_in.get_tx_index(), all_ins_iterator, all_inputs);

			digestor.update(all_inputs);

			all_ins_iterator = all_inputs.begin();
		}
		
		// Compute the hash of all inputs.
		
		auto hash = digestor.finalize();

		std::copy(hash.begin(), hash.end(), inputs_hash.begin());
	}

	return inputs_hash;
}

// Get the hash of all the input sequences required for the segwit hash.
std::array<uint8_t, 32>& Tx::hash_sequence() {
	// Serialize all input sequences.
	bool is_empty = std::all_of(sequence_hash.begin(), sequence_hash.end(),
		[](uint8_t byte) { return byte == 0; });

	if (is_empty) {
		DigestStream<HASH256_tag> digestor;

		for (const auto& tx_in : input_txs) {
			// Serialize the sequence.
			auto bytes = int_to_little_endian_bytes_pad(tx_in.get_sequence());
			digestor.update(bytes);
		}

		auto hash_2 = digestor.finalize();			
		
		std::copy(hash_2.begin(), hash_2.end(), sequence_hash.begin());
	}

	return sequence_hash;
}

// Get the hash of all the outputs required for the segwit hash.
std::array<uint8_t, 32>& Tx::hash_outputs(){
	// Serialize all transaction outputs.
	bool is_empty = std::all_of(outputs_hash.begin(), outputs_hash.end(),
		[](uint8_t byte) { return byte == 0; });

	if (is_empty) {
		uint32_t output_size = static_cast<uint32_t>(std::accumulate(output_txs.begin(), output_txs.end(), 0ULL, 
		[](uint64_t sum, const TxOut& output) { return sum + output.get_size(); }));
		
		std::vector<uint8_t> all_outputs(output_size);
		auto all_outputs_iterator = all_outputs.begin();

		for (const auto& tx_out : output_txs) {
			tx_out.serialize(all_outputs_iterator, all_outputs, false);
		}
		
		
		// Compute the hash of all inputs.
		auto hash = get_hash_256(all_outputs);			
		std::copy(hash.begin(), hash.end(), outputs_hash.begin());
	}

	return outputs_hash;
}
	

bool Tx::is_valid(uint32_t index){
	auto& tx_in = input_txs[index];

	std::vector<uint8_t> hash;

	std::vector<uint8_t> script_pubkey_bytes = hex_to_std_vec(
		TxInfoFetcher::fetch_script_pubkey(std_array_to_hex(tx_in.get_tx_id()), tx_in.get_tx_index(), testnet));

	auto script_pubkey = Script(script_pubkey_bytes.cbegin(), script_pubkey_bytes.size());
	
	if(is_p2sh(script_pubkey.get_inputs().begin(), script_pubkey.get_inputs().cend())){

		auto redeem_script_bytes = tx_in.get_script().get_inputs().back().get_value();

		auto redeem_script = Script(redeem_script_bytes.cbegin(), redeem_script_bytes.size());

		if(is_p2wsh(redeem_script.get_inputs().cbegin(), redeem_script.get_inputs().cend())){
			auto witness_script = tx_in.get_witness_data().back();
			auto witness_script_iterator = witness_script.begin();

			hash = get_bip143_transaction_hash(index, witness_script, witness_script.size());
		}
		else if(is_p2wpkh(redeem_script.get_inputs().cbegin(), redeem_script.get_inputs().cend())){

			auto pubkey_hash = redeem_script.get_inputs().back().get_value();

			std::vector<uint8_t> script_code = create_p2pkh_out_bytes(pubkey_hash);

			hash = get_bip143_transaction_hash(index, script_code);
		}
		else{
			hash = get_transaction_hash(index, redeem_script);
		}
	}
	else{

		if(is_p2wsh(script_pubkey.get_inputs().cbegin(), script_pubkey.get_inputs().cend())){
			auto witness_script = tx_in.get_witness_data().back();
			auto witness_script_iterator = witness_script.begin();

			hash = get_bip143_transaction_hash(index, witness_script, witness_script.size());
		}
		else if(is_p2wpkh(script_pubkey.get_inputs().cbegin(), script_pubkey.get_inputs().cend())){
			auto pubkey_hash = script_pubkey.get_inputs().back().get_value();

			std::vector<uint8_t> script_code = create_p2pkh_out_bytes(pubkey_hash);

			hash = get_bip143_transaction_hash(index, script_code);
		}
		else{
			hash = get_transaction_hash(index, script_pubkey);
		}
	}
	auto combined_script = tx_in.get_script() + script_pubkey;
	
	return combined_script.evaluate(hash, tx_in.get_witness_data()); // Evaluate the script with the hash.
}


bool Tx::is_valid() {
	// Check if the fee is zero or more(No bitcoins are being created).
	if (get_total_fee() < 0)
		return false;

	bool Result = true;

	// All the locking scripts(script pubkey for the inputs) have correct unlocking scripts(script sigs for the inputs)
	for (size_t counter = 0; counter < input_txs.size() && Result; ++counter) {
		Result = is_valid(counter);
	}

	return Result;
}

bool Tx::is_coinbase() {
        if (input_txs.size() != 1)
            return false;

        TxIn& input = input_txs[0];

        const auto & transaction_id = input.get_tx_id();

        if (!std::all_of(transaction_id.begin(), transaction_id.end(), [](uint8_t b){ return b == 0x00; }))
            return false;

        if (input.get_tx_index() != 0xffffffff)
            return false;

        return true;
}

std::optional<uint32_t> Tx::extract_coinbase_block_height() {
    if (!is_coinbase())
        return std::nullopt;

    // Get the scriptSig of the only input
    return big_endian_bytes_to_int<uint32_t>(input_txs[0].get_script()[0].get_value());
}

const nlohmann::json_abi_v3_12_0::json& TxInfoFetcher::fetch_tx(std::string&& tx_id, bool is_testnet) {

	auto result = cache.find(tx_id);

	// We reverse the bytes, mempool.space takes it in big endian.

	for(uint8_t counter = 0; counter < tx_id.size()/2; counter += 2){
		std::swap(tx_id[counter], tx_id[(tx_id.size() - 1)- (1 + counter)]);
		std::swap(tx_id[counter + 1], tx_id[(tx_id.size() - 1)- (counter)]);
	}

	if(result == cache.end()){
		std::string host = "mempool.space";
		std::string target = (is_testnet ? std::string("/testnet") : std::string()) + "/api/tx/" + tx_id;
		int version = 11;  

		net::io_context io_context;
		ssl::context ssl_context(ssl::context::tlsv12_client);

		tcp::resolver resolver(io_context);
		net::ssl::stream<beast::tcp_stream> stream(io_context, ssl_context);

		auto const results = resolver.resolve(host, "443");

		// Connect to mempool.space.
		beast::get_lowest_layer(stream).connect(results);

		stream.handshake(ssl::stream_base::client);

		http::request<http::string_body> request{ http::verb::get, target, version };
		request.set(http::field::host, host);
		request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

		// Send the request.
		http::write(stream, request);

		beast::flat_buffer buffer;

		http::response<http::dynamic_body> response;

		// Read the response.
		http::read(stream, buffer, response);

		beast::error_code error_code;
		stream.shutdown(error_code);

		// Handle shutdown errors (stream truncated, EOF, etc.)
		if (error_code == net::error::eof || error_code == ssl::error::stream_truncated) {
			error_code = {};
		}
		else if (error_code) {
			throw beast::system_error{ error_code };
		}

		cache.emplace(tx_id, std::make_pair(
								json::parse(beast::buffers_to_string(response.body().data())), 0));
		result = cache.find(tx_id);
	}
	else{
		result->second.second = 0;
	}

	update_cache_counts();
	return result->second.first;
}

int64_t TxInfoFetcher::fetch_input(std::string&& tx_id, bool is_testnet) {
	
	auto json_response = fetch_tx(std::forward<std::string>(tx_id),is_testnet);

	int64_t total_amount = 0;

	try {
		for (const auto& Output : json_response["vout"]) {
			total_amount += Output["value"].get<int64_t>();
		}
	}
	catch (...) {
		cache.erase(tx_id);
        throw ParsingError(ParsingError::Type::INVALID_DATA, 
			"The data returned from mempool.space is not a valid transaction.");
    }

	return total_amount;
}

std::string TxInfoFetcher::fetch_script_pubkey(std::string&& tx_id, uint64_t tx_index, bool is_testnet) {

	auto json_response = fetch_tx(std::forward<std::string>(tx_id), is_testnet);
	std::string script_pubkey;

	try {
            script_pubkey = json_response["vout"][tx_index]["scriptpubkey"].get<std::string>();
    } catch (...) {
		cache.erase(tx_id);
        throw ParsingError(ParsingError::Type::INVALID_DATA, 
			"The data returned from mempool.space is not a valid transaction.");
    }

	return script_pubkey;
}

uint64_t TxInfoFetcher::fetch_output_amount(std::string&& tx_id, uint64_t tx_index, bool IsTestnet) {

        const nlohmann::json_abi_v3_12_0::json& json_response = fetch_tx(std::forward<std::string>(tx_id), IsTestnet);
        int64_t amount = 0;

        try {
            amount = json_response["vout"][tx_index]["value"].get<int64_t>();
        } catch (...) {
			cache.erase(tx_id);
            throw ParsingError(ParsingError::Type::INVALID_DATA, 
				"The data returned from mempool.space is not a valid transaction.");
        }

        return amount;
    }

std::unordered_map<std::string, std::pair<nlohmann::json_abi_v3_12_0::json, uint32_t>> TxInfoFetcher::cache;
