#include "Script.h"
#include "../Serial/Serial.h"
#include "../Debug functions/Debug functions.h"
#include <cstdint>

std::unordered_map<ScriptInput::OpCode, std::unique_ptr<Script::OpCodeFunctionBase>> Script::opcode_functions;

ScriptInput& ScriptInput::operator=(const ScriptInput& input) {
	code = input.code;
	value = input.value;
	return *this;
}

ScriptInput& ScriptInput::operator=(ScriptInput&& input) noexcept{
	code = input.code;
	value = std::move(input.value);
	return *this;
}

bool ScriptInput::operator==(const ScriptInput& input) const{
	return code == input.code && value == input.value;
}

// Duplicate the item at the top of the stack.
bool OP_dup(std::stack<ScriptInput>& script_inputs) {
	if(script_inputs.size() == 0){
		return false;
	}
	script_inputs.push(script_inputs.top());
	return true;
}

// Hash the item at the top of the stack(the previous value is removed).
bool OP_hash160(std::stack<ScriptInput>& script_inputs) {
	if(script_inputs.size() == 0){
		return false;
	}
	ScriptInput Message = script_inputs.top();
	script_inputs.pop();
	script_inputs.push(ScriptInput(DigestStream<HASH160_tag>::digest(Message.get_value())));

	return (Message.get_opcode() == ScriptInput::OpCode::OP_0);
}

// Hash the item at the top of the stack(the previous value is removed).
bool OP_hash256(std::stack<ScriptInput>& script_inputs) {
	if(script_inputs.size() == 0){
		return false;
	}
	ScriptInput Message = script_inputs.top();
	script_inputs.pop();
	script_inputs.push(ScriptInput(DigestStream<HASH256_tag>::digest(Message.get_value())));

	return (Message.get_opcode() == ScriptInput::OpCode::OP_0);
}

// Check if the two items at the top of the stack are equal
// (the two previous values are removed).
bool OP_equal(std::stack<ScriptInput>& script_inputs) {
	if(script_inputs.size() < 2){
		return false;
	}
	ScriptInput Message_1 = script_inputs.top();
	script_inputs.pop();
	ScriptInput Message_2 = script_inputs.top();
	script_inputs.pop();


	return Message_1 == Message_2;
}

// Check if the two items at the top of the stack are equal.
// (the two previous values are removed).
bool OP_equal_verify(std::stack<ScriptInput>& script_inputs) {
	if (OP_equal(script_inputs)){
		//script_inputs.push(ScriptInput(std::vector<uint8_t>(1, 0x01)));
		return true;
	}

	//script_inputs.push(ScriptInput(std::vector<uint8_t>(1, 0x00)));
	return false;
}

// Add the two elements on the top of the stack and place the addition
// there(the previous two elements are removed).
bool OP_add(std::stack<ScriptInput>& script_inputs) {

	if(script_inputs.size() == 0){
		return false;
	}

	ScriptInput Message_1 = script_inputs.top();
	script_inputs.pop();
	ScriptInput Message_2 = script_inputs.top();
	script_inputs.pop();

	if (!(Message_1.get_opcode() == ScriptInput::OpCode::OP_0) && 
	(Message_2.get_opcode() == ScriptInput::OpCode::OP_0)){
		return false;
	}

	script_inputs.push(ScriptInput((BigNum(Message_1.get_value()) + 
	BigNum(Message_2.get_value())).to_std_vec()));

	return true;
}

// Subtract the two elements on the top of the stack and place the difference
// there(the previous two elements are removed).
bool OP_sub(std::stack<ScriptInput>& script_inputs) {
	if(script_inputs.size() < 2){
		return false;
	}

	ScriptInput Message_1 = script_inputs.top();
	script_inputs.pop();
	ScriptInput Message_2 = script_inputs.top();
	script_inputs.pop();

	if (!(Message_1.get_opcode() == ScriptInput::OpCode::OP_0) && 
		(Message_2.get_opcode() == ScriptInput::OpCode::OP_0)){
		return false;
	}

	script_inputs.push(ScriptInput((BigNum(Message_1.get_value()) - 
	BigNum(Message_2.get_value())).to_std_vec()));

	return true;
}

// Check that the private key of the public key on the stack, signed the message passed
// (the previous two elements are removed).
bool OP_checksig(std::stack<ScriptInput>& script_inputs, const std::vector<uint8_t>& message_hash) {

	if(script_inputs.size() < 2){
		return false;
	}

	BigPoint public_key(Secp256k1_a, Secp256k1_b);
	public_key.from_std_vec(script_inputs.top().get_value());

	script_inputs.pop();

	BitcoinSignature signature(script_inputs.top().get_value());

	script_inputs.pop();

	if(secp256k1_verify(signature, message_hash, public_key)){
		return true;
	}


	// script_inputs.push(ScriptInput(ScriptInput::OpCode::OP_0));

	return false;
}

// Check that the private key of the public keys on the stack, signed the message passed
// all public keys, signatures and counts are removed from the stack.
bool Op_checkmultisig(std::stack<ScriptInput>&script_inputs, const std::vector<uint8_t>& message_hash){
	if(script_inputs.size() < 1){
		return false;
	}

	uint8_t public_key_count = script_inputs.top().get_value().back(); // Get the number of public keys.
	script_inputs.pop();
	if(public_key_count < 1 || script_inputs.size() < public_key_count) {
		return false;
	}

	std::vector<BigPoint> public_keys;

	for(uint8_t counter = 0; counter < public_key_count; ++counter) {
		std::vector<uint8_t> public_key_bytes = std::move(script_inputs.top().get_value());
		script_inputs.pop();
		BigPoint public_key(Secp256k1_a, Secp256k1_b);
		public_key.from_std_vec(std::move(public_key_bytes));
		public_keys.push_back(public_key);
	}

	if(public_key_count != public_keys.size()) {
		return false;
	}

	uint8_t signature_count = script_inputs.top().get_value().back(); // Get the number of signatures.
	script_inputs.pop();
	if(signature_count < 1 || script_inputs.size() < signature_count) {
		return false;
	}
	
	std::vector<BitcoinSignature> signatures;
	for(uint8_t counter = 0; counter < signature_count; ++counter) {
		if(script_inputs.empty()) {
			return false;
		}
		std::vector<uint8_t> signature_bytes = std::move(script_inputs.top().get_value());
		script_inputs.pop();
		signatures.push_back(signature_bytes);
	}

	if(signature_count != signatures.size()) {
		return false;
	}

	uint8_t valid_signatures = 0; 
	uint8_t signature_index = 0; 
	for(uint8_t counter = 0; counter < public_key_count; ++counter){
		
		if(secp256k1_verify(signatures[signature_index], message_hash, public_keys[counter])) {
			valid_signatures++;
			signature_index++;

			if(valid_signatures == signature_count) {
				break;
			}
		}
	}

	script_inputs.pop(); // Pop the off by one.

	if(valid_signatures == signature_count){
		// script_inputs.push(ScriptInput(std::vector<uint8_t>(1, 0x01)));
		return true;
	}

	// script_inputs.push(ScriptInput(std::vector<uint8_t>(1, 0x00)));
	return false;
}

// Initialize the opcode functions.
void Script::initialize_opcode_functions() {
	opcode_functions.emplace(ScriptInput::OpCode::OP_DUP, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_dup));
	opcode_functions.emplace(ScriptInput::OpCode::OP_ADD, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_add));
	opcode_functions.emplace(ScriptInput::OpCode::OP_SUB, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_sub));
	opcode_functions.emplace(ScriptInput::OpCode::OP_EQUALVERIFY, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_equal_verify));
	opcode_functions.emplace(ScriptInput::OpCode::OP_EQUAL, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_equal));
	opcode_functions.emplace(ScriptInput::OpCode::OP_HASH160, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_hash160));
	opcode_functions.emplace(ScriptInput::OpCode::OP_HASH256, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_hash256));
	opcode_functions.emplace(ScriptInput::OpCode::OP_CHECKSIG, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&, const std::vector<uint8_t>&>>(OP_checksig));
	opcode_functions.emplace(ScriptInput::OpCode::OP_CHECKMULTISIG, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&, const std::vector<uint8_t>&>>(Op_checkmultisig));
}

void Script::serialize(std::vector<uint8_t>& input, std::vector<uint8_t>::iterator& start, bool should_adjust_iterator) const {
	// The rules for the magical constants that appear here are:- 
	// If the byte count is less than or equal to 75 then leave the size value as is.
	// else
	// If the byte count is greater than 75 and less than 256 then put in 76 and then the actual size
	// else
	// If the byte count is greater than 256 and less than 512 then put in 77 and then the actual size in two bytes.
	// There is an OP_PUSHDATA_4(78) but the max size for script inputs is capped at 520 bytes so it is not used.

	uint32_t size = get_size();
	
	if(should_adjust_iterator){
		adjust_bytes(start, input, size + get_varint_byte_size(size)); // Scripts are always serialized with their size.
	}

	serialize_varint(size, start, input, false);

	std::deque<ScriptInput>::const_iterator input_iterator = inputs.cbegin();

	while (input_iterator != inputs.cend()) {
		if (input_iterator->get_opcode() != ScriptInput::OpCode::OP_0) { // If we have an Opcode
			// Insert the Opcode and advance the iterator and increase the size.
			*start = static_cast<uint8_t>(input_iterator->get_opcode());
			start++;
		}
		else { // If we have a number(not necessarily a number, but some bytes).
			if (input_iterator->get_value().size() <= 75) {
				// Insert the byte count of the new ScriptInput and advance the iterator and increase the size.
				*start = static_cast<uint8_t>(input_iterator->get_value().size());
				start++;
			}
			else
				if (input_iterator->get_value().size() > 75 && input_iterator->get_value().size() < 256) {
					// Insert 76 and the byte count of the new ScriptInput and advance the iterator and increase the size.
					*start = 76;
					start++;
					*start = static_cast<uint8_t>(input_iterator->get_value().size());
					start++;
				}
				else
					if (input_iterator->get_value().size() >= 256 && input_iterator->get_value().size() < 512) {
						// Insert 77 and the byte count of the new ScriptInput and advance the iterator and increase the size.
						*start = 77;
						start++;
						*start = static_cast<uint8_t>(input_iterator->get_value().size());
						start++;
						*start = static_cast<uint8_t>((input_iterator->get_value().size() >> 8));
						start++;
					}

			std::vector<uint8_t> result_value = input_iterator->get_value(); 

			start = std::copy(result_value.begin(), result_value.end(), start);
		}
		input_iterator++;
	}
}

void Script::inputs_from_bytes(std::vector<uint8_t>::const_iterator&& input, uint32_t input_size, bool prepend){
	// The rules for the magical constants that appear here are:- 
	// If the value is greater than 77, it an Opcode.
	// else
	// If the value is 77, the next two bytes store the size of the next input.
	// else
	// If the value is 76, the next byte store the size of the next input.
	// else
	// If the value is less than or equal to 75, that byte is the size of the next input.
	// There is an OP_PUSHDATA_4(78) but the max size for script inputs is capped at 520 bytes so it is not used.


	uint8_t marker = 0;
	uint16_t element_size = 0;
	uint32_t count = 0;
	uint16_t added_count = 0;

	while (input_size > count) {
		marker = *input;

		input++;
		count++;

		if (marker > 77) { 
			if(prepend){
				inputs.push_front(ScriptInput(static_cast<ScriptInput::OpCode>(marker)));
			}
			else{
				inputs.push_back(ScriptInput(static_cast<ScriptInput::OpCode>(marker)));
			}
		}
		else
		{
			if (marker <= 75) {
				element_size = marker;
			}
			else
				if (marker == 76) {
					element_size = *input;

					input++;
					count++;
				}
				else
					if (marker == 77) {
						// Extract the lower byte of the size.
						element_size = *input;

						input++;
						count++;

						// Extract the higher byte of the size.
						element_size += (*input << 8);

						input++;
						count++;
					}
					
				if(prepend){	
					inputs.push_front(ScriptInput(std::vector<uint8_t>(input, input + element_size)));
				
				}
				else{
					inputs.push_back(ScriptInput(std::vector<uint8_t>(input, input + element_size)));
				}
				input += element_size;
				count += element_size;
		}

		added_count++;
		
		
	}
	
	if(prepend){
		std::reverse(inputs.begin() + (inputs.size() - added_count), inputs.end());
	}
	
}

bool Script::evaluate_with_script_pubkey(const std::vector<uint8_t>& Hash, const Script& script_pubkey, const std::vector<std::vector<uint8_t>>& witness_data) {
	
	return false;
}

bool Script::evaluate_with_script_sig(const std::vector<uint8_t>& Hash, const Script& script_sig, const std::vector<std::vector<uint8_t>>& witness_data) {
	
	return false;
}

// Fix needed: The input stack is left in an inconsistent state if an unexpected error is thrown.
bool Script::evaluate(const std::vector<uint8_t>& Hash, const std::vector<std::vector<uint8_t>>& witness_data) {
	// Stores data operands.
	std::stack<ScriptInput> operand_stack;

	auto temp_inputs = inputs.begin();
	auto current_size = inputs.size();

	
	
	while (temp_inputs != inputs.end()) {

		if(is_p2sh(temp_inputs, inputs.end())){ // https://learnmeabitcoin.com/technical/script/p2sh/
									
			OP_dup(operand_stack);

			OP_hash160(operand_stack);

			operand_stack.push(temp_inputs[1]);

			if(!OP_equal(operand_stack)){
				inputs.resize(current_size);
				return false;
			}
			std::vector<uint8_t> script = std::move(operand_stack.top().get_value());

			operand_stack.pop();

			// Skip over p2sh inputs.
			temp_inputs += 3;

			std::deque<ScriptInput> temp_remaining_inputs;
			std::copy(std::make_move_iterator(temp_inputs), std::make_move_iterator(inputs.end()), 
			std::back_inserter(temp_remaining_inputs));

			auto current_index = temp_inputs - inputs.begin();
			inputs.resize(current_index);

			append_parse_from_non_prefixed_size(script.cbegin(), script.size());

			std::copy(std::make_move_iterator(temp_remaining_inputs.begin()), std::make_move_iterator(temp_remaining_inputs.end()), 
			std::back_inserter(inputs));

			temp_inputs = inputs.begin() + current_index;
			
		}
		else if (is_p2wpkh(temp_inputs, inputs.end())) { // https://learnmeabitcoin.com/technical/script/p2wpkh/
			if (witness_data.size() < 2) {
				inputs.resize(current_size);
				throw ScriptError(ScriptError::Type::WITNESS_DATA_MISSING);
			}

			auto pubkey_hash = temp_inputs[1].get_value();

			// Skip over p2wpkh inputs.
			temp_inputs += 2;

			std::deque<ScriptInput> temp_remaining_inputs;
			std::copy(std::make_move_iterator(temp_inputs), std::make_move_iterator(inputs.end()), 
			std::back_inserter(temp_remaining_inputs));

			auto current_index = temp_inputs - inputs.begin();
			inputs.resize(current_index);

			auto p2pkh_out_bytes = create_p2pkh_out_bytes(pubkey_hash);


			
			inputs.push_back(ScriptInput(witness_data[0]));
			inputs.push_back(ScriptInput(witness_data[1]));

			append_parse(p2pkh_out_bytes.cbegin());


			
			std::copy(std::make_move_iterator(temp_remaining_inputs.begin()), std::make_move_iterator(temp_remaining_inputs.end()), 
			std::back_inserter(inputs));


			temp_inputs = inputs.begin() + current_index;
  		}
		else if (is_p2wsh(temp_inputs, inputs.end())) { // https://learnmeabitcoin.com/technical/script/p2wsh/
			if (witness_data.size() < 1){
				inputs.resize(current_size);
				throw ScriptError(ScriptError::Type::WITNESS_DATA_MISSING);
			}

			auto witness_hash = temp_inputs[1].get_value();


			// Skip over p2wsh inputs.
			temp_inputs += 2;

			std::deque<ScriptInput> temp_remaining_inputs;
			std::copy(std::make_move_iterator(temp_inputs), std::make_move_iterator(inputs.end()), 
			std::back_inserter(temp_remaining_inputs));

			auto current_index = temp_inputs - inputs.begin();
			inputs.resize(current_index);

			for(const auto& witness_script : witness_data) {

				operand_stack.push(ScriptInput(witness_script));
			}
			
			operand_stack.push(get_sha_256(operand_stack.top().get_value()));

			operand_stack.push(witness_hash);

			if(!OP_equal(operand_stack)){
				inputs.resize(current_size);
				return false;
			}

			auto redeem_script = std::move(operand_stack.top().get_value());

			operand_stack.pop();

			append_parse_from_non_prefixed_size(redeem_script.cbegin(), redeem_script.size());
			
			std::copy(std::make_move_iterator(temp_remaining_inputs.begin()), std::make_move_iterator(temp_remaining_inputs.end()), 
			std::back_inserter(inputs));

			temp_inputs = inputs.begin() + current_index;
  		}
		else{	
			ScriptInput temp_input = *temp_inputs;



			if (temp_input.get_opcode() != ScriptInput::OpCode::OP_0) {

				// If it is a number represented by an opcode add the number to the stack
				if(static_cast<uint8_t>(temp_input.get_opcode()) >= static_cast<uint8_t>(ScriptInput::OpCode::OP_1) && 
				static_cast<uint8_t>(temp_input.get_opcode()) <= static_cast<uint8_t>(ScriptInput::OpCode::OP_16)) {
					operand_stack.push(ScriptInput(std::vector<uint8_t>(1, temp_input.get_int_from_opcode().value())));
				}
				else{
					auto temp_opcode_function = opcode_functions.find(temp_input.get_opcode());
					
					if (temp_opcode_function == opcode_functions.end()){
						inputs.resize(current_size);
						throw ScriptError(ScriptError::Type::OPCODE_NOT_SUPPORTED);
					}
						
					OpCodeFunctionBase* temp_function = temp_opcode_function->second.get();
					
					if (static_cast<uint8_t>(temp_input.get_opcode()) >= 99 && static_cast<uint8_t>(temp_input.get_opcode()) <= 100) {
						// No instruction in this range is supported by this program.
						throw ScriptError(ScriptError::Type::OPCODE_NOT_SUPPORTED);
					}
					else
						if (static_cast<uint8_t>(temp_input.get_opcode()) >= 107 && static_cast<uint8_t>(temp_input.get_opcode()) <= 108) {
							// No instruction in this range is supported by this program.
							throw ScriptError(ScriptError::Type::OPCODE_NOT_SUPPORTED);
							}
						else
							if (static_cast<uint8_t>(temp_input.get_opcode()) >= 172 && static_cast<uint8_t>(temp_input.get_opcode()) <= 175) {
								auto result = dynamic_cast<OpCodeFunction<bool, std::stack<ScriptInput>&, const std::vector<uint8_t>&>*>(temp_function);
								if (result) {
									bool operation_result = result->call(operand_stack, Hash);

									if (!operation_result){
										inputs.resize(current_size);
										return false;
									}	
								}
								else {
									inputs.resize(current_size);
									throw ScriptError(ScriptError::Type::FUNCTION_CAST_FAILED);
								}
							}
							else {
								auto result = dynamic_cast<OpCodeFunction<bool, std::stack<ScriptInput>&>*>(temp_function);
								if (result) {
									bool operation_result = result->call(operand_stack);

									if (!operation_result){
										inputs.resize(current_size);
										return false;
									}	
								}
								else {
									inputs.resize(current_size);
									throw ScriptError(ScriptError::Type::FUNCTION_CAST_FAILED);
								}
								}
							}
			}
			else {

				operand_stack.push(temp_input);
			}

			temp_inputs++;
		}
	}

	inputs.resize(current_size);
	return true; // This does not conform to the implementation in the actual Bitcoin code, but it is used here because, following
				 // the implementation, without changing a lot of other thing that are also different from the standard would cause
				 // errors based on the way it is implemented here, it could also falsely return true if data was placed in the right
				 // places instead of opcodes, e.g if only data was placed in the stack, it would return true.
}

uint32_t Script::get_size() const {
    // Calculate the size of the serialized script as per the serialize function.
    uint32_t count = 0;

    for (const auto& input : inputs) {
        if (input.get_opcode() != ScriptInput::OpCode::OP_0) {
            // Opcode only: 1 byte
            count += 1;
        } else {
            size_t value_size = input.get_value().size();
            if (value_size <= 75) {
                // 1 byte for size + value_size bytes for data
                count += 1 + value_size;
            } else if (value_size > 75 && value_size < 256) {
                // 1 byte for 76 + 1 byte for size + value_size bytes for data
                count += 1 + 1 + value_size;
            } else if (value_size >= 256 && value_size < 512) {
                // 1 byte for 77 + 2 bytes for size + value_size bytes for data
                count += 1 + 2 + value_size;
            }
        }
    }

    // Add the varint size for the total count
    return count;
}

Script Script::operator+(const Script& other) const {
	std::deque<ScriptInput> result = inputs;
	result.insert(result.end(), other.inputs.begin(), other.inputs.end());
	return Script(std::move(result));
}

Script create_p2pk_out(const std::vector<uint8_t>& pubkey) {
    std::deque<ScriptInput> inputs;
    inputs.push_back(ScriptInput(pubkey));
    inputs.push_back(ScriptInput(ScriptInput::OpCode::OP_CHECKSIG));
    return Script(inputs);
}

Script create_p2pk_in(const std::vector<uint8_t>& signature) {
	std::deque<ScriptInput> inputs;
	inputs.push_back(ScriptInput(signature));
	return Script(std::move(inputs));
}

Script create_p2pkh_out(const std::vector<uint8_t>& hash_160) {
	std::deque<ScriptInput> inputs;
	inputs.push_back(ScriptInput::OpCode::OP_DUP);
	inputs.push_back(ScriptInput::OpCode::OP_HASH160);
	inputs.push_back(ScriptInput(hash_160));
	inputs.push_back(ScriptInput::OpCode::OP_EQUALVERIFY);
	inputs.push_back(ScriptInput::OpCode::OP_CHECKSIG);

	return Script(std::move(inputs));
}

std::vector<uint8_t> create_p2pkh_out_bytes(const std::vector<uint8_t>& hash_160) {
	std::vector<uint8_t> bytes(get_varint_byte_size(25) + 2 + 1 + 20 + 2);
	std::vector<uint8_t>::iterator bytes_iterator = bytes.begin();
	serialize_varint(25, bytes_iterator, bytes, false);

	*bytes_iterator = static_cast<uint8_t>(ScriptInput::OpCode::OP_DUP);
	bytes_iterator++;
	*bytes_iterator = static_cast<uint8_t>(ScriptInput::OpCode::OP_HASH160);
	bytes_iterator++;
	*bytes_iterator = static_cast<uint8_t>(hash_160.size());
	bytes_iterator++;
	bytes_iterator = std::copy(hash_160.begin(), hash_160.end(), bytes_iterator);
	*bytes_iterator = static_cast<uint8_t>(ScriptInput::OpCode::OP_EQUALVERIFY);
	bytes_iterator++;
	*bytes_iterator = static_cast<uint8_t>(ScriptInput::OpCode::OP_CHECKSIG);

	return bytes;
}

Script create_p2pkh_in(const std::vector<uint8_t>& signature, const std::vector<uint8_t>& public_key) {
	std::deque<ScriptInput> inputs;
	inputs.push_back(ScriptInput(signature));
	inputs.push_back(ScriptInput(public_key));

	return Script(std::move(inputs));
}

Script create_p2ms_out(uint8_t signature_count, uint8_t pubkey_count, const std::vector<std::vector<uint8_t>>& public_keys) {
	std::deque<ScriptInput> inputs;

	// Nodes don't relay more than 3 public keys in a multisig script, though up to 20 should be allowed, 
	// and the signature count must be at least 1 and at most the number of public keys.
	// See here:- https://learnmeabitcoin.com/technical/script/p2ms
	if (signature_count < 1 || signature_count > pubkey_count || pubkey_count < 1 || 
		pubkey_count > 3||  public_keys.size() != pubkey_count) {
		throw std::invalid_argument("Invalid signature or public key count for multisig script.");
	}

	inputs.push_back(ScriptInput(static_cast<ScriptInput::OpCode>(signature_count + static_cast<uint8_t>(ScriptInput::OpCode::OP_1)))); 
	for (const auto& pubkey : public_keys) {
		inputs.push_back(ScriptInput(pubkey));
	}
	inputs.push_back(ScriptInput(static_cast<ScriptInput::OpCode>(pubkey_count + static_cast<uint8_t>(ScriptInput::OpCode::OP_1)))); 
	inputs.push_back(ScriptInput::OpCode::OP_CHECKMULTISIG);

	return Script(std::move(inputs));
}

Script create_p2ms_in(const std::vector<std::vector<uint8_t>>& signatures) {
	std::deque<ScriptInput> inputs;
	inputs.push_back(ScriptInput::OpCode::OP_0); // For off by one error in multisig scripts.
	for (const auto& signature : signatures) {
		inputs.push_back(ScriptInput(signature));
	}

	return Script(std::move(inputs));
}

Script create_p2sh_out(const std::vector<uint8_t>& hash_160) {
	std::deque<ScriptInput> inputs;
	inputs.push_back(ScriptInput::OpCode::OP_HASH160);
	inputs.push_back(ScriptInput(hash_160));
	inputs.push_back(ScriptInput::OpCode::OP_EQUAL);

	return Script(std::move(inputs));
}

Script create_p2wpkh_out(const std::vector<uint8_t>& h160) {
	std::deque<ScriptInput> inputs;
    inputs.push_back(ScriptInput(static_cast<ScriptInput::OpCode>(0x00))); // OP_0
    inputs.push_back(ScriptInput(h160)); // Push the hash160
	return Script(std::move(inputs));
}

// Check if the script is a Pay to Script Hash (P2SH).
bool is_p2sh(std::deque<ScriptInput>::const_iterator iterator, std::deque<ScriptInput>::const_iterator end) {
    // Need at least 3 elements for a valid P2SH pattern
    auto it = iterator;
    if (std::distance(it, end) != 3){
	 	return false;
	}

    return (it[0] == ScriptInput::OpCode::OP_HASH160) &&
           (it[1].get_value().size() == 20) &&
           (it[2] == ScriptInput::OpCode::OP_EQUAL);
}

// Check if the script is a Pay to witness public key hash (P2WPKH).
bool is_p2wpkh(std::deque<ScriptInput>::const_iterator iterator, std::deque<ScriptInput>::const_iterator end) {
    auto it = iterator;
    if (std::distance(it, end) != 2) {
		return false; 
	}

    return (it[0] == ScriptInput::OpCode::OP_0) &&
           (it[1].get_value().size() == 20);
}

// Check if the script is a Pay to witness Script Hash (P2WSH).
bool is_p2wsh(std::deque<ScriptInput>::const_iterator iterator, std::deque<ScriptInput>::const_iterator end) {
    auto it = iterator;
    if (std::distance(it, end) != 2) {
		return false; 
	}

    return (it[0] == ScriptInput::OpCode::OP_0) &&
           (it[1].get_value().size() == 32);
}
