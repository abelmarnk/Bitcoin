#pragma once
#include <functional>
#include <stack>
#include <deque>
#include "../Crypt/Crypt.h"
#include "../Varint/Varint.h"
#include <optional>

class ScriptInput {
public:
	enum class OpCode : uint8_t {
		OP_FALSE = 0x00,
		OP_0 = OP_FALSE,
		OP_PUSHDATA1 = 0x4c,
		OP_PUSHDATA2 = 0x4d,
		OP_PUSHDATA4 = 0x4e,
		OP_1NEGATE = 0x4f,
		OP_RESERVED = 0x50,
		OP_TRUE = 0x51,
		OP_1 = OP_TRUE,
		OP_2 = 0x52,
		OP_3 = 0x53,
		OP_4 = 0x54,
		OP_5 = 0x55,
		OP_6 = 0x56,
		OP_7 = 0x57,
		OP_8 = 0x58,
		OP_9 = 0x59,
		OP_10 = 0x5a,
		OP_11 = 0x5b,
		OP_12 = 0x5c,
		OP_13 = 0x5d,
		OP_14 = 0x5e,
		OP_15 = 0x5f,
		OP_16 = 0x60,
		OP_NOP = 0x61,
		OP_VER = 0x62,
		OP_IF = 0x63,
		OP_NOTIF = 0x64,
		OP_VERIF = 0x65,
		OP_VERNOTIF = 0x66,
		OP_ELSE = 0x67,
		OP_ENDIF = 0x68,
		OP_VERIFY = 0x69,
		OP_RETURN = 0x6a,
		OP_TOALTSTACK = 0x6b,
		OP_FROMALTSTACK = 0x6c,
		OP_2DROP = 0x6d,
		OP_2DUP = 0x6e,
		OP_3DUP = 0x6f,
		OP_2OVER = 0x70,
		OP_2ROT = 0x71,
		OP_2SWAP = 0x72,
		OP_IFDUP = 0x73,
		OP_DEPTH = 0x74,
		OP_DROP = 0x75,
		OP_DUP = 0x76,
		OP_NIP = 0x77,
		OP_OVER = 0x78,
		OP_PICK = 0x79,
		OP_ROLL = 0x7a,
		OP_ROT = 0x7b,
		OP_SWAP = 0x7c,
		OP_TUCK = 0x7d,
		OP_CAT = 0x7e,
		OP_SUBSTR = 0x7f,
		OP_LEFT = 0x80,
		OP_RIGHT = 0x81,
		OP_SIZE = 0x82,
		OP_INVERT = 0x83,
		OP_AND = 0x84,
		OP_OR = 0x85,
		OP_XOR = 0x86,
		OP_EQUAL = 0x87,
		OP_EQUALVERIFY = 0x88,
		OP_RESERVED1 = 0x89,
		OP_RESERVED2 = 0x8a,
		OP_1ADD = 0x8b,
		OP_1SUB = 0x8c,
		OP_2MUL = 0x8d,
		OP_2DIV = 0x8e,
		OP_NEGATE = 0x8f,
		OP_ABS = 0x90,
		OP_NOT = 0x91,
		OP_0NOTEQUAL = 0x92,
		OP_ADD = 0x93,
		OP_SUB = 0x94,
		OP_MUL = 0x95,
		OP_DIV = 0x96,
		OP_MOD = 0x97,
		OP_LSHIFT = 0x98,
		OP_RSHIFT = 0x99,
		OP_BOOLAND = 0x9a,
		OP_BOOLOR = 0x9b,
		OP_NUMEQUAL = 0x9c,
		OP_NUMEQUALVERIFY = 0x9d,
		OP_NUMNOTEQUAL = 0x9e,
		OP_LESSTHAN = 0x9f,
		OP_GREATERTHAN = 0xa0,
		OP_LESSTHANOREQUAL = 0xa1,
		OP_GREATERTHANOREQUAL = 0xa2,
		OP_MIN = 0xa3,
		OP_MAX = 0xa4,
		OP_WITHIN = 0xa5,
		OP_RIPEMD160 = 0xa6,
		OP_SHA1 = 0xa7,
		OP_SHA256 = 0xa8,
		OP_HASH160 = 0xa9,
		OP_HASH256 = 0xaa,
		OP_CODESEPARATOR = 0xab,
		OP_CHECKSIG = 0xac,
		OP_CHECKSIGVERIFY = 0xad,
		OP_CHECKMULTISIG = 0xae,
		OP_CHECKMULTISIGVERIFY = 0xaf,
		OP_NOP1 = 0xb0,
		OP_CHECKLOCKTIMEVERIFY = 0xb1,
		OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
		OP_CHECKSEQUENCEVERIFY = 0xb2,
		OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
		OP_NOP4 = 0xb3,
		OP_NOP5 = 0xb4,
		OP_NOP6 = 0xb5,
		OP_NOP7 = 0xb6,
		OP_NOP8 = 0xb7,
		OP_NOP9 = 0xb8,
		OP_NOP10 = 0xb9,
		OP_INVALIDOPCODE = 0xff
	};
public:
	ScriptInput(OpCode code) :code(code) {
	}

	ScriptInput(const std::vector<uint8_t>& Number) :code(OpCode::OP_0), value(Number) {
	}

	ScriptInput(std::vector<uint8_t>&& Number) :code(OpCode::OP_0), value(std::move(Number)) {
	}

	ScriptInput(const ScriptInput& input) :code(input.code), value(input.value) {
	}

	ScriptInput(ScriptInput&& input) noexcept :code(input.code), value(std::move(input.value)) {
	}

	ScriptInput():code(OpCode::OP_0), value(std::vector<uint8_t>(1, 0x00)){

	}

	~ScriptInput() {
	}

	ScriptInput& operator=(const ScriptInput& input);

	// Two ScriptInputs are equal if their codes and values are equal.
	bool operator==(const ScriptInput& input)const;

	ScriptInput& operator=(ScriptInput&& input) noexcept;

	inline std::vector<uint8_t> get_value() const {
		return value;
	}

	inline std::vector<uint8_t>& get_value() {
		return value;
	}

	static std::optional<uint8_t> get_int_from_opcode(OpCode code){
		if(static_cast<uint8_t>(code) >= static_cast<uint8_t>(ScriptInput::OpCode::OP_1) && 
				static_cast<uint8_t>(code) <= static_cast<uint8_t>(ScriptInput::OpCode::OP_16)) {
					return static_cast<uint8_t>(code) - 
					static_cast<uint8_t>(ScriptInput::OpCode::OP_1) + 1;
		}

		return std::nullopt;
			
	}

	std::optional<uint8_t> get_int_from_opcode(){
		if(static_cast<uint8_t>(code) >= static_cast<uint8_t>(ScriptInput::OpCode::OP_1) && 
				static_cast<uint8_t>(code) <= static_cast<uint8_t>(ScriptInput::OpCode::OP_16)) {
					return static_cast<uint8_t>(code) - 
					static_cast<uint8_t>(ScriptInput::OpCode::OP_1) + 1;
		}

		return std::nullopt;
			
	}

	uint32_t get_opcode_as_int(){
					return static_cast<uint32_t>(code);
	}

	inline OpCode get_opcode() const {
		return code;
	}

private:
	OpCode code;
	std::vector<uint8_t> value;

};

class Script {

public:

	class OpCodeFunctionBase {
	public:
		virtual ~OpCodeFunctionBase() = default;
		virtual void call() = 0; // This is just a placeholder; we'll use derived class methods.
	};

	template<typename Ret, typename... Args>
	class OpCodeFunction : public OpCodeFunctionBase {
	private:
		std::function<Ret(Args...)> func;
	public:
		OpCodeFunction(std::function<Ret(Args...)> f) : func(f) {}

		Ret call(Args... args) {
			return func(args...);
		}

		void call() {

		}

	};


	Script() {
	}

	Script(std::deque<ScriptInput>& input) {
		initialize_opcode_functions();
		inputs = input;
	}

	Script(std::deque<ScriptInput>&& input) {
		initialize_opcode_functions();
		inputs = std::move(input);
	}

	Script(std::vector<uint8_t>::const_iterator&& input, uint64_t size) {
		initialize_opcode_functions();
		parse_from_non_prefixed_size(std::forward<std::vector<uint8_t>::const_iterator>(input), size);
	}

	Script(std::vector<uint8_t>::const_iterator&& input) {
		initialize_opcode_functions();
		parse(std::forward<std::vector<uint8_t>::const_iterator>(input));
	}

	Script(const Script& input) {
		initialize_opcode_functions();
		inputs = input.inputs;
	}

	Script(Script&& input) noexcept {
		initialize_opcode_functions();
		inputs = std::move(input.inputs);
	}

	~Script() {
	}

	ScriptInput& operator[](size_t Index) {
		return inputs[Index];
	}

	
	const ScriptInput& operator[](size_t Index) const{
		return inputs[Index];
	}

	void initialize_opcode_functions();

	Script& operator=(const Script& input) {
		inputs = input.inputs;
		return *this;
	}

	Script& operator=(Script&& input) noexcept {
		inputs = std::move(input.inputs);
		return *this;
	}

	void serialize(std::vector<uint8_t>& result, std::vector<uint8_t>::iterator& start, bool should_adjust_iterator = true) const;

	void serialize(std::vector<uint8_t>& result, bool should_adjust_iterator = true) const{
		auto iterator = result.begin();
		serialize(result, iterator, should_adjust_iterator);
	}

	void inputs_from_bytes(std::vector<uint8_t>::const_iterator&& input, uint32_t size, bool prepend);

	void prepend_parse(std::vector<uint8_t>::const_iterator&& input){
		uint32_t input_size = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(input)); // Note: Don't attempt to move the parse_varint call inside the 
												// parse_from_non_prefixed_size call directly parse_varint modifies input
												// and the order that the arguments is captured may not be as expected.
			
		inputs_from_bytes(std::forward<std::vector<uint8_t>::const_iterator>(input), input_size, true);
	}

	void append_parse(std::vector<uint8_t>::const_iterator&& input){
		uint32_t input_size = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(input)); // Note: Don't attempt to move the parse_varint call inside the 
												// parse_from_non_prefixed_size call directly parse_varint modifies input
												// and the order that the arguments is captured may not be as expected.
			
		
		inputs_from_bytes(std::forward<std::vector<uint8_t>::const_iterator>(input), input_size, false);
	}

	void prepend_parse_from_non_prefixed_size(std::vector<uint8_t>::const_iterator&& input, uint32_t size){
		inputs_from_bytes(std::forward<std::vector<uint8_t>::const_iterator>(input), size, true);
	}

	void append_parse_from_non_prefixed_size(std::vector<uint8_t>::const_iterator&& input, uint32_t size){
		inputs_from_bytes(std::forward<std::vector<uint8_t>::const_iterator>(input), size, false);
	}

	void parse_from_non_prefixed_size(std::vector<uint8_t>::const_iterator&& input, uint32_t input_size) {
		clear();
		prepend_parse_from_non_prefixed_size(std::forward<std::vector<uint8_t>::const_iterator>(input), input_size);
	}

	void parse(std::vector<uint8_t>::const_iterator&& input) {

		uint32_t input_size = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(input)); // Note: Don't attempt to move the parse_varint call inside the 
												// parse_from_non_prefixed_size call directly parse_varint modifies input
												// and the order that the arguments is captured may not be as expected.
														
		parse_from_non_prefixed_size(std::forward<std::vector<uint8_t>::const_iterator>(input), input_size);

	}


	// Evaluate the script based on the opcodes and data in "inputs".
	// These functions are actually a simplification of Bitcoin's actual interpreter.
	// Assumes both the script pubkey and script sig are present.
	bool evaluate(const std::vector<uint8_t>& hash = std::vector<uint8_t>(), const std::vector<std::vector<uint8_t>>& witness_data = std::vector<std::vector<uint8_t>>());

	// Assumes the script sig is present and the script pubkey is passed.
	bool evaluate_with_script_pubkey(const std::vector<uint8_t>& hash, const Script& script_pubkey, const std::vector<std::vector<uint8_t>>& witness_data = std::vector<std::vector<uint8_t>>());

	// Assumes the script pubkey is present and the script sig is passed
	bool evaluate_with_script_sig(const std::vector<uint8_t>& hash, const Script& script_sig, const std::vector<std::vector<uint8_t>>& witness_data = std::vector<std::vector<uint8_t>>());

	// Combine two scripts together.
	Script operator+(const Script& Other) const;

	void prepend(const ScriptInput& input) {
		inputs.push_front(input);
	}

	void prepend(ScriptInput&& input) {
		inputs.push_front(std::move(input));
	}
	void append(const ScriptInput& input) {
		inputs.push_back(input);
	}

	void append(ScriptInput&& input) {
		inputs.push_back(std::move(input));
	}

	void clear() {
		inputs.clear();
	}

	std::deque<ScriptInput>& get_inputs() {
		return inputs;
	}

	uint32_t get_input_count() const{
		return static_cast<uint32_t>(inputs.size());
	}

	// Get the size in bytes of the serialization of the script.
    uint32_t get_size() const;


private:
	// Stores the opcodes and data.
	std::deque<ScriptInput> inputs;
	// Stores the function for each opcode
	static std::unordered_map<ScriptInput::OpCode, std::unique_ptr<OpCodeFunctionBase>> opcode_functions;
};

// Create a Pay to Public Key (P2PK) ScriptPubKey.
Script create_p2pk_out(const std::vector<uint8_t>& pubkey);

// Create a Pay to Public Key (P2PK) ScriptSig.
Script create_p2pk_in(const std::vector<uint8_t>& signature);

// Create a Pay to Public Key Hash (P2PKH) ScriptPubKey.
Script create_p2pkh_out(const std::vector<uint8_t>& hash_160);
std::vector<uint8_t> create_p2pkh_out_bytes(const std::vector<uint8_t>& hash_160);

// Create a Pay to Public Key Hash (P2PKH) ScriptSig.
Script create_p2pkh_in(const std::vector<uint8_t>& signature, const std::vector<uint8_t>& public_key);

// Create a Pay to Multisig (P2MS) ScriptPubKey.
Script create_p2ms_out(uint8_t signature_count, uint8_t pubkey_count, const std::vector<std::vector<uint8_t>>& public_keys);

// Create a Pay to Multisig (P2MS) ScriptSig.
Script create_p2ms_in(const std::vector<std::vector<uint8_t>>& signatures);

// Create a Pay to Script Hash (P2SH) ScriptPubKey.
Script create_p2sh_out(const std::vector<uint8_t>& hash_160);

// Create a Pay to Witness Public Key Hash (P2WPKH) ScriptPubKey.
Script create_p2wpkh_out(const std::vector<uint8_t>& h160);


// Check if the script is a Pay to Script Hash (P2SH).
bool is_p2sh(std::deque<ScriptInput>::const_iterator iterator, std::deque<ScriptInput>::const_iterator end);

// Check if the script is a Pay to witness public key hash (P2WPKH).
bool is_p2wsh(std::deque<ScriptInput>::const_iterator iterator, std::deque<ScriptInput>::const_iterator end);

// Check if the script is a Pay to witness Script Hash (P2WSH).
bool is_p2wpkh(std::deque<ScriptInput>::const_iterator iterator, std::deque<ScriptInput>::const_iterator end);