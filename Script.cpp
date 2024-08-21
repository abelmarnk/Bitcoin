#include "Script.h"
#include "Debug functions.h"

std::unordered_map<ScriptInput::OpCode, std::unique_ptr<Script::OpCodeFunctionBase>> Script::OpCodeFunctions;

ScriptInput& ScriptInput::operator=(const ScriptInput& Input) {
	Code = Input.Code;
	Value = Input.Value;
	return *this;
}

ScriptInput& ScriptInput::operator=(ScriptInput&& Input) noexcept {
	Code = Input.Code;
	Value = std::move(Input.Value);
	return *this;
}

bool ScriptInput::operator==(const ScriptInput& Input) {
	return Code == Input.Code && Value == Input.Value;
}

bool OP_dup(std::stack<ScriptInput>& ScriptInputs) {
	ScriptInputs.push(ScriptInputs.top()); // Duplicate the top input of the stack.
	return true;
}

bool OP_hash160(std::stack<ScriptInput>& ScriptInputs) {
	// Remove the top value off the stack and replace it with its hash160 value.
	ScriptInput Message = ScriptInputs.top();
	ScriptInputs.pop();
	ScriptInputs.push(ScriptInput(GetHASH160(Message.GetValue().ToStdVec())));

	return (Message.GetOpCode() == ScriptInput::OpCode::OP_0);
}

bool OP_equalverify(std::stack<ScriptInput>& ScriptInputs) {
	// remove the top two elements of the stack and return true if equal.
	ScriptInput Message_1 = ScriptInputs.top();
	ScriptInputs.pop();
	ScriptInput Message_2 = ScriptInputs.top();
	ScriptInputs.pop();

	return (Message_1 == Message_2);
}

bool OP_add(std::stack<ScriptInput>& ScriptInputs) {
	// Remove the top two elements of the stack and put the sum at the top.
	ScriptInput Message_1 = ScriptInputs.top();
	ScriptInputs.pop();
	ScriptInput Message_2 = ScriptInputs.top();
	ScriptInputs.pop();
	ScriptInputs.push(ScriptInput(Message_1.GetValue() + Message_2.GetValue()));

	return (Message_1.GetOpCode() == ScriptInput::OpCode::OP_0) && (Message_2.GetOpCode() == ScriptInput::OpCode::OP_0);
}

bool OP_sub(std::stack<ScriptInput>& ScriptInputs) {
	// Remove the top two elements of the stack and put the difference at the top.
	ScriptInput Message_1 = ScriptInputs.top();
	ScriptInputs.pop();
	ScriptInput Message_2 = ScriptInputs.top();
	ScriptInputs.pop();
	ScriptInputs.push(ScriptInput(Message_1.GetValue() - Message_2.GetValue()));

	return (Message_1.GetOpCode() == ScriptInput::OpCode::OP_0) && (Message_2.GetOpCode() == ScriptInput::OpCode::OP_0);
}

bool OP_checksig(std::stack<ScriptInput>& ScriptInputs, const std::vector<uint8_t>& MessageHash) {
	// Remove a signature and a public key from the top of a stack and replace with one if valid, do nothing more otherwise.

	std::vector<uint8_t> Result_2 = ScriptInputs.top().GetValue().ToStdVec();

	std::cout << "Public key 2: ";

	HexDump(Result_2.begin(), Result_2.size());

	BigPoint PublicKey(Secp256k1_a, Secp256k1_b);
	PublicKey.CompressedSecFromStdVec(ScriptInputs.top().GetValue().ToStdVec());
	ScriptInputs.pop();

	std::vector<uint8_t> Result_1 = ScriptInputs.top().GetValue().ToStdVec();

	std::cout << "Signature 2: ";

	HexDump(Result_1.begin(), Result_1.size());

	Signature MySignature(ScriptInputs.top().GetValue().ToStdVec());
	ScriptInputs.pop();

	bool Value = Secp256k1_Verify(MySignature, MessageHash, PublicKey);

	if (Value)
		ScriptInputs.push(ScriptInput(1));

	return Value;
}

void Script::InitializeOpCodeFunctions() {
	OpCodeFunctions.emplace(ScriptInput::OpCode::OP_DUP, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_dup));
	OpCodeFunctions.emplace(ScriptInput::OpCode::OP_ADD, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_add));
	OpCodeFunctions.emplace(ScriptInput::OpCode::OP_SUB, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_sub));
	OpCodeFunctions.emplace(ScriptInput::OpCode::OP_EQUALVERIFY, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_equalverify));
	OpCodeFunctions.emplace(ScriptInput::OpCode::OP_HASH160, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&>>(OP_hash160));
	OpCodeFunctions.emplace(ScriptInput::OpCode::OP_CHECKSIG, std::make_unique<OpCodeFunction<bool, std::stack<ScriptInput>&, const std::vector<uint8_t>&>>(OP_checksig));
}

void Script::Serialize(std::vector<uint8_t>& Result, std::vector<uint8_t>::iterator& Start) const {
	// The rules for the magical constants that appear here are:- 
	// If the byte count is less than or equal to 75 then leave the size value as is.
	// else
	// If the byte count is greater than 75 and less than 256 then put in 76 and then the actual size
	// else
	// If the byte count is greater than 256 and less than 512 then put in 77 and then the actual size in two bytes.

	size_t SizePosition = Start - Result.begin(); // Position where the size would eventually be inserted(it may be more efficient to calculate and insert the size before hand for large inputs).

	size_t Count = 0; // Stores the size(byte count excluding the actual size variant).

	std::deque<ScriptInput>::const_iterator InputIterator = Inputs.cbegin();

	while (InputIterator != Inputs.cend()) {
		if (InputIterator->GetOpCode() != ScriptInput::OpCode::OP_0) { // If we have an Opcode
			// Insert the Opcode and advance the iterator and increase the size.
			Start = Result.insert(Start, static_cast<uint8_t>(InputIterator->GetOpCode()));
			Start++;
			Count += 1;
		}
		else { // If we have a number(not necessarily a number, but some bytes).
			if (InputIterator->GetValue().ByteCount() <= 75) {
				// Insert the byte count of the new ScriptInput and advance the iterator and increase the size.
				Start = Result.insert(Start, static_cast<uint8_t>(InputIterator->GetValue().ByteCount()));
				Start++;
				Count += 1;
			}
			else
				if (InputIterator->GetValue().ByteCount() > 75 && InputIterator->GetValue().ByteCount() < 256) {
					// Insert 76 and the byte count of the new ScriptInput and advance the iterator and increase the size.
					Start = Result.insert(Start, 76);
					Start++;
					Start = Result.insert(Start, static_cast<uint8_t>(InputIterator->GetValue().ByteCount()));
					Start++;
					Count += 2;
				}
				else
					if (InputIterator->GetValue().ByteCount() >= 256 && InputIterator->GetValue().ByteCount() < 512) {
						// Insert 77 and the byte count of the new ScriptInput and advance the iterator and increase the size.
						Start = Result.insert(Start, 77);
						Start++;
						Start = Result.insert(Start, static_cast<uint8_t>(InputIterator->GetValue().ByteCount()));
						Start++;
						Start = Result.insert(Start, static_cast<uint8_t>((InputIterator->GetValue().ByteCount() >> 8)));
						Start++;
						Count += 3;
					}

			std::vector<uint8_t> ResultValue = std::move(InputIterator->GetValue().ToStdVec()); // Get the bytes.

			Start = Result.insert(Start, ResultValue.begin(), ResultValue.end()); // Insert the bytes.
			Start += ResultValue.end() - ResultValue.begin(); // Advance the iterator.
			Count += ResultValue.size(); // increase the size.
		}
		InputIterator++;
	}

	std::vector<uint8_t>::iterator I = Result.begin() + SizePosition;
	Variant CountVariant = Count;
	ParseVariant(CountVariant, I, Result); // Insert the variant for the size.

	Start = Result.begin() + SizePosition + CountVariant.ByteCount() + Count; // Position the iterator.

}

void Script::Parse(std::vector<uint8_t>::iterator& Input) {
	// The rules for the magical constants that appear here are:- 
	// If the value is greater than 77, it an Opcode.
	// else
	// If the value is 77, the next two bytes store the size of the next input.
	// else
	// If the value is 76, the next byte store the size of the next input.
	// else
	// If the value is less than or equal to 75, that byte is the size of the next input.

	std::vector<uint8_t> TempValue;
	uint8_t Marker = 0;
	uint16_t ElementSize = 0;
	uint64_t Count = 0;
	uint64_t InputSize = ParseVariant(Input).GetUnsignedSmall();

	while (InputSize > Count) {
		Marker = *Input;
		Input++;
		Count++;

		if (Marker > 77) {
			// This is is an Opcode.
			Inputs.push_back(ScriptInput(static_cast<ScriptInput::OpCode>(Marker)));
		}
		else
		{
			if (Marker <= 75) {
				// This is a sequence of bytes of at most 75 in length.
				TempValue.insert(TempValue.begin(), Input, Input + Marker);
				// Advance the iterator and increase the size.
				Input += Marker;
				Count += Marker;
			}
			else
				if (Marker == 76) {
					// Get the size of the input.
					ElementSize = *Input;

					// Advance the iterator and increase the size.
					Input++;
					Count++;

					// This is a sequence of bytes of at most 255 in length.
					TempValue.insert(TempValue.begin(), Input, Input + ElementSize);

					// Advance the iterator and increase the size.
					Input += ElementSize;
					Count += ElementSize;
				}
				else
					if (Marker == 77) {
						// Extract the lower byte of the size.
						ElementSize = *Input;

						// Advance the iterator and increase the size.
						Input++;
						Count++;

						// Extract the higher byte of the size.
						ElementSize = (*Input << 8) + ElementSize;

						// Advance the iterator and increase the size.
						Input++;
						Count++;
						TempValue.insert(TempValue.begin(), Input, Input + ElementSize);

						// Advance the iterator and increase the size.
						Input += ElementSize;
						Count += ElementSize;
					}

			// Place the input in the stack.
			Inputs.push_back(ScriptInput(Variant(TempValue)));
			// We need to re-use this guy.
			TempValue.clear();
		}
	}
}

bool Script::Evaluate(const std::vector<uint8_t>& Hash) const {
	std::deque<ScriptInput> TempInputs = Inputs;
	std::stack<ScriptInput> OperandStack;
	std::stack<ScriptInput> AltOperandStack;
	uint64_t ScriptInputCount = 0;

	std::cout << "Hash 2: ";
	std::vector<uint8_t> HashCopy(Hash);
	HexDump(HashCopy.begin(), HashCopy.size());

	while (TempInputs.size() > 0) {
		ScriptInput TempInput = TempInputs.front();
		TempInputs.pop_front();

		if (TempInput.GetOpCode() != ScriptInput::OpCode::OP_0) {

			ScriptInput::OpCode NewOpCode = TempInput.GetOpCode();

			auto TempOpCodeFunction = OpCodeFunctions.find(NewOpCode);

			if (TempOpCodeFunction == OpCodeFunctions.end())
				throw OpCodeNotSupportedError{};

			OpCodeFunctionBase* TempFunction = TempOpCodeFunction->second.get();

			if (static_cast<uint8_t>(TempInput.GetOpCode()) >= 99 && static_cast<uint8_t>(TempInput.GetOpCode()) <= 100) {

			}
			else
				if (static_cast<uint8_t>(TempInput.GetOpCode()) >= 107 && static_cast<uint8_t>(TempInput.GetOpCode()) <= 108) {

					auto Result = dynamic_cast<OpCodeFunction<bool, std::stack<ScriptInput>&, std::stack<ScriptInput>&>*>(TempFunction);
					if (Result) {
						bool OperationResult = Result->call(OperandStack, AltOperandStack);

						if (!OperationResult)
							return false;
					}
					else {
						throw(FunctionError());
					}
				}
				else
					if (static_cast<uint8_t>(TempInput.GetOpCode()) >= 172 && static_cast<uint8_t>(TempInput.GetOpCode()) <= 175) {
						auto Result = dynamic_cast<OpCodeFunction<bool, std::stack<ScriptInput>&, const std::vector<uint8_t>&>*>(TempFunction);
						if (Result) {
							bool OperationResult = Result->call(OperandStack, Hash);

							if (!OperationResult)
								return false;
						}
						else {
							throw(FunctionError());
						}
					}
					else
					{
						auto Result = dynamic_cast<OpCodeFunction<bool, std::stack<ScriptInput>&>*>(TempFunction);
						if (Result) {
							bool OperationResult = Result->call(OperandStack);

							if (!OperationResult)
								return false;
						}
						else {
							throw(FunctionError());
						}
					}
		}
		else {
			OperandStack.push(TempInput);
		}
	}

	return (OperandStack.size() > 0 && OperandStack.top().GetValue() != 0);
}

Script Script::operator+(const Script& Other) const {
	std::deque<ScriptInput> Result = Inputs;
	Result.insert(Result.end(), Other.Inputs.begin(), Other.Inputs.end());
	return Script(std::move(Result));
}

Script CreateScriptPubkey(const std::vector<uint8_t>& Hash160) {
	std::deque<ScriptInput> Inputs;
	Inputs.push_back(ScriptInput::OpCode::OP_DUP);
	Inputs.push_back(ScriptInput::OpCode::OP_HASH160);
	Inputs.push_back(ScriptInput(Hash160));
	Inputs.push_back(ScriptInput::OpCode::OP_EQUALVERIFY);
	Inputs.push_back(ScriptInput::OpCode::OP_CHECKSIG);

	return Script(std::move(Inputs));
}