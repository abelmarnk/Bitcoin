#include "Debug functions.h"
#include "Transaction.h"
#include <iostream>

TxIn& TxIn::operator=(const TxIn& MyInput) {
	TxID = MyInput.TxID;
	TxIndex = (MyInput.TxIndex);
	ScriptSig = MyInput.ScriptSig;
	Sequence = MyInput.Sequence;
	return *this;
}

TxIn& TxIn::operator=(TxIn&& MyInput) {
	TxID = std::move(MyInput.TxID);
	TxIndex = (MyInput.TxIndex);
	ScriptSig = std::move(MyInput.ScriptSig);
	Sequence = MyInput.Sequence;
	return *this;
}


void TxIn::Parse(std::vector<uint8_t>::iterator& Start) {

	// Read Tx ID.
	TxID = std::move(std::vector<uint8_t>(Start, Start + TxIDTypeSize));

	// Advance the iterator.
	Start += TxIDTypeSize;

	// Read Tx index.
	std::copy_n(Start, TxIndexTypeSize, (uint8_t*)&TxIndex);

	// Advance the iterator.
	Start += TxIndexTypeSize;

	// Read the script-sig and advance the iterator.
	ScriptSig.Parse(Start);

	// Read the sequence.
	std::copy_n(Start, SequenceTypeSize, (uint8_t*)&Sequence);

	// Advance the iterator.
	Start += SequenceTypeSize;
}

void TxIn::Serialize(std::vector<uint8_t>::iterator& Start, std::vector<uint8_t>& Input) const {
	// Write Tx ID.
	// // The Addition of padding would be neccesary in the case where we have a constructor or function that allows us to set the
	// TxID and have the byte size not sum up to 32, since none such exist the below line shouldn't exist either but i feel a bit
	// queasy about not having it, if at all some one came and added such a function without this knowledge they would spend some time 
	// trying to find the bug, or worse, there would be no bug, and they would end up with a seemingly correct program. 

	uint8_t Counter = TxIDTypeSize - TxID.size();

	while (Counter > 0) {
		Start = Input.insert(Start, 0x00); // Add padding.
		Start++;

		Counter--;
	}

	Start = Input.insert(Start, TxID.begin(), TxID.end()); // Make the copy
	Start += TxID.end() - TxID.begin(); // Advance the iterator.

	// Write Tx index.
	std::vector<uint8_t> VectorTxIndex = std::move(Variant(TxIndex).ToStdVec_32()); // sizeof(MyTx.TxIndex) == 4 bytes;
	std::reverse(VectorTxIndex.begin(), VectorTxIndex.end()); // Convert to little endian.


	Start = Input.insert(Start, VectorTxIndex.begin(), VectorTxIndex.end()); // Make the copy
	Start += VectorTxIndex.end() - VectorTxIndex.begin(); // Advance the iterator.

	// Write ScriptSig.
	ScriptSig.Serialize(Input, Start); //Makes the copy and advances the iterator.

	// Write Sequence.
	std::vector<uint8_t> Sequence_ = std::move(Variant(Sequence).ToStdVec_32());  // Add the appropriate front padding(the size is always 32 bytes irregardless of the number's size).
	std::reverse(Sequence_.begin(), Sequence_.end()); // Convert to little endian.

	Start = Input.insert(Start, Sequence_.begin(), Sequence_.end()); // Make the copy.
	Start += Sequence_.end() - Sequence_.begin();  // Advance the iterator.
}

TxOut& TxOut::operator=(const TxOut& MyOutput) {
	Amount = MyOutput.Amount;
	ScriptSig = MyOutput.ScriptSig;
	return *this;
}

TxOut& TxOut::operator=(TxOut&& MyOutput) {
	Amount = MyOutput.Amount;
	ScriptSig = std::move(MyOutput.ScriptSig);
	return *this;
}


void TxOut::Parse(std::vector<uint8_t>::iterator& Start) {
	// Read Amount.
	std::copy_n(Start, AmountTypeSize, (uint8_t*)&Amount);

	// Advance the iterator.
	Start += AmountTypeSize;

	// Read the Script-sig
	ScriptSig.Parse(Start); // Read and advance the iterator.
}

void TxOut::Serialize(std::vector<uint8_t>::iterator& Start, std::vector<uint8_t>& Input) const {
	std::vector<uint8_t> Vector = std::move(Variant(Amount).ToStdVec_64()); //sizeof(MyTx.Amount) == 8 bytes;
	std::reverse(Vector.begin(), Vector.end()); // Convert to little endian.

	// Write Amount.
	Start = Input.insert(Start, Vector.begin(), Vector.end());

	Start += Vector.end() - Vector.begin();	// Advance the iterator.							

	// Write ScriptSig.
	ScriptSig.Serialize(Input, Start); // Make the write and advance the iterator.
}

const std::vector<uint8_t> Tx::SIGHASH_ALL{ 0x01,0x00,0x00,0x00 };


Tx& Tx::operator=(const Tx& MyTx) {
	Version = MyTx.Version;
	InputTxs = MyTx.InputTxs;
	OutputTxs = MyTx.OutputTxs;
	Locktime = MyTx.Locktime;
	Testnet = MyTx.Testnet;
	return *this;
}

Tx& Tx::operator=(Tx&& MyTx) noexcept {
	Version = MyTx.Version;
	InputTxs = std::move(MyTx.InputTxs);
	OutputTxs = std::move(MyTx.OutputTxs);
	Locktime = MyTx.Locktime;
	Testnet = MyTx.Testnet;
	return *this;
}


void Tx::Parse(std::vector<uint8_t>::iterator& Input) {
	ParseVersion(Input); // Read the version and advance the iterator.

	size_t InputSize = ParseVariant(Input).GetUnsignedSmall(); // The call to GetUnsignedSmall is valid as a variant is always less than
																// std::numeric_limits<uint64_t>::max().
	while (InputSize > 0) {

		TxIn MyInput;
		InputTxs.push_back(TxIn(Input)); // Read the input Txs and advance the iterator.
		InputSize--;
	}
	size_t OutputSize = ParseVariant(Input).GetUnsignedSmall(); // The call to GetUnsignedSmall is valid as a variant is always less than
																// std::numeric_limits<uint64_t>::max().
	while (OutputSize > 0) {
		OutputTxs.push_back(TxOut(Input)); // Read the output Txs and advance the iterator.
		OutputSize--;
	}

	ParseLocktime(Input); // Read the locktime and advance the iterator.

	Testnet = false;
}

void Tx::Serialize(std::vector<uint8_t>& Input, std::vector<uint8_t>::iterator& InputIterator) const {
	SerializeVersion(InputIterator, Input); // Write the Version and advance the iterator.

	ParseVariant(InputTxs.size(), InputIterator, Input); // Write a variant(Number of Tx inputs) and advance the iterator.

	auto Iterator = InputTxs.begin();

	while (Iterator != InputTxs.end()) {
		Iterator->Serialize(InputIterator, Input); // Write the Tx inputs and advance the iterator.
		Iterator++;
	}

	ParseVariant(OutputTxs.size(), InputIterator, Input); // Write a variant(Number of Tx outputs) and advance the iterator.

	auto OutputIterator = OutputTxs.begin();

	while (OutputIterator != OutputTxs.end()) {
		OutputIterator->Serialize(InputIterator, Input); // Write the Tx outputs and advance the iterator.
		OutputIterator++;
	}

	SerializeLocktime(InputIterator, Input); // Write the locktime and advance the iterator.

}

void Tx::ParseVersion(std::vector<uint8_t>::iterator& Start) {
	std::vector<uint8_t> Version_(Start, Start + 4);
	std::reverse(Version_.begin(), Version_.end()); // Make the conversion to big-endian.

	Variant Number(Version_);
	Start += Version_.end() - Version_.begin();

	Version = static_cast<uint32_t>(Number.GetUnsignedSmall()); // The call is valid due to the integer occupying only 4 bytes.
}

void Tx::SerializeVersion(std::vector<uint8_t>::iterator& Start, std::vector<uint8_t>& Input) const {
	std::vector<uint8_t> Vector(std::move(Variant(Version).ToStdVec_32())); //sizeof(Version) == 4 bytes;
	std::reverse(Vector.begin(), Vector.end()); // Make the conversion to little-endian.

	Start = Input.insert(Start, Vector.begin(), Vector.end()); //Make the write.
	Start += Vector.end() - Vector.begin(); // Advance the iterator.										
}

void Tx::ParseLocktime(std::vector<uint8_t>::iterator& Start) {
	// Read the locktime.
	std::copy_n(Start, 4, (uint8_t*)&Locktime);

	// Advance the iterator.
	Start += 4;
}

void Tx::SerializeLocktime(std::vector<uint8_t>::iterator& Start, std::vector<uint8_t>& Input) const {
	std::vector<uint8_t> Vector = std::move(Variant(Locktime).ToStdVec_32()); //sizeof(Locktime) == 4 bytes;
	std::reverse(Vector.begin(), Vector.end()); // Convert to little-endian.

	Start = Input.insert(Start, Vector.begin(), Vector.end()); // Write the locktime.
	Start += Vector.end() - Vector.begin();	// Advance the iterator.
}

int64_t Tx::GetOutputSum() const {
	int64_t OutputTxSum = 0;

	for (auto& OutputTx : OutputTxs) {
		OutputTxSum += OutputTx.GetAmount();
	}

	return OutputTxSum;
}

int64_t Tx::GetInputSum() const {
	int64_t InputTxSum = 0;
	for (auto& InputTx : InputTxs) {
		InputTxSum += TxInfoFetcher::FetchInput(BigNum(InputTx.GetTxID()).ToHex());
	}
	return InputTxSum;
}

// This is a private function so it shouldn't have a wrong index
std::vector<uint8_t> Tx::GetTransactionHash(uint64_t Index) {

	std::vector<Script> OldScripts;
	
	for (auto& InputTransaction : InputTxs) { // Move the old scripts.
		OldScripts.push_back(std::move(InputTransaction.GetScript()));
		InputTransaction.ClearScript();
	}

	// Fetch the new script.
	std::vector<uint8_t> ScriptPubKey = HexToStdVec(TxInfoFetcher::FetchScriptPubKey(StdVecToHex(InputTxs[Index].GetTxID()), InputTxs[Index].GetTxIndex()));

	std::vector<uint8_t>::iterator ScriptPubKeyIterator = ScriptPubKey.begin();

	ParseVariant(ScriptPubKey.size(), ScriptPubKeyIterator, ScriptPubKey);

	ScriptPubKeyIterator = ScriptPubKey.begin();

	// Set the new script.
	InputTxs[Index].SetScript(Script(ScriptPubKeyIterator));

	std::vector<uint8_t> TxSerialization;
	std::vector<uint8_t>::iterator TxSerializationIterator = TxSerialization.begin();

	Serialize(TxSerialization, TxSerializationIterator);

	for (size_t Counter = 0; Counter < OldScripts.size(); Counter++) { // Return the old scripts.
		InputTxs[Counter].SetScript(std::move(OldScripts[Counter]));
	}

	TxSerialization.insert(TxSerialization.end(), SIGHASH_ALL.begin(), SIGHASH_ALL.end());

	return GetSHA256(GetSHA256(TxSerialization)); // Double hash **Extra protection**.
}

bool Tx::IsValid() {
	if (GetTotalFee() < 0)
		return false;

	bool Result = true;

	for (size_t Counter = 0; Counter < InputTxs.size() && Result; Counter++) {
		Script Script_1 = InputTxs[Counter].GetScript();

		std::vector<uint8_t> ScriptPubKey = HexToStdVec(TxInfoFetcher::FetchScriptPubKey(StdVecToHex(InputTxs[Counter].GetTxID()), InputTxs[Counter].GetTxIndex()));

		std::vector<uint8_t>::iterator ScriptPubKeyIterator = ScriptPubKey.begin();

		ParseVariant(ScriptPubKey.size(), ScriptPubKeyIterator, ScriptPubKey);

		ScriptPubKeyIterator = ScriptPubKey.begin();

		Script Script_2(ScriptPubKeyIterator);

		Script Script_3(Script_1 + Script_2);

		InputTxs[Counter].SetScript(std::move(Script_3));

		std::cout << "Hash 3: ";
		std::vector<uint8_t> HashCopy(GetTransactionHash(Counter));
		HexDump(HashCopy.begin(), HashCopy.size());

		Result = (InputTxs[Counter].GetScript().Evaluate(HashCopy));

		InputTxs[Counter].SetScript(std::move(Script_1));
	}

	return Result;
}

nlohmann::json_abi_v3_11_3::json TxInfoFetcher::FetchTx(const std::string& TxID, bool IsTestnet) {
	std::string Host = "mempool.space";
	std::string Target = (IsTestnet ? std::string("/testnet") : std::string()) + "/api/tx/" + TxID;
	int Version = 11;  // HTTP version 1.1

	// Create an I/O context and SSL context with TLSv1.2
	net::io_context IO_Context;
	ssl::context SSL_Context(ssl::context::tlsv12_client);

	// Create an SSL stream
	tcp::resolver Resolver(IO_Context);
	net::ssl::stream<beast::tcp_stream> Stream(IO_Context, SSL_Context);

	// Resolve the domain name
	auto const Results = Resolver.resolve(Host, "443");

	// Connect to the host
	beast::get_lowest_layer(Stream).connect(Results);

	// Perform the SSL handshake
	Stream.handshake(ssl::stream_base::client);

	// Set up an HTTP GET request message
	http::request<http::string_body> Request{ http::verb::get, Target, Version };
	Request.set(http::field::host, Host);
	Request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

	// Send the HTTP request to the remote host
	http::write(Stream, Request);

	// This buffer is used for reading and must be persisted
	beast::flat_buffer Buffer;

	// Declare a container to hold the response
	http::response<http::dynamic_body> Response;

	// Receive the HTTP response
	http::read(Stream, Buffer, Response);


	// Close the SSL connection
	beast::error_code ErrorCode;
	Stream.shutdown(ErrorCode);

	// Handle shutdown errors (stream truncated, EOF, etc.)
	if (ErrorCode == net::error::eof || ErrorCode == ssl::error::stream_truncated) {
		// This is common for HTTP/1.1, where the server may close the connection before the SSL shutdown
		ErrorCode = {};
	}
	else if (ErrorCode) {
		throw beast::system_error{ ErrorCode };
	}

	// Parse the JSON response
	return json::parse(beast::buffers_to_string(Response.body().data()));
}

int64_t TxInfoFetcher::FetchInput(const std::string& TxID, bool IsTestnet) {
	
	// Parse the JSON response
	auto JsonResponse = FetchTx(TxID,IsTestnet);

	int64_t TotalAmount = 0;

	for (const auto& Output : JsonResponse["vout"]) {
		TotalAmount += Output["value"].get<int64_t>();
	}

	return TotalAmount;
}

std::string TxInfoFetcher::FetchScriptPubKey(const std::string& TxID, uint64_t TxIndex, bool IsTestnet) {

	// Parse the JSON response
	auto JsonResponse = FetchTx(TxID, IsTestnet);

	return JsonResponse["vout"][TxIndex]["scriptpubkey"].get<std::string>();
}
