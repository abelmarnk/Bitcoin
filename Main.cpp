#include <vector>
#include <variant>
#include <iomanip>
#include <iostream>
#include "Transaction.h"
#include "Debug functions.h"
#include "Serial.h"

int main() {

	Tx TestTransaction;
	TestTransaction.SetLockTime(0);
	TestTransaction.SetVersion(1);
	TestTransaction.SetTestnet(true);


	TxIn InputTransaction;
	InputTransaction.SetTxID(HexToStdVec("c4b72c4267d2f11b07acd5ea484cade23dc9dda67a34751a52e340c08539fb07"));
	InputTransaction.SetTxIndex(0);

	// Fetch the new script.
	std::vector<uint8_t> ScriptPubKey = HexToStdVec(TxInfoFetcher::FetchScriptPubKey(StdVecToHex(InputTransaction.GetTxID()), InputTransaction.GetTxIndex()));

	std::vector<uint8_t>::iterator ScriptPubKeyIterator = ScriptPubKey.begin();

	ParseVariant(ScriptPubKey.size(), ScriptPubKeyIterator, ScriptPubKey);

	ScriptPubKeyIterator = ScriptPubKey.begin();

	// Set the new script.
	InputTransaction.SetScript(Script(ScriptPubKeyIterator));

	TxOut OutputTransaction;
	OutputTransaction.SetAmount(5000);
	OutputTransaction.SetScript(std::move(CreateScriptPubkey(DecodeFromBitcoinAddress("n3R9qYkfLW8EBJiRRTAc9GYrRUuxpFHiqo"))));

	TestTransaction.SetTxIns(std::vector<TxIn>{InputTransaction});

	TestTransaction.SetTxOuts(std::vector<TxOut>{OutputTransaction});

	std::vector<uint8_t> InputSerialization;

	std::vector<uint8_t>::iterator InputSerializationIterator = InputSerialization.begin();

	TestTransaction.Serialize(InputSerialization, InputSerializationIterator);

	InputSerialization.insert(InputSerialization.end(), Tx::SIGHASH_ALL.begin(), Tx::SIGHASH_ALL.end());

	InputSerializationIterator = InputSerialization.begin();

	PrivateKey Key(BigNum("459804aba82fa30ba0491025918d84ca08757054cf1ddc596d24a95d9ed382d2"), Secp256k1_Generator);

	std::vector<uint8_t> Hash = GetSHA256(GetSHA256(InputSerialization));

	Signature NewSignature = Secp256k1_Sign(Key, BigNum(Hash));

	std::vector<uint8_t> Vector = Key._PublicKey.CompressedSecToStdVec();

	std::cout << "Key 1: ";

	HexDump(Vector.begin(), Vector.size());

	std::vector<uint8_t> VectorSignature = NewSignature.DERtoStdVec();

	std::cout << "Signature 1: ";
	HexDump(VectorSignature.begin(), VectorSignature.size());

	if (Secp256k1_Verify(NewSignature, Hash, Key._PublicKey))
		std::cout << "First verified.";

	std::deque<ScriptInput> Inputs;

	Inputs.push_back(ScriptInput(VectorSignature));

	Inputs.push_back(ScriptInput(Vector));

	InputTransaction.SetScript(Script(Inputs));

	TestTransaction.SetTxIns(std::vector<TxIn>{InputTransaction});



	if (TestTransaction.IsValid())
		std::cout << "You are doing fine, keep it up";

	std::cout << "\n" << "\n";


	std::vector<uint8_t> FinalResult;

	std::vector<uint8_t>::iterator FinalResultIterator = FinalResult.begin();

	TestTransaction.Serialize(FinalResult, FinalResultIterator);

	FinalResultIterator = FinalResult.begin();

	std::cout << "Final Result" << "\n";

	HexDump(FinalResultIterator, FinalResult.size());

	Tx NewTransaction(FinalResultIterator);

	if (NewTransaction.IsValid())
		std::cout << "You are doing fine, keep it up";

	std::vector<uint8_t> Inputt;


	std::vector<uint8_t>::iterator InputIterator = Inputt.begin();

	InputTransaction.GetScript().Serialize(Inputt, InputIterator);

	InputIterator = Inputt.begin();

	std::cout << "Final Result" << "\n";

	HexDump(InputIterator, Inputt.size());


	std::cout << "\n" << "\n";

	return 0;
}