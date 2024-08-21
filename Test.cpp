#include <vector>
#include <variant>
#include <iomanip>
#include <iostream>
#include "Transaction.h"
#include "Debug functions.h"
#include "Serial.h"

int Crypt_Test_1() {
	PrivateKey PKey(BigNum("99f2882e"), Secp256k1_Generator);

	BigPoint Public = PKey._PublicKey;

	std::vector<uint8_t> Message{ 1,2,3,4,5,6,7,8 };

	auto MySiganture = Secp256k1_Sign(PKey, Message);

	auto Vector = Public.UncompressedSecToStdVec();

	auto String = Public.UncompressedSecToHex();

	for (auto Element : Vector)
		std::cout << std::hex << std::setw(2) << std::setfill('0') << Element * 1 << " ";

	std::cout << "\n" << "\n";

	std::cout << String;

	std::cout << "\n" << "\n";

	if (Secp256k1_Verify(MySiganture, Message, Public))
		std::cout << "First is verified." << "\n" << "\n";

	BigPoint OtherPoint(Public._a, Public._b);

	OtherPoint.UncompressedSecFromStdVec(Vector);

	if (Secp256k1_Verify(MySiganture, Message, OtherPoint))
		std::cout << "Second is verified." << "\n" << "\n";

	return 0;
}

int Script_Test_1() {
	PrivateKey PKey(BigNum("99f2882e"), Secp256k1_Generator);

	BigPoint Public = PKey._PublicKey;

	std::vector<uint8_t> Message{ 1,2,3,4,5,6,7,8 };

	auto MySiganture = Secp256k1_Sign(PKey, Message);

	auto PublicVector = Public.CompressedSecToStdVec();

	auto SingatureVector = MySiganture.DERtoStdVec();

	ScriptInput Input1(SingatureVector);
	ScriptInput Input2(PublicVector);
	ScriptInput Input3(ScriptInput::OpCode::OP_CHECKSIG);

	std::deque<ScriptInput> Inputs;

	Inputs.push_front(Input3);
	Inputs.push_front(Input1);
	Inputs.push_front(Input2);

	Script MyScript(Inputs);

	uint32_t OldValue = MyScript.Evaluate(Message);

	std::cout << "Old value: " << OldValue << "\n" << "\n";

	std::vector<uint8_t> Result;

	std::vector<uint8_t>::iterator ResultIterator = Result.begin();

	MyScript.Serialize(Result, ResultIterator);

	ResultIterator = Result.begin();

	Script MyNewScript(ResultIterator);

	uint32_t NewValue = MyNewScript.Evaluate(std::vector<uint8_t>());

	std::cout << "New value: " << NewValue << "\n" << "\n";
	return 0;
}


int Script_Test_2() {

	ScriptInput Input1(BigNum(10));
	ScriptInput Input2(BigNum(224));
	ScriptInput Input3(ScriptInput::OpCode::OP_SUB);

	std::deque<ScriptInput> Inputs;

	Inputs.push_front(Input3);
	Inputs.push_front(Input1);
	Inputs.push_front(Input2);

	Script MyScript(Inputs);

	/*uint32_t OldValue = MyScript.Evaluate(std::vector<uint8_t>()).GetUnsignedSmall();

	std::cout << "Old value: " << OldValue << "\n" << "\n";*/

	std::vector<uint8_t> Result;
	std::vector<uint8_t>::iterator ResultIterator = Result.begin();;
	MyScript.Serialize(Result, ResultIterator);

	ResultIterator = Result.begin();
	Script MyNewScript(ResultIterator);

	uint32_t NewValue = MyNewScript.Evaluate(std::vector<uint8_t>());

	std::cout << "New value: " << NewValue << "\n" << "\n";
	return 0;
}

int Tx_Fetcher_Test() {
	try {
		std::cout << TxInfoFetcher::FetchInput("1d31642c65ffdf207075b4d323d47cfecf927d2091c33bc344dfe24fce69989a");
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
	return 0;
}

int Tx_Test() {

	std::string Hex =
		"010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e0100\
00006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951\
c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0\
da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4\
038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a473044022078\
99531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b84\
61cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba\
1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c35\
6efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da\
6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c3\
4210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49\
abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd\
04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea833\
1ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c\
2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20df\
e7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948\
a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46\
430600";

	std::vector<uint8_t> Vector = HexToStdVec(Hex);
	std::vector<uint8_t>::iterator VectorIterator = Vector.begin();

	//TransactionOut MyTransactionOut = ParseTransactionOut(VectorIterator);
	Tx MyTransaction(VectorIterator);

	std::vector<uint8_t> OtherVector;

	std::vector<uint8_t>::iterator OtherVectorIterator = OtherVector.end();

	MyTransaction.Serialize(OtherVector, OtherVectorIterator);

	std::cout << "Parsing starts here." << "\n" << "\n";

	if (BigNum(Hex) == BigNum(OtherVector))
		std::cout << "Equal" << "\n" << "\n";


	return 6;

}

int Encoding_Decoding_Test_1() {
	Tx NewTx;

	TxIn InputTx;
	InputTx.SetTxID(HexToStdVec("b232cef138eef6d4775a814e32209c73c5336f9018766818b66ce7c9ea22ef82"));
	InputTx.SetTxIndex(1);

	//std::vector<uint8_t> New

	TxOut OutputTx_1(500, CreateScriptPubkey(DecodeFromBitcoinAddress("mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv")));
	//TxOut OutputTx_2(250, CreateScriptPubkey(DecodeFromBitcoinAddress("tb1qaae6cfm97rlqpx3kj9ge68fvpuuk8rdd6yhm7g")));

	//std::vector<uint8_t> SEC = PrivateKey(BigNum(25), Secp256k1_Generator)._PublicKey.CompressedSecToStdVec();

	std::vector<uint8_t> SEC = HexToStdVec("029d386983fa7e28ceda99454d0258e89d5d8e07cdb155ac142ff6bae505997154");

	HexDump(SEC.begin(), SEC.size());

	std::string Address_1 = EncodeToBitcoinAddress(SEC, true);

	std::cout << Address_1;

	std::cout << "\n" << "\n";

	std::vector<uint8_t> NewHash = DecodeFromBitcoinAddress(Address_1);

	HexDump(NewHash.begin(), NewHash.size());

	//std::cout << EncodeToBitcoinAddress(PrivateKey(2))
	return 0;
}

int Tx_In_Test_1() {

	Tx TestTransaction;
	TestTransaction.SetLockTime(0);
	TestTransaction.SetVersion(1);
	TestTransaction.SetTestnet(true);

	TxIn InputTransaction;
	InputTransaction.SetTxID(HexToStdVec("e5b8b30fd34b96eadcbb95f743e087d7a81a2431bb8a4d7c1cb6b59b7f4bb1f7"));
	InputTransaction.SetTxIndex(0);

	std::vector<uint8_t> ScriptStream = HexToStdVec("76a914477c14873ce8778bf8f2f609ac4138ebc7c4f18488ac");

	std::vector<uint8_t>::iterator ScriptStreamIterator = ScriptStream.begin();

	ParseVariant(ScriptStream.size(), ScriptStreamIterator, ScriptStream);

	ScriptStreamIterator = ScriptStream.begin();

	HexDump(ScriptStreamIterator, ScriptStream.size());

	ScriptStreamIterator = ScriptStream.begin();
	InputTransaction.SetScript(Script(ScriptStreamIterator));

	std::vector<uint8_t> InputSerialization;
	std::vector<uint8_t>::iterator InputSerializationIterator = InputSerialization.begin();

	InputTransaction.Serialize(InputSerializationIterator, InputSerialization);

	InputSerializationIterator = InputSerialization.begin();
	HexDump(InputSerializationIterator, InputSerialization.size());

	TxIn NewTransaction(InputSerializationIterator);

	std::cout << "\n" << "\n";
	std::cout << "Sequence: " << NewTransaction.GetSequence();

	std::cout << "\n" << "\n";
	std::cout << "Index: " << NewTransaction.GetTxIndex();

	InputSerialization.clear();

	std::vector<uint8_t> Temp = NewTransaction.GetTxID();

	std::cout << "ID: ";
	HexDump(Temp.begin(), Temp.size());

	InputSerializationIterator = InputSerialization.begin();

	NewTransaction.GetScript().Serialize(InputSerialization, InputSerializationIterator);

	InputSerializationIterator = InputSerialization.begin();

	std::cout << "Script: ";
	HexDump(InputSerializationIterator, InputSerialization.size());

	return 0;
}

int TxIn_Test_2() {

	Tx TestTransaction;
	TestTransaction.SetLockTime(0);
	TestTransaction.SetVersion(1);
	TestTransaction.SetTestnet(true);

	TxIn InputTransaction;
	InputTransaction.SetTxID(HexToStdVec("e5b8b30fd34b96eadcbb95f743e087d7a81a2431bb8a4d7c1cb6b59b7f4bb1f7"));
	InputTransaction.SetTxIndex(0);

	std::vector<uint8_t> ScriptStream = HexToStdVec("76a914477c14873ce8778bf8f2f609ac4138ebc7c4f18488ac");

	std::vector<uint8_t>::iterator ScriptStreamIterator = ScriptStream.begin();

	ParseVariant(ScriptStream.size(), ScriptStreamIterator, ScriptStream);

	ScriptStreamIterator = ScriptStream.begin();

	HexDump(ScriptStreamIterator, ScriptStream.size());

	ScriptStreamIterator = ScriptStream.begin();

	InputTransaction.SetScript(Script(ScriptStreamIterator));

	std::vector<uint8_t> InputSerialization;

	std::vector<uint8_t>::iterator InputSerializationIterator = InputSerialization.begin();

	InputTransaction.Serialize(InputSerializationIterator, InputSerialization);

	InputSerializationIterator = InputSerialization.begin();

	HexDump(InputSerializationIterator, InputSerialization.size());

	PrivateKey Key(BigNum("459804aba82fa30ba0491025918d84ca08757054cf1ddc596d24a95d9ed382d2"), Secp256k1_Generator);

	Signature NewSignature = Secp256k1_Sign(Key, BigNum(GetSHA256(GetSHA256(InputSerialization))));

	DecodeFromBitcoinAddress("mn2vuv7mofHHeAVjYehNoVuibpkYALnrGU");

	std::vector<uint8_t> Vector = Key._PublicKey.CompressedSecToStdVec();

	//Vector.back() = 12;

	std::vector<uint8_t> VectorSignature = NewSignature.DERtoStdVec();

	//std::cout << "Signature 1: ";

	//HexDump(VectorSignature.begin(), VectorSignature.size());

	//std::cout << "Public key hash 1 :";

	//HexDump(Vector.begin(), Vector.size());

	//InputTransaction.SetScript(Script(Inputs));
	//std::cout << "Public key hash 2 :";

	//HexDump(GetHASH160(Key._PublicKey.CompressedSecToStdVec()).begin(), 20);

	InputTransaction.GetScript().Prepend(ScriptInput(Vector));

	InputTransaction.GetScript().Prepend(ScriptInput(VectorSignature));

	//InputSerialization.back() = 13;

	if (InputTransaction.GetScript().Evaluate(GetSHA256(GetSHA256(InputSerialization))))
		std::cout << "Well done!!!";

	return 0;
}