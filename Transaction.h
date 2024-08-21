#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <nlohmann/json.hpp>  
#include "Crypt.h"
#include "Script.h"
#include "Variant.h"

class TxInfoFetcher;

class TxIn {
public:

	typedef std::vector<uint8_t> TxIDType;
	typedef uint32_t TxIndexType;
	typedef Script ScriptType;
	typedef uint32_t SequenceType;

	static const uint8_t TxIDTypeSize = 32;
	static const uint8_t TxIndexTypeSize = 4;
	// The Script size is variable.
	static const uint8_t SequenceTypeSize = 4;

	TxIn(const TxIDType& TxID, TxIndexType  TxIndex, const ScriptType& ScriptSig, SequenceType Sequence) :
		TxID(TxID), TxIndex(TxIndex), ScriptSig(ScriptSig), Sequence(Sequence) {
	}

	TxIn():TxIndex(), Sequence(0xffffffff){
	}

	TxIn(std::vector<uint8_t>::iterator& Start) :TxIndex(), Sequence() {
		Parse(Start);
	}

	TxIn(const TxIn& MyInput): 
		TxID(MyInput.TxID), TxIndex(MyInput.TxIndex),
		ScriptSig(MyInput.ScriptSig),Sequence(MyInput.Sequence) {

	}

	TxIn(TxIn&& MyInput) noexcept:
		TxID(std::move(MyInput.TxID)), TxIndex(MyInput.TxIndex),
		ScriptSig(std::move(MyInput.ScriptSig)), Sequence(MyInput.Sequence) {

	}

	TxIn& operator=(const TxIn& MyInput);

	TxIn& operator=(TxIn&& MyInput);

	void Parse(std::vector<uint8_t>::iterator& Start);

	void Serialize(std::vector<uint8_t>::iterator& Start, std::vector<uint8_t>& Input) const;

	const SequenceType GetSequence() const{
		return Sequence;
	}

	ScriptType& GetScript(){
		return ScriptSig;
	}

	void SetScript(const ScriptType& NewScript) {
		ScriptSig = NewScript;
	}

	void SetScript(ScriptType&& NewScript) {
		ScriptSig = std::move(NewScript);
	}

	void ClearScript() {
		ScriptSig.Clear();
	}

	const TxIDType& GetTxID() const{
		return TxID;
	}

	void SetTxID(const TxIDType& NewTxID) {
		TxID = NewTxID;
	}

	const TxIndexType GetTxIndex() const{
		return TxIndex;
	}

	void SetTxIndex(TxIndexType NewTxIndex) {
		TxIndex = NewTxIndex;
	}


private:
	TxIDType TxID;
	TxIndexType TxIndex;
	ScriptType ScriptSig;
	SequenceType Sequence;
};



class TxOut {
public:
	typedef uint64_t AmountType;
	typedef Script PublicScriptType;

	static const uint8_t AmountTypeSize = 8;
	// The PublicScriptType has a variable size.

	TxOut(AmountType  Amount, PublicScriptType ScriptSig) :
		Amount(Amount), ScriptSig(ScriptSig) {
	}

	TxOut() :Amount() {
	}

	TxOut(std::vector<uint8_t>::iterator& Start) {
		Parse(Start);
	}

	TxOut(const TxOut& MyOutput) :
		Amount(MyOutput.Amount),ScriptSig(MyOutput.ScriptSig){

	}

	TxOut(TxOut&& MyOutput) :
		Amount(MyOutput.Amount), ScriptSig(std::move(MyOutput.ScriptSig)){

	}

	TxOut& operator=(const TxOut& MyOutput);

	TxOut& operator=(TxOut&& MyOutput);


	void Parse(std::vector<uint8_t>::iterator& Start);

	void Serialize(std::vector<uint8_t>::iterator& Start, std::vector<uint8_t>& Input) const;

	AmountType GetAmount() const{
		return Amount;
	}

	void SetAmount(AmountType NewAmount) {
		Amount = NewAmount;
	}

	void SetScript(const PublicScriptType& NewScript) {
		ScriptSig = NewScript;
	}

	void SetScript(PublicScriptType&& NewScript) {
		ScriptSig = std::move(NewScript);
	}

	const PublicScriptType& GetScript() const{
		return ScriptSig;
	}

private:
	AmountType Amount;
	PublicScriptType ScriptSig;
};

class Tx {
public:
	typedef uint64_t VersionType;
	typedef TxIn TxInType;
	typedef TxOut TxOutType;
	typedef uint32_t LocktimeType;
	typedef bool TestnetType;
public:

	static const std::vector<uint8_t> SIGHASH_ALL;

	static const uint32_t LocktimeSize = 4;
	Tx(VersionType Version, const std::vector<TxInType> &InputTxs, const std::vector<TxOutType>& OutputTxs, LocktimeType Locktime, TestnetType Testnet) :
		Version(Version), InputTxs(InputTxs), OutputTxs(OutputTxs), Locktime(Locktime), Testnet(Testnet) {
	}

	Tx():Version(),Locktime(),Testnet() {
	}

	Tx(std::vector<uint8_t>::iterator& Input){
		Parse(Input);
	}

	Tx(const Tx& MyTx) :
		Version(MyTx.Version),
		InputTxs(MyTx.InputTxs), OutputTxs(MyTx.OutputTxs),
		Locktime(MyTx.Locktime), Testnet(MyTx.Testnet) {

	}

	Tx(Tx&& MyTx) noexcept:
		Version(MyTx.Version),
		InputTxs(std::move(MyTx.InputTxs)), OutputTxs(std::move(MyTx.OutputTxs)),
		Locktime(MyTx.Locktime), Testnet(MyTx.Testnet) {

	}

	Tx& operator=(const Tx& MyTx);

	Tx& operator=(Tx&& MyTx) noexcept;

	void Parse(std::vector<uint8_t>::iterator& Input);

	void Serialize(std::vector<uint8_t>& Input, std::vector<uint8_t>::iterator& InputIterator) const;

	void ParseVersion(std::vector<uint8_t>::iterator& Start);

	void SerializeVersion(std::vector<uint8_t>::iterator& Start, std::vector<uint8_t>& Input) const;

	void ParseLocktime(std::vector<uint8_t>::iterator& Start);

	void SerializeLocktime(std::vector<uint8_t>::iterator& Start, std::vector<uint8_t>& Input) const;

	std::vector<TxInType>& GetInTxs(){
		return InputTxs;
	}

	void ClearInTxs() {
		InputTxs.clear();
	}

	void SetTxIns(const std::vector<TxInType>& NewInputTxs) {
		InputTxs = NewInputTxs;
	}

	void AddTxIns(const TxInType& NewInputTx) {
		InputTxs.push_back(NewInputTx);
	}

	void SetTxIns(std::vector<TxInType>&& NewInputTxs) {
		InputTxs = std::move(NewInputTxs);
	}

	void AddTxIns(TxInType&& NewInputTx) {
		InputTxs.push_back(std::move(NewInputTx));
	}

	std::vector<TxOutType>& GetOutTxs()  {
		return OutputTxs;
	}
	
	void ClearOutTxs() {
		OutputTxs.clear();
	}

	void SetTxOuts(const std::vector<TxOutType>& NewOutputTx) {
		OutputTxs = NewOutputTx;
	}

	void AddTxIns(const TxOutType& NewOutputTx) {
		OutputTxs.push_back(NewOutputTx);
	}

	void SetTxOuts(std::vector<TxOutType>&& NewOutputTxs) {
		OutputTxs = std::move(NewOutputTxs);
	}

	void AddTxIns(TxOutType&& NewOutputTx) {
		OutputTxs.push_back(std::move(NewOutputTx));
	}


	VersionType GetVersion() const{
		return Version;
	}

	void SetVersion(VersionType NewVersion){
		 Version = NewVersion;
	}

	LocktimeType GetLockTime() const {
		return Locktime;
	}

	void SetLockTime(LocktimeType NewLocktime) {
		Locktime = NewLocktime;
	}

	bool IsTestnet() const{
		return Testnet;
	}

	void SetTestnet(bool NewTestnet) {
		Testnet = NewTestnet;
	}

	int64_t GetOutputSum() const;

	int64_t GetInputSum() const;

	int64_t GetTotalFee() const {
		return GetInputSum() - GetOutputSum();
	}

	std::vector<uint8_t> GetTransactionHash(uint64_t Index);

	bool IsValid();

private:

	VersionType Version;
	std::vector<TxInType> InputTxs;
	std::vector<TxOutType> OutputTxs;
	LocktimeType Locktime;
	TestnetType Testnet;

};


using json = nlohmann::json;
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

class TxInfoFetcher {
private:
	static nlohmann::json_abi_v3_11_3::json FetchTx(const std::string& TxID, bool IsTestnet = true);

public:
	static int64_t FetchInput(const std::string& TxID, bool IsTestnet = true);

	static std::string FetchScriptPubKey(const std::string& TxID, uint64_t TxIndex, bool IsTestnet = true);
};
