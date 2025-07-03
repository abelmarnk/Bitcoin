// Network.hs
#pragma once
#ifndef BOOST_ASIO_HAS_CO_AWAIT
#define BOOST_ASIO_HAS_CO_AWAIT
#endif
#include <ranges>
#include <numeric>
#include <vector>
#include <string>
#include <random>
#include <memory>
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include "../Varint/Varint.h"
#include "../Block/Block.h"
#include <optional>
#include <boost/outcome.hpp>
#include <boost/asio.hpp>
#include <functional>
#include <unordered_map>
#include <coroutine>
#include "../Error/Error.h"
#include "../Serial/Serial.h"

namespace outcome = BOOST_OUTCOME_V2_NAMESPACE;


static constexpr uint8_t BITCOIN_INACTIVITY_TIMEOUT = 1; // Minutes.
static constexpr uint8_t BITCOIN_PING_REFRESH = 2; // Minutes.
static constexpr uint16_t BITCOIN_TESTNET_PORT = 18333;
static constexpr uint16_t BITCOIN_MAINNET_PORT = 8333;
static constexpr uint32_t MAINNET_NETWORK_MAGIC = 0xf9beb4d9;
static constexpr uint32_t TESTNET_NETWORK_MAGIC = 0x0b110907;
static constexpr uint32_t NETWORK_MAGIC_LENGTH = sizeof(MAINNET_NETWORK_MAGIC);
static constexpr size_t COMMAND_LENGTH = 12;
static constexpr size_t PAYLOAD_SIZE_LENGTH = 4;
static constexpr size_t CHECKSUM_LENGTH = 4;
static constexpr size_t HEADER_SIZE = NETWORK_MAGIC_LENGTH + COMMAND_LENGTH + PAYLOAD_SIZE_LENGTH + CHECKSUM_LENGTH;
static constexpr size_t MAX_MESSAGE_SIZE = 1024 * 1024 * 32; // 32MB.


// Messages are what is used to communicate over the Bitcoin network.
class Message{
public:
    virtual ~Message() = default;
    virtual void parse(std::vector<uint8_t>::const_iterator &&start) = 0;
    virtual void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const = 0;
    virtual inline const std::vector<uint8_t>& get_command() const = 0;
    virtual inline uint32_t get_size() const = 0;
};

// The version message is used to establish a consensus on what versions to be used.
// https://en.bitcoin.it/wiki/Protocol_documentation#version
class VersionMessage: public Message {
public:
const static std::vector<uint8_t> command;
    
    VersionMessage(
        uint32_t version = 70015,
        uint64_t services = 0,
        uint64_t timestamp = std::chrono::steady_clock::now().
                                time_since_epoch().count(),
        uint64_t receiver_services = 0,
        std::array<uint8_t, 16> receiver_ip = {},
        uint16_t receiver_port = BITCOIN_TESTNET_PORT,
        uint64_t sender_services = 0,
        std::array<uint8_t, 16> sender_ip = {},
        uint16_t sender_port = BITCOIN_TESTNET_PORT,
        uint64_t nonce = std::mt19937_64(std::random_device()())(),
        std::string user_agent = "",
        uint32_t latest_block_= 0,
        bool relay = false
    ) :
        version(version),
        services(services),
        timestamp(timestamp),
        receiver_services(receiver_services),
        receiver_ip(receiver_ip),
        receiver_port(receiver_port),
        sender_services(sender_services),
        sender_ip(sender_ip),
        sender_port(sender_port),
        nonce(nonce),
        user_agent(std::move(user_agent)),
        latest_block(latest_block),
        relay(relay){

    }

    inline uint32_t get_size() const override{
        return sizeof(version) + sizeof(services) + sizeof(timestamp) + sizeof(receiver_services) + sizeof(receiver_ip) + 
        sizeof(receiver_port) + sizeof(sender_services) + sizeof(sender_ip) + sizeof(sender_port) + sizeof(nonce) + 
        get_varint_byte_size(user_agent.size()) + user_agent.size() + sizeof(latest_block) + (version < 70001 ? 0 : sizeof(relay));
    }

    inline const std::vector<uint8_t>& get_command() const override {
        return command;
    }

    void parse(std::vector<uint8_t>::const_iterator &&start) override;

    void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const override;
    
    // Obtains the overlap between the two versions.
    void set_minimum(const VersionMessage& message){
        version = std::min(message.version, version);
    }
private:

    uint32_t version;
    uint64_t services;
    uint64_t timestamp;
    uint64_t receiver_services;
    std::array<uint8_t, 16> receiver_ip;
    uint64_t receiver_final_services;// This is added to store the services the receiver actually provides, in contrast to "receiver_services"
                                     // which stores services that are expected to be provided.
    uint16_t receiver_port;
    uint64_t sender_services;
    std::array<uint8_t, 16> sender_ip;
    uint16_t sender_port;
    uint64_t nonce;
    std::string user_agent;
    uint32_t latest_block;
    bool relay;

};



// The verack message acknowledges the connection.
// https://en.bitcoin.it/wiki/Protocol_documentation#verack
class VerAckMessage: public Message {
    public:
    static const std::vector<uint8_t> command;
    VerAckMessage() = default;
    inline const std::vector<uint8_t>& get_command() const override {
        return command;
    }
    // The implementation of this function does nothing.
    void parse(std::vector<uint8_t>::const_iterator &&start) override;
    
    // The implementation of this function does nothing.
    void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const override;
    
    inline uint32_t get_size() const override {
        return 0; // The verack message has no payload.
    }
};



// The get headers message is used to obtain a sequence of blocks
// https://en.bitcoin.it/wiki/Protocol_documentation#getheaders
class GetHeadersMessage: public Message {
public:
    static const std::vector<uint8_t> command;
    int32_t version; // Protocol version.
    uint64_t hash_count; // Used for requesting for blocks when we are likely off the main chain.
    std::array<uint8_t, 32> start_block; // Where to start getting blocks from, this is supposed to be an array,
                                         // of hashes which would be used for locating a proper starting point, but we would keep
                                         // it simple by using a single hash which we know to be on the main chain.
    std::array<uint8_t, 32> end_block; // Where to stop getting blocks from, if set to zero the max possible(2000) would be returned.

    GetHeadersMessage(
        int32_t version = 70015,
        uint64_t hash_count = 0,
        std::array<uint8_t, 32> start_block = {},
        std::array<uint8_t, 32> end_block = {}
    ) :
        version(version),
        hash_count(hash_count),
        start_block(std::move(start_block)),
        end_block(std::move(end_block))
    {}

    inline const std::vector<uint8_t>& get_command() const override {
        return command;
    }

    inline uint32_t get_size() const override{
        return sizeof(version) + sizeof(hash_count) + sizeof(start_block) + sizeof(end_block);
    }

    void zero_end_block(){
        for (uint8_t& byte: end_block){
                byte = 0;
        }
    }

    void parse(std::vector<uint8_t>::const_iterator &&start) override;

    void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const override;
};


// This is the response gotten for sending the get headers message.
// https://en.bitcoin.it/wiki/Protocol_documentation#headers
class HeadersMessage: public Message {
public:
    static const std::vector<uint8_t> command;
    std::vector<Block> blocks;

    HeadersMessage(std::vector<Block> blocks_ = {}) : blocks(std::move(blocks_)) {}

    inline const std::vector<uint8_t>& get_command() const override {
        return command;
    }

    inline uint32_t get_size() const override{
        return get_varint_byte_size(blocks.size()) + // Size in bytes required to store the block size as a varint
        std::accumulate( //Size of all the blocks
                blocks.begin(), blocks.end(), 0,
                [](int sum, const Block& block) {
                    return sum + block.get_size();
                }
            );
    }

    void parse(std::vector<uint8_t>::const_iterator &&start) override;

    void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const override;
};


// This message is used for asserting the connection.
// https://en.bitcoin.it/wiki/Protocol_documentation#ping
class PingMessage:public Message{
    
    public:
    const static std::vector<uint8_t> command;

    PingMessage(uint64_t nonce = std::mt19937_64(std::random_device()())()):nonce(nonce){

    }

    inline const std::vector<uint8_t>& get_command()const override{
        return command;
    }

    inline void parse(std::vector<uint8_t>::const_iterator &&start) override {
        // The bytes in "start" are expected to be in little endian.
        // The iterator is advanced after each read.

        read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), nonce);
    }

    inline void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const override{
        // The bytes are serialized in little endian. 
        // The iterator is advanced after each write.

        // Make space if necessary.
        if(should_adjust_iterator) {
            adjust_bytes(start, input, get_size());
        }

        write_int_as_little_endian_bytes(nonce, start, input);
    }

    inline uint32_t get_size() const override{
        return sizeof(nonce);
    }

    void set_nonce(uint64_t nonce_){
        nonce = nonce_;
    }
    
    uint64_t get_nonce() const{
        return nonce;
    }

    private:
    uint64_t nonce;
};


// This message is used for asserting the connection.
// https://en.bitcoin.it/wiki/Protocol_documentation#pong
class PongMessage:public Message{

    public:
    const static std::vector<uint8_t> command;

    PongMessage(uint64_t nonce ):nonce(nonce){

    }

    PongMessage(const PingMessage& ping_message) : nonce(ping_message.get_nonce()) {
        
    }
    
    inline const std::vector<uint8_t>& get_command()const override{
        return command;
    }

    inline void parse(std::vector<uint8_t>::const_iterator &&start) override {
        // The bytes in "start" are expected to be in little endian.
        // The iterator is advanced after each read.

        read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), nonce);
    }

    inline void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const override{
        // The bytes are serialized in little endian. 
        // The iterator is advanced after each write.

        // Make space if necessary.
        if(should_adjust_iterator) {
            adjust_bytes(start, input, get_size());
        }

        write_int_as_little_endian_bytes(nonce, start, input);
    }

    uint64_t get_nonce() const {
        return nonce;
    }
    
    inline uint32_t get_size() const override{
        return 0;
    }

    void set_nonce(uint64_t nonce_){
        nonce = nonce_;
    }

    private:
    uint64_t nonce;
};


// This message is used to get information about a block, that could be used to 
// assert the existence of a transaction in that block.
// https://en.bitcoin.it/wiki/Protocol_documentation#filterload,_filteradd,_filterclear,_merkleblock
class MerkleBlockMessage : public Message {
    public:
    static const std::vector<uint8_t> command;
    
    int32_t version;
    std::array<uint8_t, 32> prev_block;
    std::array<uint8_t, 32> merkle_root;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
    uint32_t total_transactions;
    std::vector<std::array<uint8_t, 32>> hashes;
    std::vector<uint8_t> flag_bits; 

    MerkleBlockMessage() : version(0), timestamp(0), bits(0), nonce(0), total_transactions(0){}

    inline const std::vector<uint8_t>& get_command() const override {
        return command;
    }

    inline uint32_t get_size() const override{
        return sizeof(version) + 
               sizeof(prev_block) + 
               sizeof(merkle_root) + 
               sizeof(timestamp) + 
               sizeof(bits) + 
               sizeof(nonce) + 
               sizeof(total_transactions) + 
               hashes.size() * 32 + // Each hash is 32 bytes.
               flag_bits.size(); // Size of the flag bits.
    }

    void parse(std::vector<uint8_t>::const_iterator &&start) override;

    void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const override;
};


// This message is used to send a request for blocks matching a specifc 
// bloom filter.
// https://developer.bitcoin.org/reference/p2p_networking.html#filterload
// https://en.bitcoin.it/wiki/Protocol_documentation#filterload,_filteradd,_filterclear,_merkleblock
class FilterLoadMessage : public Message {
public:
    static const std::vector<uint8_t> command;

    std::vector<uint8_t> bit_field; // Bit field for the Bloom filter
    uint32_t hash_count;            // Number of hash functions
    uint32_t tweak;                 // Random seed for the Bloom filter
    uint8_t matched_item_flag;      // Flag for matched items

    // Constructor
    FilterLoadMessage() : hash_count(0), tweak(0), matched_item_flag(0) {}

    inline const std::vector<uint8_t>& get_command() const override {
        return command;
    }

    inline uint32_t get_size() const override{
        return sizeof(uint64_t) + // Size of the bit field size
               bit_field.size() + // Size of the bit field
               sizeof(hash_count) + 
               sizeof(tweak) + 
               sizeof(matched_item_flag);
    }


    void parse(std::vector<uint8_t>::const_iterator &&start) override;

    void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const override;
};


// This gets the response of the filter load message.
// https://en.bitcoin.it/wiki/Protocol_documentation#getdata
class GetDataMessage : public Message {
public:
    static const std::vector<uint8_t> command;

    uint64_t item_count;
    std::vector<std::pair<uint32_t, std::array<uint8_t, 32>>> items; // Type and hash pairs

    GetDataMessage() : item_count(0) {}

    inline const std::vector<uint8_t>& get_command() const override {
        return command;
    }

    inline uint32_t get_size() const override{
        return get_varint_byte_size(items.size()) + // Size of the item count
               std::accumulate(items.begin(), items.end(), 0, 
                   [](int sum, const std::pair<uint32_t, std::array<uint8_t, 32>>& item) {
                       return sum + sizeof(item.first) + sizeof(item.second);
                   }); // Size of each item (type and hash)
    }

    void parse(std::vector<uint8_t>::const_iterator &&start) override;
    
    void serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const override;
    
    inline void add_data(uint32_t data_type, const std::array<uint8_t, 32>& data){
        items.push_back(std::make_pair(data_type, data));
    }
};



// This class wraps around a message to be sent.
class NetworkEnvelope {
public:
    
    NetworkEnvelope(std::unique_ptr<Message>&& message, uint32_t magic = TESTNET_NETWORK_MAGIC) : message(std::move(message)), magic(magic) {}

    NetworkEnvelope(uint32_t magic = TESTNET_NETWORK_MAGIC) : message(nullptr), magic(magic) {}
    
    outcome::result<void, ParsingError> parse(std::vector<uint8_t>::const_iterator &&start);

    outcome::result<void, SerializingError> serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator = true) const;

    void set_message(std::unique_ptr<Message>&& message){
        this->message = std::move(message);
    }

    std::optional<std::vector<uint8_t>> get_command(){
        return message.get() == nullptr ? std::nullopt : std::optional<std::vector<uint8_t>>(message->get_command());
    }

    uint32_t get_magic() const {
        return magic;
    }
    void set_magic(uint32_t magic) {
        this->magic = magic;
    }

    inline uint32_t get_size() const{
        return HEADER_SIZE + (message ? message->get_size() : 0);
    }

private:
    uint32_t magic; // The magic is the unique identifier for the network.
    std::unique_ptr<Message> message; // This class(Network Envelope) essentially wraps around this message.
};

using namespace boost::asio;

// This class handles communication over the network.
class NetworkNode {
    public:
    
   enum class Command : uint8_t {
        VERSION,
        VERACK,
        PING,
        PONG,
        GETHEADERS,
        HEADERS,
        GETDATA,
        MERKLEBLOCK,
        FILTERLOAD,
        UNKNOWN
    };

    NetworkNode(std::shared_ptr<io_context> ctx, std::string host = "", uint16_t port = 0)
        : context(ctx), socket(*ctx), host(std::move(host)), port(port),
          ping_timer(*ctx), ping_deadline_timer(*ctx), acceptor(*ctx, boost::asio::ip::tcp::v4()) {}

    NetworkNode(NetworkNode&& node): context(node.context), socket(std::move(node.socket)), host(std::move(node.host)), port(node.port),
          ping_timer(std::move(node.ping_timer)), ping_deadline_timer(std::move(node.ping_deadline_timer)), acceptor(std::move(node.acceptor)){

    }

    NetworkNode& operator=(NetworkNode&& node){
        context = std::move(node.context);
        socket = std::move(node.socket); 
        host = std::move(node.host);
        port = node.port;
        ping_timer = std::move(node.ping_timer);
        ping_deadline_timer = std::move(node.ping_deadline_timer); 
        acceptor = std::move(node.acceptor);

        return *this;
    }


        
    awaitable<boost::system::error_code> start_send_handshake(std::string host, uint16_t port){
        this->host = host;
        this->port = port;
        co_return co_await start_send_handshake();
    }
    
    awaitable<boost::system::error_code> start_send_handshake();

    awaitable<boost::system::error_code> start_receive_handshake(uint16_t port);

    awaitable<boost::system::error_code> connect();

    awaitable<boost::system::error_code> accept(uint16_t port);

    void close(){
        socket.close();
    }

    awaitable<boost::system::error_code> send_handshake();

    awaitable<boost::system::error_code> receive_handshake();

    awaitable<void> send_ping_receive_pong();

    awaitable<void> track_timeout();

    awaitable<boost::system::error_code> send(std::unique_ptr<Message>&& msg);

    awaitable<outcome::result<std::unique_ptr<Message>, boost::system::error_code>> receive(Command expected_command);

    bool is_command_type(const std::vector<uint8_t>& header, Command expected_command);

    uint32_t get_payload_size(const std::vector<uint8_t>& header);

    outcome::result<std::unique_ptr<Message>, boost::system::error_code> parse_message(const std::vector<uint8_t>& header, const std::vector<uint8_t>& body);

    std::shared_ptr<io_context> context;
    ip::tcp::socket socket;
    ip::tcp::acceptor acceptor;
    std::string host;
    uint16_t port;
    VersionMessage version_msg;
    steady_timer ping_timer;
    steady_timer ping_deadline_timer;
    static const std::unordered_map<Command, std::vector<uint8_t>> command_map;
};

