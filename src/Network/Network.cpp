// Network.cpp
#include <coroutine>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include "Network.h"
using boost::asio::awaitable;
using boost::asio::use_awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::redirect_error;

const std::vector<uint8_t> GetDataMessage::command{'g', 'e', 't', 'd', 'a', 't', 'a', '\0', '\0', '\0', '\0', '\0'};
const std::vector<uint8_t> FilterLoadMessage::command{'f', 'i', 'l', 't', 'e', 'r', 'l', 'o', 'a', 'd', '\0', '\0'};
const std::vector<uint8_t> MerkleBlockMessage::command{'m', 'e', 'r', 'k', 'l', 'e', 'b', 'l', 'o', 'c', 'k', '\0'};
const std::vector<uint8_t> PongMessage::command = {'p', 'o', 'n', 'g', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0'};
const std::vector<uint8_t> PingMessage::command = {'p', 'i', 'n', 'g', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0'};
const std::vector<uint8_t> HeadersMessage::command{'h', 'e', 'a', 'd', 'e', 'r', 's', '\0', '\0', '\0', '\0', '\0'};
const std::vector<uint8_t> VerAckMessage::command{'v', 'e', 'r', 'a', 'c', 'k', '\0', '\0', '\0', '\0', '\0', '\0'};
const std::vector<uint8_t> VersionMessage::command{'v', 'e', 'r', 's', 'i', 'o', 'n', '\0', '\0', '\0', '\0', '\0'};
const std::vector<uint8_t> GetHeadersMessage::command{'g', 'e', 't', 'h', 'e', 'a', 'd', 'e', 'r', 's', '\0', '\0'};


void VersionMessage::parse(std::vector<uint8_t>::const_iterator &&start) {  
    // The bytes in "start" are expected to be in little endian.
    // The iterator is advanced after each read.

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), version);
    
    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), services);

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), timestamp);
    
    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), receiver_services);
    
    std::copy(start, start + receiver_ip.size(), receiver_ip.begin());
    start += receiver_ip.size();
    
    read_int_from_big_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), receiver_port);
    
    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), sender_services);
    
    std::copy(start, start + sender_ip.size(), sender_ip.begin());
    start += sender_ip.size();
    
    read_int_from_big_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), sender_port);

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), nonce);
    
    uint64_t user_agent_len = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start));

    user_agent.insert(user_agent.begin(), start, start + user_agent_len);
    start += user_agent_len;

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), latest_block);
    
    if (version >= 70001) {
        uint8_t relay_flag;
        read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), relay_flag);
        relay = relay_flag != 0;
    }
}

inline void VersionMessage::serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator) const {
    // The bytes are serialized in little endian. 
    // The iterator is advanced after each write.

    // Make space if necessary.
    if(should_adjust_iterator) {
        adjust_bytes(start, input, get_size());
    }
    write_int_as_little_endian_bytes(version, start, input);
    
    write_int_as_little_endian_bytes(services, start, input);

    write_int_as_little_endian_bytes(timestamp, start, input);

    write_int_as_little_endian_bytes(receiver_services, start, input);
    
    start = std::copy(receiver_ip.begin(), receiver_ip.end(), start);
    
    write_int_as_big_endian_bytes(receiver_port, start, input);

    write_int_as_little_endian_bytes(sender_services, start, input);
    
    start = std::copy(sender_ip.begin(), sender_ip.end(), start);
    
    write_int_as_big_endian_bytes(sender_port, start, input);

    write_int_as_little_endian_bytes(nonce, start, input);

    serialize_varint(user_agent.size(), start, input, false);

    start = std::copy(user_agent.begin(), user_agent.end(), start);

    write_int_as_little_endian_bytes(latest_block, start, input);

    if (version >= 70001) {
        uint8_t relay_flag = relay ? 1 : 0;
        write_int_as_little_endian_bytes(relay_flag, start, input);
    }
}

void VerAckMessage::parse(std::vector<uint8_t>::const_iterator &&start) {
    // The VerAck message has no payload, so this function does nothing.
}

inline void VerAckMessage::serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator) const {
    // The VerAck message has no payload, so this function does nothing.
}

void GetHeadersMessage::parse(std::vector<uint8_t>::const_iterator &&start) {
    // The bytes in "start" are expected to be in little endian.
    // The iterator is advanced after each read.

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), version);

    hash_count = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start));

    std::copy(start, start + start_block.size(), start_block.begin());
    start += start_block.size();

    std::copy(start, start + end_block.size(), end_block.begin());
    start += end_block.size();
}

inline void GetHeadersMessage::serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator) const {
    // The bytes are serialized in little endian. 
    // The iterator is advanced after each write.

    // Make space if necessary.
    if(should_adjust_iterator) {
        adjust_bytes(start, input, get_size());
    }
    write_int_as_little_endian_bytes(version, start, input);
    
    serialize_varint(hash_count, start, input, false);

    start = std::copy(start_block.begin(), start_block.end(), start);

    start = std::copy(end_block.begin(), end_block.end(), start);
}

void HeadersMessage::parse(std::vector<uint8_t>::const_iterator &&start) {
    // The bytes in "start" are expected to be in little endian.
    // The iterator is advanced after each read.

    uint64_t block_count = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start));

    blocks.resize(block_count);

    for (auto& block : blocks) {
        block.parse(std::forward<std::vector<uint8_t>::const_iterator>(start));;
    }
}

void HeadersMessage::serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator) const {
    // The bytes are serialized in little endian. 
    // The iterator is advanced after each write.

    // Make space if necessary.
    if(should_adjust_iterator) {
        adjust_bytes(start, input, get_size());
    }

    serialize_varint(blocks.size(), start, input, false);
    
    for (const auto& block : blocks) {
        block.serialize(start, input, false); // The bytes space has already been adjusted.
    }
}


void MerkleBlockMessage::parse(std::vector<uint8_t>::const_iterator &&start) {
    // The bytes in "start" are expected to be in little endian.
    // The iterator is advanced after each read.

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), version);

    std::copy(start, start + prev_block.size(), prev_block.begin());
    start += prev_block.size();

    std::copy(start, start + merkle_root.size(), merkle_root.begin());
    start += merkle_root.size();

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), timestamp);

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), bits);

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), nonce);

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), total_transactions);

    uint64_t hash_count = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start));

    hashes.resize(hash_count);

    for (uint32_t counter = 0; counter < hash_count; ++counter) {
        std::copy(start, start + hashes[counter].size(), hashes[counter].begin());
        start += hashes[counter].size();
    }

    uint64_t flag_size = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start));

    flag_bits.resize(flag_size);
    std::copy(start, start + flag_size, flag_bits.begin());
    start += flag_size;
}

inline void MerkleBlockMessage::serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator) const {
    // The bytes are serialized in little endian. 
    // The iterator is advanced after each write.

    // Make space if necessary.
    if(should_adjust_iterator) {
        adjust_bytes(start, input, get_size());
    }

    write_int_as_little_endian_bytes(version, start, input);

    start = std::copy(prev_block.begin(), prev_block.end(), start);

    start = std::copy(merkle_root.begin(), merkle_root.end(), start);

    write_int_as_little_endian_bytes(timestamp, start, input);

    write_int_as_little_endian_bytes(bits, start, input);

    write_int_as_little_endian_bytes(nonce, start, input);

    write_int_as_little_endian_bytes(total_transactions, start, input);

    serialize_varint(hashes.size(), start, input, false);

    for (const auto& hash : hashes) {
        start = std::copy(hash.begin(), hash.end(), start);
    }

    serialize_varint(flag_bits.size(), start, input, false);

    start = std::copy(flag_bits.begin(), flag_bits.end(), start);
}

void FilterLoadMessage::parse(std::vector<uint8_t>::const_iterator &&start){
    // The bytes in "start" are expected to be in little endian.
    // The iterator is advanced after each read.

    uint64_t bit_field_size = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start));
    bit_field.resize(bit_field_size);

    std::copy(start, start + bit_field_size, bit_field.begin());
    start += bit_field_size;

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), hash_count);

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), tweak);

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), matched_item_flag);
}


inline void FilterLoadMessage::serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator) const {
    // The bytes are serialized in little endian. 
    // The iterator is advanced after each write.

    // Make space if necessary.
    if(should_adjust_iterator) {
        adjust_bytes(start, input, get_size());
    }

    serialize_varint(bit_field.size(), start, input, false);

    start = std::copy(bit_field.begin(), bit_field.end(), start);

    write_int_as_little_endian_bytes(hash_count, start, input);

    write_int_as_little_endian_bytes(tweak, start, input);

    write_int_as_little_endian_bytes(matched_item_flag, start, input);
}

void GetDataMessage::parse(std::vector<uint8_t>::const_iterator &&start) {
    // The bytes in "start" are expected to be in little endian.
    // The iterator is advanced after each read.

    item_count = parse_varint(std::forward<std::vector<uint8_t>::const_iterator>(start));

    items.resize(item_count);
    for (uint64_t counter = 0; counter < item_count; ++counter) {
        read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), items[counter].first);

        std::copy(start, start + items[counter].second.size(), items[counter].second.begin());
        start += items[counter].second.size();
    }
}

inline void GetDataMessage::serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator) const {
    // The bytes are serialized in little endian. 
    // The iterator is advanced after each write.

    // Make space if necessary.
    if(should_adjust_iterator) {
        adjust_bytes(start, input, get_size());
    }

    serialize_varint(items.size(), start, input, false);

    for (const auto& item : items) {
        write_int_as_little_endian_bytes(item.first, start, input);
        start = std::copy(item.second.begin(), item.second.end(), start);
    }
};

outcome::result<void, ParsingError> NetworkEnvelope::parse(std::vector<uint8_t>::const_iterator &&start) {
    // The bytes in "start" are expected to be in little endian.
    // The iterator is advanced after each read.

    read_int_from_big_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), magic);
    
    std::vector<uint8_t> command(start, start + COMMAND_LENGTH);
    start += COMMAND_LENGTH;
    
    uint32_t payload_length;
    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), payload_length);
    
    std::vector<uint8_t> checksum(start, start + CHECKSUM_LENGTH);
    start += CHECKSUM_LENGTH;
    
    if (command == VersionMessage::command) {
        message = std::make_unique<VersionMessage>();
    } 
    else if (command == VerAckMessage::command) {
        message = std::make_unique<VerAckMessage>();
    }
    else if (command == GetHeadersMessage::command) {
        message = std::make_unique<GetHeadersMessage>();
    }
    else if (command == HeadersMessage::command) {
        message = std::make_unique<HeadersMessage>();
    }
    else {
        return outcome::failure(ParsingError(ParsingError::Type::INVALID_COMMAND));
    }
    
    std::vector<uint8_t> payload(start, start + payload_length);

    std::vector<uint8_t> hash = get_hash_256(payload);
    std::vector<uint8_t> expected_checksum(hash.begin(), hash.begin() + CHECKSUM_LENGTH);

    if(expected_checksum != checksum) {
        return outcome::failure(ParsingError(ParsingError::Type::INVALID_CHECKSUM));
    }

    // parse payload using message-specific parser
    message->parse(std::forward<std::vector<uint8_t>::const_iterator>(start));

    return outcome::success();
}

outcome::result<void, SerializingError> NetworkEnvelope::serialize(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator) const {
    // The bytes are serialized in little endian. 
    // The iterator is advanced after each write.

    if(should_adjust_iterator){
        adjust_bytes(start, input, get_size());
    }

    write_int_as_big_endian_bytes(magic, start, input);

    if(!message){
        return outcome::failure(SerializingError(SerializingError::Type::INVALID_DATA));
    }
    
    const auto& cmd = message->get_command();
    start = std::copy(cmd.begin(), cmd.end(), start);
    
    std::vector<uint8_t> payload;
    std::vector<uint8_t>::iterator payload_it = payload.begin();
    message->serialize(payload_it, payload);
    
    uint32_t length = payload.size();
    write_int_as_little_endian_bytes(length, start, input);
    
    auto hash = DigestStream<HASH256_tag>::digest(payload);
    start = std::copy(hash.begin(), hash.begin() + CHECKSUM_LENGTH, start);
    
    start = std::copy(payload.begin(), payload.end(), start);

    return outcome::success();
}

// Start the communication and send out a handshake.
awaitable<boost::system::error_code> NetworkNode::start_send_handshake(){

    // Connect.
    auto connection_result = co_await connect();

    if (connection_result) {
        co_return connection_result; 
    }


    // Send the handshake.
    auto handshake_result = co_await send_handshake();
    if (handshake_result) {
        socket.close();
        co_return handshake_result; 
    }

    // Start a different sub process for receiving and sending ping pongs.
    // co_spawn(context, send_ping_receive_pong(), detached);

    // Start a different sub process for checking the timeout timer.
    // co_spawn(context, track_timeout(), detached);

    co_return make_error_code(boost::system::errc::success);
}

// Start the communication and receive a handshake.
awaitable<boost::system::error_code> NetworkNode::start_receive_handshake(uint16_t port){

    // Accept.
    auto connection_result = co_await accept(port);

    if (connection_result) {
        co_return connection_result;
    }

    // Start recieving the handsake.
    auto handshake_result = co_await receive_handshake();
    if (handshake_result) {
        socket.close();
        co_return handshake_result;
    }




    // Start a different sub process for receiving and sending ping pongs.
    // co_spawn(context, send_ping_receive_pong(), detached);

    // Start a different sub process for checking the timeout timer.
    // boost::asio::co_spawn(context, track_timeout(), detached);

    co_return make_error_code(boost::system::errc::success);
}

awaitable<boost::system::error_code> NetworkNode::connect() {

    boost::system::error_code ec;
    
    socket.close();
    socket.open(boost::asio::ip::tcp::v4(), ec);

    if(ec){
        co_return ec;
    }

    ip::tcp::resolver resolver(*context);
    auto endpoints = co_await resolver.async_resolve(host, std::to_string(port), use_awaitable);
    co_await async_connect(socket, endpoints, redirect_error(use_awaitable, ec));

    if(ec) {
        co_return ec;
    }

    co_return make_error_code(boost::system::errc::success);

}

awaitable<boost::system::error_code> NetworkNode::accept(uint16_t port){
    
    boost::system::error_code ec;
    
    socket.cancel();
    socket.open(boost::asio::ip::tcp::v4(), ec);

    if(ec){
        co_return ec;
    }

    acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port), ec);

    if(ec){
        co_return ec;
    }

    socket = co_await acceptor.async_accept(redirect_error(use_awaitable, ec));
    co_return ec;
}

awaitable<boost::system::error_code> NetworkNode::send_handshake() {
    
    // Send version.
    std::unique_ptr<Message> temp_version_msg = std::make_unique<VersionMessage>(version_msg);

    auto send_version_result = co_await send(std::move(temp_version_msg));

    if(send_version_result){
        socket.close();
        co_return send_version_result;
    }


    // Receive version.
    auto version = co_await receive(Command::VERSION);

    if (!version) {
        socket.close();
        co_return version.error();
    }

    // Receive verack.
    auto verack = co_await receive(Command::VERACK);

    if (!verack) {
        socket.close();
        co_return verack.error();
    }

    // Send verack.
    std::unique_ptr<Message> verack_msg = std::make_unique<VerAckMessage>();
    auto send_verack_result = co_await send(std::move(verack_msg));

    if(send_verack_result){
        socket.close();
        co_return send_verack_result;
    }

    auto version_msg = dynamic_cast<VersionMessage*>(version.value().get());


    if (!version_msg) {
        socket.close();
        co_return NetworkError::INVALID_MESSAGE;
    }

    this->version_msg.set_minimum(*version_msg);

    co_return make_error_code(boost::system::errc::success);
}

awaitable<boost::system::error_code> NetworkNode::receive_handshake() {

    // Receive version.
    auto version = co_await receive(Command::VERSION);

    if (!version) {
        socket.close();
        co_return version.error();
    }

    // Send version.
    std::unique_ptr<Message> temp_version_msg = std::make_unique<VersionMessage>(version_msg);
    auto sent_version_result = co_await send(std::move(temp_version_msg));

    if (sent_version_result) {
        socket.close();
        co_return sent_version_result;
    }

    // Send our verack.
    std::unique_ptr<Message> verack_msg = std::make_unique<VerAckMessage>();
    auto send_verack_result = co_await send(std::move(verack_msg));

    if (send_verack_result) {
        socket.close();
        co_return send_verack_result;
    }

    // Receive verack.
    auto verack = co_await receive(Command::VERACK);

    if (!verack) {
        socket.close();
        co_return verack.error();
    }

    auto version_msg = dynamic_cast<VersionMessage*>(version.value().get());

    if (!version_msg) {
        socket.close();
        co_return NetworkError::INVALID_MESSAGE;
    }

    this->version_msg.set_minimum(*version_msg);


    co_return make_error_code(boost::system::errc::success);
}

awaitable<void> NetworkNode::send_ping_receive_pong() {

    while(socket.is_open()){  // The loop is non-blocking, it resumes after the asynchronous tasks have been completed.

        // Set when the next ping would take place.
        ping_timer.expires_after(std::chrono::minutes(BITCOIN_PING_REFRESH));

        co_await ping_timer.async_wait(use_awaitable);

        std::unique_ptr<Message> ping_msg = std::make_unique<PingMessage>();

        // Send the ping message.
        auto send_pong_result = co_await send(std::move(ping_msg));

        if (send_pong_result) {
            std::cerr << "Failed to send Ping: " << send_pong_result.message() << std::endl;
            socket.close();
            co_return; // We discard the error.
        }

        // Wait for a pong message.
        auto receive_pong_result = co_await receive(Command::PONG);

        if (!receive_pong_result) {
            std::cerr << "Failed to receive Pong: " << receive_pong_result.error().message() << std::endl;
            socket.close();
            co_return; // We discard the error.
        }

        auto pong_msg = dynamic_cast<PongMessage*>(receive_pong_result.value().get());

        if (pong_msg) {
            std::cout << "Received Pong with nonce: " << pong_msg->get_nonce() << std::endl;
        } 
        else {
            std::cerr << "Failed to process Pong." << std::endl;
        }
    }
}

awaitable<void> NetworkNode::track_timeout() {

    while (socket.is_open()) {

        // Sets time limit for when all operations are stopped.
        ping_deadline_timer.expires_after(std::chrono::minutes(BITCOIN_INACTIVITY_TIMEOUT));

        boost::system::error_code ec;
        co_await ping_deadline_timer.async_wait(redirect_error(use_awaitable, ec));

        if (ec) {
            std::cerr << "Inactivity timeout. Closing connection.\n";
            socket.close();
            co_return;
        }
        // If timer was cancelled, loop continues and resets the 20mins timer.
    }
}

awaitable<boost::system::error_code> NetworkNode::send(std::unique_ptr<Message>&& msg) {

    boost::system::error_code ec;

    // Serialize the message.
    std::vector<uint8_t> buffer;
    std::vector<uint8_t>::iterator it = buffer.begin();

    NetworkEnvelope envelope(std::move(msg));

    auto result = envelope.serialize(it, buffer);
    if(!result){
        throw result.error();
    }

    // Send it.
    co_await async_write(socket, boost::asio::buffer(buffer), redirect_error(use_awaitable, ec));

    if (ec) {
        co_return ec;
    }

    ping_deadline_timer.cancel(); // Reset the inactivity timer.

    co_return make_error_code(boost::system::errc::success);
;
}

awaitable<outcome::result<std::unique_ptr<Message>, boost::system::error_code>> NetworkNode::receive(Command expected_command) {
    
    boost::system::error_code ec;

    std::vector<uint8_t> header(HEADER_SIZE, 0);

    co_await async_read(socket, buffer(header), transfer_exactly(HEADER_SIZE), redirect_error(use_awaitable, ec));

    if(ec){
        co_return outcome::failure(ec);
    }

    uint32_t payload_size = get_payload_size(header);


    if (payload_size > MAX_MESSAGE_SIZE) {
        co_return outcome::failure(boost::asio::error::message_size);
    }
    
    std::vector<uint8_t> body(payload_size);
    co_await async_read(socket, buffer(body), transfer_exactly(payload_size), redirect_error(use_awaitable, ec));
    
    if(ec){
        co_return outcome::failure(ec);
    }

    if (!is_command_type(header, expected_command)) {
        co_return outcome::failure(NetworkError::UNEXPECTED_COMMAND);
    }

    ping_deadline_timer.cancel(); // Reset the inactivity timer.

    co_return parse_message(header, body);
}

bool NetworkNode::is_command_type(const std::vector<uint8_t>& header, Command expected_command){
    const auto& expected_bytes = command_map.at(expected_command);

    std::string command(header.begin() + NETWORK_MAGIC_LENGTH,
        header.begin() + NETWORK_MAGIC_LENGTH + COMMAND_LENGTH);

    return std::equal(
        header.begin() + NETWORK_MAGIC_LENGTH,
        header.begin() + NETWORK_MAGIC_LENGTH + COMMAND_LENGTH,
        expected_bytes.begin()
    );
}

uint32_t NetworkNode::get_payload_size(const std::vector<uint8_t>& header) {
    uint32_t payload_size = 0;
    constexpr size_t offset = NETWORK_MAGIC_LENGTH + COMMAND_LENGTH;
    
    if (header.size() < offset + sizeof(payload_size)) {
        throw ParsingError(ParsingError::Type::INVALID_HEADER);
    }

    read_int_from_little_endian_bytes(header.cbegin() + offset, payload_size);

    return payload_size;
}
    
outcome::result<std::unique_ptr<Message>, boost::system::error_code> NetworkNode::parse_message(const std::vector<uint8_t>& header, const std::vector<uint8_t>& body) {
    
    // Extract command from header.
    std::vector<uint8_t> command(header.begin() + NETWORK_MAGIC_LENGTH,
                                    header.begin() + NETWORK_MAGIC_LENGTH + COMMAND_LENGTH);

    std::unique_ptr<Message> msg;

    // Match command and create message.
    if (command == VersionMessage::command) {
        msg = std::make_unique<VersionMessage>();
    } else if (command == VerAckMessage::command) {
        msg = std::make_unique<VerAckMessage>();
    } else if (command == PingMessage::command) {
        msg = std::make_unique<PingMessage>();
    } else if (command == PongMessage::command) {
        msg = std::make_unique<PongMessage>(0);
    } else if (command == GetHeadersMessage::command) {
        msg = std::make_unique<GetHeadersMessage>();
    } else if (command == HeadersMessage::command) {
        msg = std::make_unique<HeadersMessage>();
    } else {
        return outcome::failure(NetworkError::UNKNOWN_COMMAND);
    }

    auto it = body.cbegin();

    msg->parse(std::forward<std::vector<uint8_t>::const_iterator>(it));
    return msg;
}

const std::unordered_map<NetworkNode::Command, std::vector<uint8_t>> NetworkNode::command_map = {
    { Command::VERSION,      {'v','e','r','s','i','o','n','\0','\0','\0','\0','\0'} },
    { Command::VERACK,       {'v','e','r','a','c','k','\0','\0','\0','\0','\0','\0'} },
    { Command::PING,         {'p','i','n','g','\0','\0','\0','\0','\0','\0','\0','\0'} },
    { Command::PONG,         {'p','o','n','g','\0','\0','\0','\0','\0','\0','\0','\0'} },
    { Command::GETHEADERS,   {'g','e','t','h','e','a','d','e','r','s','\0','\0'} },
    { Command::HEADERS,      {'h','e','a','d','e','r','s','\0','\0','\0','\0','\0'} },
    { Command::GETDATA,      {'g','e','t','d','a','t','a','\0','\0','\0','\0','\0'} },
    { Command::MERKLEBLOCK,  {'m','e','r','k','l','e','b','l','o','c','k','\0'} },
    { Command::FILTERLOAD,   {'f','i','l','t','e','r','l','o','a','d','\0','\0'} }
};