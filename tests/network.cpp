#include <vector>
#include <variant>
#include <iomanip>
#include <iostream>
#include "../src/Transaction/Transaction.h"
#include "../src/Block/Block.h"
#include "../src/Serial/Serial.h"
#include "../src/Network/Network.h"
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include "/home/abel/Documents/-Libraries/catch/catch_amalgamated.hpp"
using namespace boost::asio::experimental::awaitable_operators;

using boost::asio::awaitable;
using boost::asio::use_awaitable;

awaitable<std::optional<NetworkNode>> test_handshake(std::shared_ptr<boost::asio::io_context> context, const std::vector<std::pair<std::string, uint16_t>>& seeds) {
    NetworkNode node(context);
    boost::asio::cancellation_signal timer_cancel_signal;
    boost::asio::cancellation_signal handshake_cancel_signal;
    boost::system::error_code timer_error;
    boost::system::error_code handshake_error;
    std::optional<boost::system::error_code> handshake_result;

    for (const auto& [host, port] : seeds) {
        try {
            std::cout << "Attempting handshake with " << host << ":" << port << " ..." << std::endl;
            
            co_spawn(co_await boost::asio::this_coro::executor, [&]() -> awaitable<void> {

                std::cout << "Reached here." << std::endl;
                
                handshake_result = co_await node.start_send_handshake(host, port);
                timer_cancel_signal.emit(boost::asio::cancellation_type::all);

                co_return;
            },  redirect_error(boost::asio::bind_cancellation_slot(handshake_cancel_signal.slot(), boost::asio::detached), handshake_error));


            boost::asio::steady_timer timer(co_await boost::asio::this_coro::executor);
            timer.expires_after(std::chrono::seconds(15));
            co_await timer.async_wait(redirect_error(boost::asio::bind_cancellation_slot(timer_cancel_signal.slot(), use_awaitable), timer_error));

            handshake_cancel_signal.emit(boost::asio::cancellation_type::all);

            if (!handshake_result) {
                std::cerr << "Handshake with " << host << ":" << port << " timed out." << std::endl;
                continue;
            }

            if (handshake_result.value()) {
                std::cerr << "Handshake failed with " << host << ":" << port << " (" << handshake_result.value().message() << ")" << std::endl;
                continue;
            } 

            std::cout << "Handshake successful with " << host << ":" << port << std::endl;

            co_return node;
        
        } catch (const std::exception& e) {
            std::cerr << "Exception during handshake." << std::endl;
        }
        
        boost::asio::steady_timer timer(co_await boost::asio::this_coro::executor);
        timer.expires_after(std::chrono::seconds(30));
        co_await timer.async_wait(use_awaitable);
    }

    co_return std::nullopt;
}

TEST_CASE("Network", "[handshake]"){

        auto context = std::make_shared<boost::asio::io_context>();
    auto executor = context->get_executor();

    std::vector<std::pair<std::string, uint16_t>> seeds = {
        {"testnet-seed.bitcoin.jonasschnelli.ch", 18333},
        {"seed.tbtc.petertodd.org", 18333},
        {"testnet-seed.bluematt.me", 18333},
        {"seed.testnet.bitcoin.sprovoost.nl", 18333},
    };

    std::optional<bool> result;

    co_spawn(
        executor,
        [context, seeds, &result]() -> awaitable<void> {
            result = (co_await test_handshake(context, seeds)).has_value();
            co_return;
        },
        detached
    );

    context->run();

    REQUIRE(result.has_value());
    REQUIRE(result.value());
}