#pragma once
#include <memory>
#include <string>
#include <thread>

#include "websocket_config.hpp"


//#define SSL_ENABLE

// Detection 
//template<class T, class = void>
//struct is_valid_controller : std::false_type {};
//
//template<class T>
//struct is_valid_controller <T, std::void_t<
//    decltype(std::declval<T>().SeizeOneSendMessage()),
//    decltype(std::declval<T>().AddRecvMessage(std::declval<MessagePtr&>())) >
//> : std::true_type {};
//
//template<class T>
//constexpr bool is_valid_controller_v = is_valid_controller<T>::value;
/********************************************************************/



class connection_impl : public std::enable_shared_from_this<connection_impl>
{
    friend class ServiceHandler;
    using transport = net::ip::tcp::socket;
#ifdef SSL_ENABLE
    using stream = websocket::stream < beast::ssl_stream< transport >>;
#else
    using stream = websocket::stream < transport >;
#endif

public:
    explicit  connection_impl(net::io_context& ioc,  std::weak_ptr<ServiceHandler> sh);
    ~connection_impl();
    void config_init();

    //auto local_endpoint()->net::ip::tcp::endpoint;
    //auto get_executor()->net::executor;

    void run();
    void handle_run();

    void stop();
    void handle_stop(); 

    void handle_connect(error_code ec);
    void initiate_handshake() ;

#ifdef SSL_ENABLE
    void initiate_ssl_handshake();
    void handle_ssl_handshake(error_code ec);
#endif

    void init_tcp_handshake();
    void handle_handshake(error_code ec);

    void init_session();
    void try_reconnect();

private:

    void sync_write() const;
    void sync_read();

    void initiate_rx();
    void handle_rx(error_code ec, size_t);

    void send(std::string msg);
    void may_be_send_next();

    void initiate_tx(const std::string& msg);
    void handle_tx(error_code ec);



    //------ Back-Off Algo --------
    int curr_span();
    void reset_timer();

    // make ws_ dynamically/lazy initializable, otherwise stream won't be recreate
    // cxx17 `std::optional` will of better use cause in this case we only need the
    // resettability here we use `std::unique_ptr` for substitution.
    // more details please move to https://github.com/boostorg/beast/issues/2409
#ifdef SSL_ENABLE
    net::ssl::context ctx_{ net::ssl::context::tlsv12_client };
#endif
    std::unique_ptr<stream> ws_;

    net::io_context& ioc_;

    // service handler's life-time is guarenteen longer than connection
    std::weak_ptr<ServiceHandler> sh_;

    beast::flat_buffer buffer_;
    tcp::resolver resolver_;
    error_code ec_;


    std::thread writing_thread_;
    std::thread read_thread_;

    enum
    {
        handshaking,
        chatting
    } state_ = handshaking;

    enum
    {
        send_idle,
        sending
    } sending_state_ = send_idle;

    
    struct StepSetter
    {
        void reset() {
            std::srand(static_cast<unsigned int>(std::time(nullptr)));
            span_ = 1;
        }
        int current_span() {
            // backoff = min(((2 ^ n) + random_number_milliseconds), maximum_backoff)
            const auto exp = std::min(++span_, 16);
            auto this_step = (1 << std::min(exp, 16)) + rand() % 10;
            if (this_step > 64'000)
                this_step = 64'000;
            return this_step;
        }

        int span_ = 1;    // meantime regarded as attemps' times   
    } ss_;

    struct remote_info
    {
        std::string host_;
        std::string subUrl_;
        unsigned short port_;
    } remote_info_;

};