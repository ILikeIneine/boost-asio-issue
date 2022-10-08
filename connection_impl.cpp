#include "connection_impl.hpp"

#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

#ifdef SSL_ENABLE
#include <boost/asio/ssl.hpp>
#endif

#include "ServiceHandler.hpp"
#include "../network_message_handler.h"

using namespace std::chrono_literals;
connection_impl::connection_impl(net::io_context& ioc, std::weak_ptr<ServiceHandler> sh) 
    : ioc_(ioc),
      sh_{ std::move(sh) },
      resolver_{ net::make_strand(ioc_) }
{

#ifdef SSL_ENABLE
    beast::error_code ec;
    ctx_.add_verify_path(CERTIFICATE_PATH, ec);
    if (ec) LOG_ERROR("\n\n\n[ERROR] >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"
                        "load {} failed {}\n <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n", CERTIFICATE_PATH ,ec.message());
    ctx_.load_verify_file(CERTIFICATE_PATH CERTIFICATE_NAME, ec);
    if (ec) LOG_ERROR("\n\n\n[ERROR] >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"
                        "load {} failed {}\n <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n", CERTIFICATE_PATH ,ec.message());
    else { LOG_INFO("load certificate successfully"); }
#endif

    config_init();
    reset_timer();

    auto local_ep = net::ip::tcp::endpoint(net::ip::address_v4::any(), 0);

#ifdef SSL_ENABLE
    ws_ = std::make_unique<stream> (net::make_strand(ioc_), ctx_);
#else
    ws_ = std::make_unique<stream> (net::make_strand(ioc_));
#endif
    beast::get_lowest_layer(*ws_).open(local_ep.protocol());
    // gives ws_ a local_endpoint
    beast::get_lowest_layer(*ws_).bind(local_ep);

    }

connection_impl::~connection_impl()
{
    LOG_INFO("net thread gg");
}

void
connection_impl::config_init()
{
    LOG_INFO("connection config init");
    const auto sh = sh_.lock();
    const auto netstat = sh->GetNetstat();

    remote_info_.host_   = netstat.host;
    remote_info_.port_   = netstat.port;
    remote_info_.subUrl_ = netstat.url;
}

//auto
//connection_impl::get_executor() -> net::executor
//{
//    if (ws_) return ws_->get_executor();
//}

//auto
//connection_impl::local_endpoint() -> net::ip::tcp::endpoint
//{
//    if (ws_) return  beast::get_lowest_layer(*ws_).local_endpoint();
//}


void
connection_impl::run()
{
    LOG_INFO("run start");
    net::dispatch(ws_->get_executor(), [self = shared_from_this()]
        {
            self->handle_run();
        });
}


void
connection_impl::try_reconnect()
{
    LOG_INFO("\n[info] session has been disconnected, trying to reconnect...\n\t[wss://{0}:{1}{2}]", 
        remote_info_.host_, 
        remote_info_.port_, 
        remote_info_.subUrl_);

    config_init();
    const auto sh = sh_.lock();
    if (sh->IsExit()) {
        LOG_INFO("Try Reconnect exit");
        return;
    }

    sh->DisConnect();
    if (ws_->is_open())
    {
        ws_->close(websocket::close_code::normal);
    }

    // here to re-emplace websocket stream for another connection
    const auto& executor = ws_->get_executor();
    ws_.reset();

    // Exponential backoff to avoid peaking connections
    const auto this_step = curr_span();
    LOG_INFO("[info] next trial will start after: {0}ms", this_step );
    std::this_thread::sleep_for(std::chrono::milliseconds(this_step));

    handle_run();
}

void
connection_impl::handle_run()
{
    ws_->binary(true);

    const auto remote_ep = net::ip::tcp::endpoint{
        net::ip::make_address(remote_info_.host_), remote_info_.port_ };

    LOG_INFO("[info] async_connecting");
    beast::get_lowest_layer(*ws_).async_connect(remote_ep,
        net::bind_executor(ws_->get_executor(), [self = shared_from_this()](error_code ec)
    {
        if (ec) LOG_ERROR("connect error: {}", ec.message());
        self->handle_connect(ec);
    }));

}

void
connection_impl::handle_connect(error_code ec)
{
     if (ec)
    {
        LOG_ERROR("[error] connect, {0}", ec.message());
        //self->try_reconnect();
        return;
    }
    initiate_handshake();
}



void
connection_impl::initiate_handshake()
{
    // still tcp stream
    //beast::get_lowest_layer(*ws_).expires_after(30s);

    LOG_INFO("\n[info] Session Connection Established...");
    const auto sh = sh_.lock();

    ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
    ws_->set_option(websocket::stream_base::decorator(
        [](websocket::request_type& req)->void
        {
            req.set(http::field::user_agent, std::string(BOOST_BEAST_VERSION_STRING) +
                "BoleanGuard Client Websocket");
        }));

#ifdef SSL_ENABLE
    initial_ssl_handshake();
#else
    init_tcp_handshake();
#endif
}

#ifdef SSL_ENABLE
void connection_impl::initiate_ssl_handshake()
{

    const auto remote_host = remote_info_.host_ + std::to_string(remote_info_.port_);
    // Set SNI Hostname (many hosts need this to handshake successfully)
    if (!SSL_set_tlsext_host_name( ws_->next_layer().native_handle(), remote_host.c_str()))
    {
        beast::error_code ec = beast::error_code(static_cast<int>(::ERR_get_error()),
            net::error::get_ssl_category());
        LOG_ERROR("\n[error] connect: {}", ec.message());
    }

    ws_->next_layer().async_handshake(net::ssl::stream_base::client,
        [&](const beast::error_code& ec)
    {
        if (ec)
        {
            LOG_ERROR("\n[error] ssl_handshake: {}", ec.message());
            //try_reconnect();
            return;
        }
        handle_ssl_handshake();
    });

}


void
connection_impl::handle_ssl_handshake(error_code ec)
{
    // Turn off the timeout on tcp stream
    // websocket has its own timeout system
    //beast::get_lowest_layer(*ws_).expires_never();
    init_tcp_handshake();
}
#endif

void
connection_impl::init_tcp_handshake()
{
    LOG_INFO("[info] SSL handshake successfully finished!");

    const auto remote_host = remote_info_.host_ + std::to_string(remote_info_.port_);
    ws_->async_handshake(remote_host, remote_info_.subUrl_,
        [self = shared_from_this()](beast::error_code ec)
    {
        self->handle_handshake(ec);
    });

}


void
connection_impl::handle_handshake(error_code ec)
{
    if (ec)
    {
        //upgrade_declined
        LOG_ERROR("[error]: websocket handshake fail, code{}, {}", ec.value(), ec.message());
        return;
    }
    LOG_INFO("[info] Handshake Finished...");

    // change corresponding status
    const auto sh = sh_.lock();
    sh->Connect();

    state_ = chatting;
    init_session();
}

void
connection_impl::stop()
{

    net::dispatch(net::bind_executor(ws_->get_executor(), [self = shared_from_this()]
    {
        self->handle_stop();
    }));


    ws_.reset();
    //beast::get_lowest_layer(*ws_).close();
    //if (writing_thread_.joinable())
    //{
    //    writing_thread_.join();
    //}
    //LOG_INFO("WriteThread exit");

    //if (read_thread_.joinable())
    //{
    //    read_thread_.join();
    //}
    //LOG_INFO("ReadThread exit");

    //LOG_INFO("NetThread exit");
    //ws_.reset();
}

void
connection_impl::handle_stop()
{
    ec_ = net::error::operation_aborted;
    if(state_ == chatting)
    {
        ws_->async_close(websocket::close_code::going_away, [self = shared_from_this()](error_code ec)
        {
            LOG_INFO("closed");
        });
    }
    else
    {
        beast::get_lowest_layer(*ws_).cancel();
        LOG_INFO("closed");
    }
    ws_.reset();
}



void
connection_impl::init_session()
{
    LOG_INFO("[info] On HeartBeating ...");
    reset_timer();
    const auto sh = sh_.lock();
    if(sh->IsAuthorized())
        sh->SendVerify();


    initiate_rx();
    may_be_send_next();

    //if (!writing_thread_.joinable()) {
    //    writing_thread_ = std::thread( [self=shared_from_this()] {
    //        self->sync_write();
    //    });
    //}

    //if (!read_thread_.joinable()) {
    //    read_thread_ = std::thread( [self = shared_from_this()] {
    //        self->sync_read();
    //    });
    //}
}


void
connection_impl::sync_write() const
{
    const auto sh = sh_.lock();

    while (!sh->IsExit())
    {
        try
        {
            LOG_INFO("[info] wait generate message");
            const auto msgStr = sh->SeizeOneSendMessageAsString();
            if (msgStr.empty()) continue;
            ws_->write(net::buffer(msgStr));
        }
        catch (boost::system::system_error const& se)
        {
            LOG_ERROR("[system error]: {0}", se.what());
            return;
        }
        catch (...)
        {
            LOG_ERROR("exception here");
            return;
        }
    }
}

void
connection_impl::sync_read()
{
    const auto sh = sh_.lock();

    while (!sh->IsExit())
    {
        try
        {
            LOG_INFO("[info] reading");
            buffer_.consume(buffer_.size());
            ws_->read(buffer_);
            const std::string msgIn = beast::buffers_to_string(buffer_.data());
            sh->AddRecvMessage(msgIn);
        }
        catch (boost::system::system_error const& se)
        {
            LOG_ERROR("[system error]: {0}", se.what());
            return;
        }
        catch (...)
        {
            LOG_ERROR("exception here");
            return;
        }
    }
}


void
connection_impl::initiate_rx()
{
    LOG_INFO("[info] Async read");
    const auto sh = sh_.lock();
    if (sh->IsExit()) {
        LOG_INFO("Async Read exit");
        return;
    }

    ws_->async_read(buffer_,
        [self = shared_from_this()](beast::error_code ec, std::size_t bytes_transferred)
        ->void
    {
        self->handle_rx(ec, bytes_transferred);
    });

}

void
connection_impl::handle_rx(error_code ec, size_t bytes_transferred)
{
    if (ec) {
        LOG_ERROR("[error]: read, {0}", ec.message());
        return;   // !WARINING! same reason as above
    }

    LOG_INFO("[info] read bytes: {}", bytes_transferred);
    const std::string msgIn = beast::buffers_to_string(buffer_.data());

    const auto sh = sh_.lock();
    sh->AddRecvMessage(msgIn);

    buffer_.consume(msgIn.size());
    initiate_rx();
}

void
connection_impl::may_be_send_next()
{
    const auto sh = sh_.lock();

    while (!sh->IsExit())
    {
    if (sending_state_ == sending)
            continue;
    LOG_INFO("[info] wait generate message");
    const std::string msg_str = sh->SeizeOneSendMessageAsStringNoBlock();
    send(msg_str);
    }
}

void
connection_impl::send(std::string msg)
{
    if (msg.empty()) 
        return;

    net::dispatch(
        net::bind_executor(ws_->get_executor(), [self = shared_from_this(), message = std::move(msg)]
        {
            self->initiate_tx(message);
        }));
}

void
connection_impl::initiate_tx(const std::string& msg)
{
    assert(sending_state_ == send_idle);
    if(msg.empty())
    {
        may_be_send_next();
        return;
    }
    
    sending_state_ = sending;
    ws_->async_write(net::buffer(msg),
        [self = shared_from_this()](const beast::error_code& ec, size_t bytes_transferred)
    {
        LOG_INFO("[info]: write transferred bytes: {}", bytes_transferred);
        self->handle_tx(ec);
    });
}

void
connection_impl::handle_tx(error_code ec)
{
    assert(sending_state_ == sending);

    if (ec) {
        LOG_ERROR("[error]: write, {}", ec.message());
        return;
    }
    sending_state_ = send_idle;
    //may_be_send_next();
}

int
connection_impl::curr_span()
{
    return ss_.current_span();
}

void
connection_impl::reset_timer()
{
    ss_.reset();
}
