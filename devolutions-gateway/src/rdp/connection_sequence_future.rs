use crate::rdp::filter::FilterConfig;
use crate::rdp::sequence_future::{
    create_negotiation_request, Finalization, GetStateArgs, McsFuture, McsFutureTransport, McsInitialFuture,
    NegotiationWithClientFuture, NegotiationWithServerFuture, NlaTransport, NlaWithClientFuture, NlaWithServerFuture,
    ParseStateArgs, PostMcs, PostMcsFutureTransport, SendStateArgs, SequenceFuture, StaticChannels,
};
use crate::rdp::RdpIdentity;
use crate::transport::mcs::{McsTransport, SendDataContextTransport};
use crate::transport::rdp::{RdpPdu, RdpTransport};
use crate::transport::x224::{DataTransport, NegotiationWithClientTransport, NegotiationWithServerTransport};
use crate::utils::{self, TargetAddr};
use bytes::BytesMut;
use futures::{ready, SinkExt};
use ironrdp::nego;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsStream};
use tokio_util::codec::{Decoder, Framed};

pub struct ConnectionSequenceFuture {
    state: ConnectionSequenceFutureState,
    client_nla_transport: Option<NlaTransport>,
    tls_proxy_pubkey: Option<Vec<u8>>,
    tls_acceptor: Option<TlsAcceptor>,
    identity: RdpIdentity,
    request: Option<nego::Request>,
    response_protocol: Option<nego::SecurityProtocol>,
    filter_config: Option<FilterConfig>,
    joined_static_channels: Option<StaticChannels>,
    selected_target: Option<TargetAddr>,
}

pub struct RdpProxyConnection {
    pub client: Framed<TlsStream<TcpStream>, RdpTransport>,
    pub server: Framed<TlsStream<TcpStream>, RdpTransport>,
    pub channels: StaticChannels,
    pub selected_target: TargetAddr,
}

impl ConnectionSequenceFuture {
    pub fn new(
        client: TcpStream,
        connection_request: nego::Request,
        tls_proxy_pubkey: Vec<u8>,
        tls_acceptor: TlsAcceptor,
        identity: RdpIdentity,
    ) -> Self {
        Self {
            state: ConnectionSequenceFutureState::NegotiationWithClient(Box::pin(
                Self::create_negotiation_with_client_future(client, connection_request),
            )),
            client_nla_transport: None,
            tls_proxy_pubkey: Some(tls_proxy_pubkey),
            tls_acceptor: Some(tls_acceptor),
            identity,
            request: None,
            response_protocol: None,
            filter_config: None,
            joined_static_channels: None,
            selected_target: None,
        }
    }

    fn create_negotiation_with_client_future(
        client: TcpStream,
        negotiation_request: nego::Request,
    ) -> SequenceFuture<NegotiationWithClientFuture, TcpStream, NegotiationWithClientTransport, nego::Response> {
        SequenceFuture::with_parse_state(
            NegotiationWithClientFuture::new(),
            ParseStateArgs {
                client: Some(NegotiationWithClientTransport.framed(client)),
                server: None,
                pdu: negotiation_request,
                phantom_data: PhantomData,
            },
        )
    }

    fn create_nla_client_future(
        &mut self,
        client: TcpStream,
        client_response_protocol: nego::SecurityProtocol,
    ) -> NlaWithClientFuture {
        NlaWithClientFuture::new(
            client,
            client_response_protocol,
            self.tls_proxy_pubkey
                .take()
                .expect("TLS proxy public key must be set in the constructor"),
            self.identity.clone(),
            self.tls_acceptor
                .take()
                .expect("TLS acceptor must be set in the constructor"),
        )
    }

    fn create_server_negotiation_future(
        &mut self,
        server: TcpStream,
    ) -> io::Result<SequenceFuture<NegotiationWithServerFuture, TcpStream, NegotiationWithServerTransport, nego::Request>>
    {
        let server_transport = NegotiationWithServerTransport::default().framed(server);

        let target_username = self.identity.target.username.clone();

        let pdu = create_negotiation_request(
            target_username,
            self.request
                .as_ref()
                .expect("For server negotiation future, the request must be set after negotiation with client")
                .clone(),
        )?;

        let send_future = async {
            let mut server_transport = server_transport;
            Pin::new(&mut server_transport).send(pdu).await?;
            Ok(server_transport)
        };

        Ok(SequenceFuture::with_send_state(
            NegotiationWithServerFuture::new(),
            SendStateArgs {
                send_future: Box::pin(send_future),
                phantom_data: PhantomData,
            },
        ))
    }

    fn create_nla_server_future(
        &self,
        server: TcpStream,
        server_response_protocol: nego::SecurityProtocol,
    ) -> io::Result<NlaWithServerFuture> {
        let target_identity = self.identity.target.clone();
        let request_flags = self
            .request
            .as_ref()
            .expect("for NLA server future, the request must be set after negotiation with client")
            .flags;

        NlaWithServerFuture::new(server, request_flags, server_response_protocol, target_identity, true)
    }

    fn create_mcs_initial_future(
        &mut self,
        server_nla_transport: NlaTransport,
    ) -> SequenceFuture<McsInitialFuture, TlsStream<TcpStream>, DataTransport, BytesMut> {
        let client_nla_transport = self
            .client_nla_transport
            .take()
            .expect("For the McsInitial state, the client NLA transport must be set after the client negotiation");
        let client_transport = match client_nla_transport {
            NlaTransport::TsRequest(transport) => utils::update_framed_codec(transport, DataTransport::default()),
            NlaTransport::EarlyUserAuthResult(transport) => {
                utils::update_framed_codec(transport, DataTransport::default())
            }
        };
        let server_transport = match server_nla_transport {
            NlaTransport::TsRequest(transport) => utils::update_framed_codec(transport, DataTransport::default()),
            NlaTransport::EarlyUserAuthResult(transport) => {
                utils::update_framed_codec(transport, DataTransport::default())
            }
        };

        let response_protocol = self
            .response_protocol
            .expect("Response protocol must be set in NegotiationWithServer future");

        let target = self.identity.target.clone();
        let target_converted = ironrdp::rdp::Credentials {
            username: target.username,
            password: target.password,
            domain: target.domain,
        };

        SequenceFuture::with_get_state(
            McsInitialFuture::new(FilterConfig::new(response_protocol, target_converted)),
            GetStateArgs {
                client: Some(client_transport),
                server: Some(server_transport),
                phantom_data: PhantomData,
            },
        )
    }

    fn create_mcs_future(
        &mut self,
        client_mcs_initial_transport: Framed<TlsStream<TcpStream>, DataTransport>,
        server_mcs_initial_transport: Framed<TlsStream<TcpStream>, DataTransport>,
        static_channels: StaticChannels,
    ) -> SequenceFuture<McsFuture, TlsStream<TcpStream>, McsTransport, ironrdp::McsPdu> {
        SequenceFuture::with_get_state(
            McsFuture::new(static_channels),
            GetStateArgs {
                client: Some(utils::update_framed_codec(
                    client_mcs_initial_transport,
                    McsTransport::default(),
                )),
                server: Some(utils::update_framed_codec(
                    server_mcs_initial_transport,
                    McsTransport::default(),
                )),
                phantom_data: PhantomData,
            },
        )
    }

    fn create_post_mcs_future(
        &mut self,
        client_transport: McsFutureTransport,
        server_transport: McsFutureTransport,
    ) -> SequenceFuture<PostMcs, TlsStream<TcpStream>, SendDataContextTransport, (ironrdp::McsPdu, Vec<u8>)> {
        SequenceFuture::with_get_state(
            PostMcs::new(
                self.filter_config
                    .take()
                    .expect("the filter config must be set after the MCS initial"),
            ),
            GetStateArgs {
                client: Some(utils::update_framed_codec(
                    client_transport,
                    SendDataContextTransport::default(),
                )),
                server: Some(utils::update_framed_codec(
                    server_transport,
                    SendDataContextTransport::default(),
                )),
                phantom_data: PhantomData,
            },
        )
    }

    fn create_finalization(
        &mut self,
        client_transport: PostMcsFutureTransport,
        server_transport: PostMcsFutureTransport,
    ) -> SequenceFuture<Finalization, TlsStream<TcpStream>, RdpTransport, RdpPdu> {
        let client_transport = utils::update_framed_codec(client_transport, RdpTransport::default());
        let server_transport = utils::update_framed_codec(server_transport, RdpTransport::default());

        SequenceFuture::with_get_state(
            Finalization::new(),
            GetStateArgs {
                client: Some(client_transport),
                server: Some(server_transport),
                phantom_data: PhantomData,
            },
        )
    }
}

impl Future for ConnectionSequenceFuture {
    type Output = anyhow::Result<RdpProxyConnection>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match &mut self.state {
                ConnectionSequenceFutureState::NegotiationWithClient(negotiation_future) => {
                    let (transport, request, response) = ready!(negotiation_future.as_mut().poll(cx))?;
                    self.request = Some(request);

                    let client = transport.into_inner();

                    if let Some(nego::ResponseData::Response { protocol, .. }) = response.response {
                        self.state = ConnectionSequenceFutureState::NlaWithClient(Box::pin(
                            self.create_nla_client_future(client, protocol),
                        ));
                    } else {
                        return Poll::Ready(Err(anyhow::Error::msg(
                            "The client does not support HYBRID (or HYBRID_EX) protocol",
                        )));
                    }
                }
                ConnectionSequenceFutureState::NlaWithClient(nla_future) => {
                    let client_transport = ready!(nla_future.as_mut().poll(cx))?;
                    self.client_nla_transport = Some(client_transport);

                    let destinations = self.identity.targets.clone();
                    let future = async move {
                        let destinations = destinations;
                        utils::successive_try(&destinations, utils::tcp_stream_connect)
                            .await
                            .map(|(stream, selected)| (stream, selected.clone()))
                    };

                    self.state = ConnectionSequenceFutureState::ConnectToServer(Box::pin(future));
                }
                ConnectionSequenceFutureState::ConnectToServer(connect_future) => {
                    let (server, selected_target) = ready!(connect_future.as_mut().poll(cx))?;
                    self.selected_target = Some(selected_target);

                    self.state = ConnectionSequenceFutureState::NegotiationWithServer(Box::pin(
                        self.create_server_negotiation_future(server)?,
                    ));
                }
                ConnectionSequenceFutureState::NegotiationWithServer(negotiation_future) => {
                    let (server_transport, response) = ready!(negotiation_future.as_mut().poll(cx))?;

                    let server = server_transport.into_inner();

                    if let Some(nego::ResponseData::Response { protocol, .. }) = response.response {
                        self.response_protocol = Some(protocol);
                        self.state = ConnectionSequenceFutureState::NlaWithServer(Box::pin(
                            self.create_nla_server_future(server, protocol)?,
                        ));
                    } else {
                        unreachable!("The negotiation with client future must return response");
                    }
                }
                ConnectionSequenceFutureState::NlaWithServer(nla_future) => {
                    let server_nla_transport = ready!(nla_future.as_mut().poll(cx))?;

                    self.state = ConnectionSequenceFutureState::McsInitial(Box::pin(
                        self.create_mcs_initial_future(server_nla_transport),
                    ))
                }
                ConnectionSequenceFutureState::McsInitial(mcs_initial_future) => {
                    let (client_transport, server_transport, filter_config, static_channels) =
                        ready!(mcs_initial_future.as_mut().poll(cx))?;
                    self.filter_config = Some(filter_config);

                    self.state = ConnectionSequenceFutureState::Mcs(Box::pin(self.create_mcs_future(
                        client_transport,
                        server_transport,
                        static_channels,
                    )));
                }
                ConnectionSequenceFutureState::Mcs(mcs_future) => {
                    let (client_transport, server_transport, joined_static_channels) =
                        ready!(mcs_future.as_mut().poll(cx))?;
                    self.joined_static_channels = Some(joined_static_channels);

                    self.state = ConnectionSequenceFutureState::PostMcs(Box::pin(
                        self.create_post_mcs_future(client_transport, server_transport),
                    ));
                }
                ConnectionSequenceFutureState::PostMcs(rdp_future) => {
                    let (client_transport, server_transport, _filter_config) = ready!(rdp_future.as_mut().poll(cx))?;

                    self.state = ConnectionSequenceFutureState::Finalization(Box::pin(
                        self.create_finalization(client_transport, server_transport),
                    ));
                }
                ConnectionSequenceFutureState::Finalization(finalization) => {
                    let (client_transport, server_transport) = ready!(finalization.as_mut().poll(cx))?;

                    return Poll::Ready(Ok(RdpProxyConnection {
                        client: client_transport,
                        server: server_transport,
                        channels: self.joined_static_channels.take().expect(
                            "During RDP connection sequence, the joined static channels must exist in the RDP state",
                        ),
                        selected_target: self
                            .selected_target
                            .take()
                            .expect("During RDP connection sequence, a target is selected"),
                    }));
                }
            }
        }
    }
}

enum ConnectionSequenceFutureState {
    NegotiationWithClient(NegotiationWithClientT),
    NlaWithClient(NlaWithClientT),
    ConnectToServer(ConnectToServerT),
    NegotiationWithServer(NegotiationWithServerT),
    NlaWithServer(NlaWithServerT),
    McsInitial(McsInitialT),
    Mcs(McsT),
    PostMcs(PostMcsT),
    Finalization(FinalizationT),
}

type NegotiationWithClientT =
    Pin<Box<SequenceFuture<NegotiationWithClientFuture, TcpStream, NegotiationWithClientTransport, nego::Response>>>;
type NlaWithClientT = Pin<Box<NlaWithClientFuture>>;
type ConnectToServerT = Pin<Box<dyn Future<Output = anyhow::Result<(TcpStream, TargetAddr)>> + Send>>;
type NegotiationWithServerT =
    Pin<Box<SequenceFuture<NegotiationWithServerFuture, TcpStream, NegotiationWithServerTransport, nego::Request>>>;
type NlaWithServerT = Pin<Box<NlaWithServerFuture>>;
type McsInitialT = Pin<Box<SequenceFuture<McsInitialFuture, TlsStream<TcpStream>, DataTransport, BytesMut>>>;
type McsT = Pin<Box<SequenceFuture<McsFuture, TlsStream<TcpStream>, McsTransport, ironrdp::McsPdu>>>;
type PostMcsT =
    Pin<Box<SequenceFuture<PostMcs, TlsStream<TcpStream>, SendDataContextTransport, (ironrdp::McsPdu, Vec<u8>)>>>;
type FinalizationT = Pin<Box<SequenceFuture<Finalization, TlsStream<TcpStream>, RdpTransport, RdpPdu>>>;
