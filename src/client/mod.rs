pub mod config;
mod resplit;

use failure::{format_err, Error, Fail, ResultExt};
use futures::{future, prelude::*};
use hyper::{Body, Chunk, Request, Response, StatusCode};
use hyper_tls::HttpsConnector;
use log::{debug, error, warn};
use native_tls::{Certificate, Identity, TlsConnector};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{
    env,
    fmt::{Debug, Display},
    path::PathBuf,
    sync::Arc,
};
use url::Url;

use self::config::ConfigContext;

#[derive(Fail, Debug)]
#[fail(display = "Unexpected HTTP response status: {}", status)]
pub struct HttpStatusError {
    status: StatusCode,
}

#[derive(Fail, Debug)]
#[fail(display = "Unable to parse response: {}", reason)]
pub struct ParseError {
    reason: String,
}

#[derive(Debug, Clone)]
pub struct Client<C> {
    client: Arc<hyper::Client<C>>,
    config: ConfigContext,
}

impl Client<HttpsConnector<hyper::client::HttpConnector>> {
    pub fn new() -> Result<Self, Error> {
        let dns_threads = 1; // Only need a single DNS lookup
        let http = hyper::client::HttpConnector::new(dns_threads);
        Client::new_from_http(http)
    }

    pub fn new_from_http(http: hyper::client::HttpConnector) -> Result<Self, Error> {
        let config_path = env::var_os(config::CONFIG_ENV)
            .map(PathBuf::from)
            .or_else(config::default_path)
            .ok_or_else(|| format_err!("Unable to find config"))?;
        debug!("Reading config from {}", config_path.display());
        let config = config::load_from_file(&config_path)
            .with_context(|e| format!("Unable to read {}: {}", config_path.display(), e))?;
        let context = config.config_context(&config.current_context)?;
        Client::new_from_context(http, context)
    }

    pub fn new_from_context(
        mut http: hyper::client::HttpConnector,
        config: ConfigContext,
    ) -> Result<Self, Error> {
        http.enforce_http(false);
        let mut tls = TlsConnector::builder();
        if let (Some(certdata), Some(keydata)) = (
            config.user.client_certificate_read(),
            config.user.client_key_read(),
        ) {
            debug!("Setting user client cert");
            let cert = openssl::x509::X509::from_pem(&certdata?)?;
            let pkey = openssl::pkey::PKey::private_key_from_pem(&keydata?)?;
            // openssl pkcs12 -export -clcerts -inkey kubecfg.key -in kubecfg.crt -out kubecfg.p12 -name "kubecfg"
            let password = "";
            let p12 =
                openssl::pkcs12::Pkcs12::builder().build(password, "kubeconfig", &pkey, &cert)?;
            tls.identity(Identity::from_pkcs12(&p12.to_der()?, password)?);
        }

        if let Some(data) = config.cluster.certificate_authority_read() {
            debug!("Setting cluster CA cert");
            let cert = Certificate::from_pem(&data?)?;
            // FIXME: want to validate against _only_ this cert ..
            tls.add_root_certificate(cert);
        }

        if config.cluster.insecure_skip_tls_verify {
            warn!("Disabling CA verification");

            tls.danger_accept_invalid_certs(true);
        }

        let hyper_client =
            hyper::Client::builder().build(HttpsConnector::from((http, tls.build()?)));

        Self::new_with_client(hyper_client, config)
    }
}

impl<C> Client<C> {
    pub fn new_with_client(client: hyper::Client<C>, config: ConfigContext) -> Result<Self, Error> {
        Ok(Client {
            client: Arc::new(client),
            config,
        })
    }

    pub fn client(&self) -> &hyper::Client<C> {
        &self.client
    }
}

#[derive(Clone, Debug)]
pub struct StatusError<S: Debug>(S);

impl<S: Debug> std::error::Error for StatusError<S> {
    fn description(&self) -> &str {
        "request failed"
    }
}

impl<S: Debug> Display for StatusError<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let StatusError(status) = self;
        write!(f, "{:?}", status)
    }
}

pub enum Observed<L, I> {
    List(L),
    ListPart(L),
    Item(I),
}

pub struct ListState<L> {
    list: L,
    continu_: Option<String>,
    resource_version: String,
}

pub struct WatchState<I> {
    item: I,
    resource_version: String,
}

pub enum KubernetesError<S> {
    Status(S),
    Other(Error),
}

impl<S> From<Error> for KubernetesError<S> {
    fn from(error: Error) -> Self {
        KubernetesError::Other(error)
    }
}

pub enum ObserverState<List, Item, Status> {
    None,
    Listing(Box<dyn Future<Item = ListState<List>, Error = KubernetesError<Status>> + Send>),
    Watching(Box<dyn Stream<Item = WatchState<Item>, Error = KubernetesError<Status>> + Send>),
}

pub struct Observer<L, I, S, B>
where
    L: DeserializeOwned + Debug + Send + Sync + 'static,
    I: DeserializeOwned + Debug + Send + Sync + 'static,
    S: DeserializeOwned + Debug + Send + Sync + 'static,
    B: Into<hyper::Body> + Send + 'static,
{
    state: ObserverState<L, I, S>,
    last_resource_version: Option<String>,
    client: Client<HttpsConnector<hyper::client::HttpConnector>>,
    request_factory: Box<Fn(RequestOpts) -> K8sRequest<B> + Send>,
}

fn get_resource_version(value: &Value) -> Option<String> {
    value
        .get("metadata")
        .and_then(|m| m.get("resourceVersion"))
        .and_then(|rv| rv.as_str())
        .map(|str| str.to_string())
}

fn get_continue(value: &Value) -> Option<String> {
    value
        .get("metadata")
        .and_then(|m| m.get("continue"))
        .and_then(|rv| rv.as_str())
        .map(|str| str.to_string())
}

pub struct RequestOpts<'a> {
    pub watch: bool,
    pub resource_version: Option<&'a str>,
    pub continu_: Option<&'a str>,
}

impl<L, I, S, B> Observer<L, I, S, B>
where
    L: DeserializeOwned + Debug + Send + Sync + 'static,
    I: DeserializeOwned + Debug + Send + Sync + 'static,
    S: DeserializeOwned + Debug + Send + Sync + 'static,
    B: Into<hyper::Body> + Send + 'static,
{
    fn list(
        &mut self,
        continu_: &Option<String>,
    ) -> impl Future<Item = ListState<L>, Error = KubernetesError<S>> + Send {
        let req = (*self.request_factory)(RequestOpts {
            watch: false,
            resource_version: None,
            continu_: match continu_ {
                Some(ref str) => Some(str.as_str()),
                None => None,
            },
        });

        self.client.simple_req_chunk(req).then(
            |result| -> Result<ListState<L>, KubernetesError<S>> {
                match result {
                    Ok(chunk) => {
                        let o: Value = serde_json::from_slice(chunk.as_ref())
                            .map_err(|e| KubernetesError::Other(e.into()))?;

                        let resource_version: String = match get_resource_version(&o) {
                            Some(rv) => Ok(rv),
                            None => Err(KubernetesError::Other(
                                ParseError {
                                    reason: format!(
                                        "missing resourceVersion in response object {:?}",
                                        o
                                    ),
                                }.into(),
                            )),
                        }?;
                        let continu_ = get_continue(&o);

                        warn!(
                            "Got resource version {:?}, continu_ {:?} from list operation",
                            resource_version, continu_
                        );

                        Ok(ListState {
                            list: serde_json::from_value(o).map_err(|e| {
                                error!(
                                    "Parsing response body: {}",
                                    String::from_utf8_lossy(chunk.as_ref())
                                );
                                KubernetesError::Other(e.into())
                            })?,
                            resource_version,
                            continu_,
                        })
                    }
                    Err(KubernetesError::Status((chunk, httpstatus))) => {
                        let status: S = serde_json::from_slice(chunk.as_ref()).map_err(|e| {
                            error!(
                                "Failed to parse error Status ({}), falling back to HTTP status",
                                e
                            );
                            KubernetesError::Other(HttpStatusError { status: httpstatus }.into())
                        })?;

                        Err(KubernetesError::Status(status))
                    }
                    Err(KubernetesError::Other(e)) => Err(KubernetesError::Other(e)),
                }
            },
        )
    }

    fn watch(&mut self) -> impl Stream<Item = WatchState<I>, Error = KubernetesError<S>> + Send {
        let req = (*self.request_factory)(RequestOpts {
            watch: true,
            continu_: None,
            resource_version: match self.last_resource_version {
                Some(ref str) => Some(str.as_str()),
                None => None,
            },
        });

        self.client.watch_as_chunk(req).then(
            |result| -> Result<WatchState<I>, KubernetesError<S>> {
                match result {
                    Ok(chunk) => {
                        let o: Value = serde_json::from_slice(chunk.as_ref())
                            .map_err(|e| KubernetesError::Other(e.into()))?;

                        let resource_version: String =
                            match o.get("object").and_then(get_resource_version) {
                                Some(rv) => Ok(rv),
                                None => Err(KubernetesError::Other(
                                    ParseError {
                                        reason: format!(
                                            "missing resourceVersion in response object {:?}",
                                            o
                                        ),
                                    }.into(),
                                )),
                            }?;

                        Ok(WatchState {
                            item: serde_json::from_value(o).map_err(|e| {
                                error!(
                                    "Parsing response body: {}",
                                    String::from_utf8_lossy(chunk.as_ref())
                                );
                                KubernetesError::Other(e.into())
                            })?,
                            resource_version,
                        })
                    }
                    Err(KubernetesError::Status((chunk, httpstatus))) => {
                        let status: S = serde_json::from_slice(chunk.as_ref()).map_err(|e| {
                            error!(
                                "Failed to parse error Status ({}), falling back to HTTP status",
                                e
                            );
                            KubernetesError::Other(HttpStatusError { status: httpstatus }.into())
                        })?;

                        Err(KubernetesError::Status(status))
                    }
                    Err(KubernetesError::Other(e)) => Err(KubernetesError::Other(e)),
                }
            },
        )
    }
}

impl<L, I, S, B> Stream for Observer<L, I, S, B>
where
    L: DeserializeOwned + Debug + Send + Sync + 'static,
    I: DeserializeOwned + Debug + Send + Sync + 'static,
    S: DeserializeOwned + Debug + Send + Sync + 'static,
    B: Into<hyper::Body> + Send + 'static,
{
    type Error = KubernetesError<S>;
    type Item = Observed<L, I>;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match &mut self.state {
            ObserverState::None => {
                let future = Box::new(self.list(&None));
                self.state = ObserverState::Listing(future);
                self.poll()
            }
            ObserverState::Listing(future) => (*future)
                .poll()
                .map(|async_value| {
                    async_value.map(|list_state| {
                        if let Some(continu_) = list_state.continu_ {
                            let future = Box::new(self.list(&Some(continu_)));
                            self.state = ObserverState::Listing(future);
                            Some(Observed::ListPart(list_state.list))
                        } else {
                            self.last_resource_version = Some(list_state.resource_version);
                            let stream = Box::new(self.watch());
                            self.state = ObserverState::Watching(stream);
                            Some(Observed::List(list_state.list))
                        }
                    })
                }).map_err(|e| {
                    self.state = ObserverState::None;
                    self.last_resource_version = None;
                    e
                }),
            ObserverState::Watching(stream) => (*stream)
                .poll()
                .and_then(|async_value| match async_value {
                    Async::Ready(result) => match result {
                        Some(watch_state) => {
                            self.last_resource_version = Some(watch_state.resource_version);
                            Ok(Async::Ready(Some(Observed::Item(watch_state.item))))
                        }
                        None => {
                            let stream = Box::new(self.watch());
                            self.state = ObserverState::Watching(stream);
                            self.poll()
                        }
                    },
                    Async::NotReady => Ok(Async::NotReady),
                }).map_err(|e| {
                    self.state = ObserverState::None;
                    self.last_resource_version = None;
                    e
                }),
        }
    }
}

type K8sRequest<B> = Result<Request<B>, k8s_openapi::RequestError>;

impl<C: hyper::client::connect::Connect + 'static> Client<C> {
    fn rebase_url<B>(&self, mut req: Request<B>) -> Result<Request<hyper::Body>, Error>
    where
        B: Into<hyper::Body> + Send + 'static,
    {
        if req.uri().host().is_none() {
            let req_uri = format!("{}", req.uri());
            let base_uri: Url = self.config.cluster.server.parse()?;
            let joined_uri = base_uri.join(&req_uri)?;

            *req.uri_mut() = joined_uri.to_string().parse()?;
        }

        Ok(req.map(<B>::into))
    }

    fn wrap_req<B>(
        &self,
        result_req: Result<Request<B>, k8s_openapi::RequestError>,
    ) -> Result<Request<hyper::Body>, Error>
    where
        B: Into<hyper::Body> + Send + 'static,
    {
        match result_req {
            Ok(req) => Ok(self.rebase_url(req)?),
            Err(e) => Err(e.into()),
        }
    }

    pub fn observe<L, I, S, B>(
        &self,
        request_factory: Box<Fn(RequestOpts) -> K8sRequest<B> + Send>,
    ) -> Result<impl Stream<Item = Observed<L, I>, Error = KubernetesError<S>> + Send, Error>
    where
        L: DeserializeOwned + Debug + Send + Sync + 'static,
        I: DeserializeOwned + Debug + Send + Sync + 'static,
        S: DeserializeOwned + Debug + Send + Sync + 'static,
        B: Into<hyper::Body> + Send + 'static,
    {
        Ok(Observer {
            state: ObserverState::None,
            last_resource_version: None,
            client: Client::new()?,
            request_factory,
        })
    }

    pub fn simple_req_chunk<B>(
        &self,
        req: Result<Request<B>, k8s_openapi::RequestError>,
    ) -> impl Future<Item = Chunk, Error = KubernetesError<(Chunk, StatusCode)>> + Send
    where
        B: Into<hyper::Body> + Send + 'static,
    {
        let client = Arc::clone(&self.client);
        future::result(self.wrap_req(req))
            .inspect(|req|
                    // Avoid body, since it may not be Debug
                    debug!("Request: {} {}", req.method(), req.uri()))
            .and_then(move |req|
                    // TODO: add method/uri context to error
                    client.request(req).from_err::<Error>())
            .inspect(|res| debug!("Response: {} {:?}", res.status(), res.headers()))
            // Verbose!
            //.inspect(|res| debug!("Response: {:#?}", res))
            .and_then(|res| {
                let status = res.status();
                res.into_body().concat2().map(move |body| (status, body)).from_err()
            })
            // Verbose!
            //.inspect(|(_, body)| debug!("Response body: {:?}", ::std::str::from_utf8(body.as_ref())))
            .map_err(KubernetesError::Other)
            .and_then(move |(httpstatus, body)| -> Result<Chunk, KubernetesError<(Chunk, StatusCode)>> {
                if httpstatus.is_success() {
                    Ok(body)
                } else {
                    error!("failure body: {:#?}", ::std::str::from_utf8(body.as_ref()));
                    Err(KubernetesError::Status((body, httpstatus)))
                }
            })
    }

    pub fn simple_req<T, S, B>(
        &self,
        req: Result<Request<B>, k8s_openapi::RequestError>,
    ) -> impl Future<Item = T, Error = KubernetesError<S>> + Send
    where
        T: DeserializeOwned + Debug + Send + Sync + 'static,
        S: DeserializeOwned + Debug + Send + Sync + 'static,
        B: Into<hyper::Body> + Send + 'static,
    {
        self.simple_req_chunk(req).then(|result| match result {
            Ok(chunk) => {
                let o: T = serde_json::from_slice(chunk.as_ref()).map_err(|e| {
                    error!(
                        "Parsing response body: {}",
                        String::from_utf8_lossy(chunk.as_ref())
                    );
                    KubernetesError::Other(e.into())
                })?;
                Ok(o)
            }
            Err(KubernetesError::Status((chunk, httpstatus))) => {
                let status: S = serde_json::from_slice(chunk.as_ref()).map_err(|e| {
                    error!(
                        "Failed to parse error Status ({}), falling back to HTTP status",
                        e
                    );
                    KubernetesError::Other(HttpStatusError { status: httpstatus }.into())
                })?;

                Err(KubernetesError::Status(status))
            }
            Err(KubernetesError::Other(e)) => Err(KubernetesError::Other(e)),
        })
    }

    pub(crate) fn watch_as_chunk<B>(
        &self,
        req: Result<Request<B>, k8s_openapi::RequestError>,
    ) -> impl Stream<Item = Vec<u8>, Error = KubernetesError<(Chunk, StatusCode)>> + Send
    where
        B: Into<hyper::Body> + Send + 'static,
    {
        let client = Arc::clone(&self.client);
        future::result(self.wrap_req(req))
            .inspect(|req| debug!("Watch request: {} {}", req.method(), req.uri()))
            .and_then(move |req|
                    // TODO: add method/uri context to error
                    client.request(req).from_err::<Error>())
            .inspect(|res| debug!("Response: {:#?}", res))
            .map_err(KubernetesError::Other)
            .and_then(|res| {
                let httpstatus = res.status();
                let r = if httpstatus.is_success() { Ok(res) } else { Err(res) };
                future::result(r)
                    .or_else(move |res| {
                        res.into_body()
                            .concat2()
                            .map_err(|e| KubernetesError::Other(e.into()))
                            .and_then(move |body| -> Result<Response<Body>, KubernetesError<(Chunk, StatusCode)>> {
                                error!("failure body: {:#?}", ::std::str::from_utf8(body.as_ref()));
                                Err(KubernetesError::Status((body, httpstatus)))
                            })
                    })
                    .map(|res| {
                        resplit::new(res.into_body(), |&c| c == b'\n')
                            .inspect(|line| debug!("Got line: {:#?}", ::std::str::from_utf8(line).unwrap_or("<invalid utf8>")))
                            .map_err(|e| KubernetesError::Other(e.into()))
                            .and_then(move |line| -> Result<Vec<u8>, KubernetesError<(Chunk, StatusCode)>> {
                                Ok(line)
                            })
                    })
            })
            .flatten_stream()
    }

    pub fn watch<T, S, B>(
        &self,
        req: Result<Request<B>, k8s_openapi::RequestError>,
    ) -> impl Stream<Item = T, Error = KubernetesError<S>> + Send
    where
        T: DeserializeOwned + Debug + Send + Sync + 'static,
        S: DeserializeOwned + Debug + Send + Sync + 'static,
        B: Into<hyper::Body> + Send + 'static,
    {
        self.watch_as_chunk(req).then(|result| match result {
            Ok(chunk) => {
                let o: T = serde_json::from_slice(chunk.as_ref()).map_err(|e| {
                    error!(
                        "Parsing response body: {}",
                        String::from_utf8_lossy(chunk.as_ref())
                    );
                    KubernetesError::Other(e.into())
                })?;
                Ok(o)
            }
            Err(KubernetesError::Status((chunk, httpstatus))) => {
                let status: S = serde_json::from_slice(chunk.as_ref()).map_err(|e| {
                    error!(
                        "Failed to parse error Status ({}), falling back to HTTP status",
                        e
                    );
                    KubernetesError::Other(HttpStatusError { status: httpstatus }.into())
                })?;

                Err(KubernetesError::Status(status))
            }
            Err(KubernetesError::Other(e)) => Err(KubernetesError::Other(e)),
        })
        // let client = Arc::clone(&self.client);
        // future::result(self.wrap_req(req))
        //     .inspect(|req| debug!("Watch request: {} {}", req.method(), req.uri()))
        //     .and_then(move |req|
        //             // TODO: add method/uri context to error
        //             client.request(req).from_err::<Error>())
        //     .inspect(|res| debug!("Response: {:#?}", res))
        //     .map_err(|e| -> KubernetesError<S> { KubernetesError::Other(e) })
        //     .and_then(|res| {
        //         let httpstatus = res.status();
        //         let r = if httpstatus.is_success() { Ok(res) } else { Err(res) };
        //         future::result(r)
        //             .or_else(move |res| {
        //                 res.into_body()
        //                     .concat2()
        //                     .map_err(|e| KubernetesError::Other(e.into()))
        //                     .and_then(move |body| -> Result<Response<Body>, KubernetesError<S>> {
        //                         error!("failure body: {:#?}", ::std::str::from_utf8(body.as_ref()));
        //                         let status: S = serde_json::from_slice(body.as_ref())
        //                             .map_err(|e| {
        //                                 error!("Failed to parse error Status ({}), falling back to HTTP status", e);
        //                                 KubernetesError::Other(HttpStatusError{status: httpstatus}.into())
        //                             })?;

        //                         Err(KubernetesError::Status(status))
        //                     })
        //             })
        //             .map(|res| {
        //                 resplit::new(res.into_body(), |&c| c == b'\n')
        //                     .inspect(|line| debug!("Got line: {:#?}", ::std::str::from_utf8(line).unwrap_or("<invalid utf8>")))
        //                     .map_err(|e| KubernetesError::Other(e.into()))
        //                     .and_then(move |line| -> Result<T, KubernetesError<S>> {
        //                         let o: T = serde_json::from_slice(line.as_ref())
        //                             .map_err(|e| {
        //                                 error!("Parsing response body: {}", String::from_utf8_lossy(line.as_ref()));
        //                                 KubernetesError::Other(e.into())
        //                             })?;
        //                         Ok(o)
        //                     })
        //             })
        //     })
        //     .flatten_stream()
    }
}
