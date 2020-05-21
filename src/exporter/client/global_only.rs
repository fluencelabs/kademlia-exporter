use libp2p::core::{
    multiaddr::{Multiaddr, Protocol},
    transport::TransportError,
    Transport,
};
use log::debug;

// Wrapper around a libp2p `Transport` dropping all dial requests to non-global
// IP addresses.
#[derive(Debug, Clone, Default)]
pub struct GlobalIpOnly<T> {
    inner: T,
}

#[allow(dead_code)]
impl<T> GlobalIpOnly<T> {
    pub fn new(transport: T) -> Self {
        GlobalIpOnly { inner: transport }
    }
}

impl<T: Transport> Transport for GlobalIpOnly<T> {
    type Output = <T as Transport>::Output;
    type Error = <T as Transport>::Error;
    type Listener = <T as Transport>::Listener;
    type ListenerUpgrade = <T as Transport>::ListenerUpgrade;
    type Dial = <T as Transport>::Dial;

    fn listen_on(self, addr: Multiaddr) -> Result<Self::Listener, TransportError<Self::Error>> {
        self.inner.listen_on(addr)
    }

    fn dial(self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        match addr.iter().next() {
            Some(Protocol::Ip4(a)) => {
                if a.is_global() {
                    self.inner.dial(addr)
                } else {
                    debug!("Not dialing non global IP address {:?}.", a);
                    Err(TransportError::MultiaddrNotSupported(addr))
                }
            }
            Some(Protocol::Ip6(a)) => {
                if a.is_global() {
                    self.inner.dial(addr)
                } else {
                    debug!("Not dialing non global IP address {:?}.", a);
                    Err(TransportError::MultiaddrNotSupported(addr))
                }
            }
            _ => {
                debug!("Not dialing unsupported Multiaddress {:?}.", addr);
                Err(TransportError::MultiaddrNotSupported(addr))
            }
        }
    }
}
