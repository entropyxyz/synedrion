use rand_core::{CryptoRng, CryptoRngCore, RngCore};

/// We get a `dyn CryptoRngCore` from `manul::protocol` trait methods, but some dependencies
/// do not accept `?Sized` arguments (yet). This wrapper turns a dyn trait object into a static type
/// implementing `CryptoRngCore`.
pub(crate) struct BoxedRng<'a>(pub(crate) &'a mut dyn CryptoRngCore);

impl CryptoRng for BoxedRng<'_> {}

impl RngCore for BoxedRng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}
