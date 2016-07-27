use winapi;
use secur32;
use std::ops::Deref;
use std::slice;

pub struct ContextBuffer(pub winapi::SecBuffer);

impl Drop for ContextBuffer {
    fn drop(&mut self) {
        unsafe {
            secur32::FreeContextBuffer(self.0.pvBuffer);
        }
    }
}

impl Deref for ContextBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.0.pvBuffer as *const _, self.0.cbBuffer as usize) }
    }
}
