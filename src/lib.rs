//! Bindings to the Windows SChannel APIs.
#![cfg(windows)]
#![warn(missing_docs)]
#![allow(non_upper_case_globals)]

extern crate winapi;

#[macro_use]
extern crate lazy_static;

use std::mem;
use std::ptr;
use winapi::ctypes;
use winapi::shared::sspi;

macro_rules! inner {
    ($t:path, $raw:ty) => {
        impl crate::Inner<$raw> for $t {
            unsafe fn from_inner(t: $raw) -> Self {
                $t(t)
            }

            fn as_inner(&self) -> $raw {
                self.0
            }

            fn get_mut(&mut self) -> &mut $raw {
                &mut self.0
            }
        }

        impl crate::RawPointer for $t {
            unsafe fn from_ptr(t: *mut ::std::os::raw::c_void) -> $t {
                $t(t as _)
            }

            unsafe fn as_ptr(&self) -> *mut ::std::os::raw::c_void {
                self.0 as *mut _
            }
        }
    }
}

/// Allows access to the underlying schannel API representation of a wrapped data type
/// 
/// Performing actions with internal handles might lead to the violation of internal assumptions 
/// and therefore is inherently unsafe.
pub trait RawPointer {
    /// Constructs an instance of this type from its handle / pointer.
    unsafe fn from_ptr(t: *mut ::std::os::raw::c_void) -> Self;

    /// Get a raw pointer from the underlying handle / pointer.
    unsafe fn as_ptr(&self) -> *mut ::std::os::raw::c_void;
}

pub mod cert_chain;
pub mod cert_context;
pub mod cert_store;
pub mod crypt_key;
pub mod crypt_prov;
/* pub */ mod ctl_context;
pub mod key_handle;
pub mod ncrypt_key;
pub mod schannel_cred;
pub mod tls_stream;

mod context_buffer;
mod security_context;

#[cfg(test)]
mod test;

const ACCEPT_REQUESTS: ctypes::c_ulong =
    sspi::ASC_REQ_ALLOCATE_MEMORY | sspi::ASC_REQ_CONFIDENTIALITY |
    sspi::ASC_REQ_SEQUENCE_DETECT | sspi::ASC_REQ_STREAM |
    sspi::ASC_REQ_REPLAY_DETECT;

const INIT_REQUESTS: ctypes::c_ulong =
    sspi::ISC_REQ_CONFIDENTIALITY | sspi::ISC_REQ_INTEGRITY | sspi::ISC_REQ_REPLAY_DETECT |
    sspi::ISC_REQ_SEQUENCE_DETECT | sspi::ISC_REQ_MANUAL_CRED_VALIDATION |
    sspi::ISC_REQ_ALLOCATE_MEMORY | sspi::ISC_REQ_STREAM | sspi::ISC_REQ_USE_SUPPLIED_CREDS;

const SEC_APPLICATION_PROTOCOL_LIST_HEADER_SIZE: usize =
    mem::size_of::<u32>() + mem::size_of::<ctypes::c_ushort>();
const SEC_APPLICATION_PROTOCOL_HEADER_SIZE: usize =
    mem::size_of::<ctypes::c_ulong>() + SEC_APPLICATION_PROTOCOL_LIST_HEADER_SIZE;

trait Inner<T> {
    unsafe fn from_inner(t: T) -> Self;

    fn as_inner(&self) -> T;

    fn get_mut(&mut self) -> &mut T;
}

unsafe fn secbuf(buftype: ctypes::c_ulong,
                 bytes: Option<&mut [u8]>) -> sspi::SecBuffer {
    let (ptr, len) = match bytes {
        Some(bytes) => (bytes.as_mut_ptr(), bytes.len() as ctypes::c_ulong),
        None => (ptr::null_mut(), 0),
    };
    sspi::SecBuffer {
        BufferType: buftype,
        cbBuffer: len,
        pvBuffer: ptr as *mut ctypes::c_void,
    }
}

unsafe fn secbuf_desc(bufs: &mut [sspi::SecBuffer]) -> sspi::SecBufferDesc {
    sspi::SecBufferDesc {
        ulVersion: sspi::SECBUFFER_VERSION,
        cBuffers: bufs.len() as ctypes::c_ulong,
        pBuffers: bufs.as_mut_ptr(),
    }
}

unsafe fn alpn_list(protos: &[Vec<u8>]) -> Vec<u8> {
    // ALPN wire format is each ALPN preceded by its length as a byte.
    let mut alpn_wire_format = Vec::with_capacity(
        protos.iter().map(Vec::len).sum::<usize>() + protos.len(),
    );
    for alpn in protos {
        alpn_wire_format.push(alpn.len() as u8);
        alpn_wire_format.extend(alpn);
    }

    // Make sure that the memory we're using for `sspi::SEC_APPLICATION_PROTOCOLS` matches
    // alignment requirements.
    let size = SEC_APPLICATION_PROTOCOL_HEADER_SIZE + alpn_wire_format.len();
    let mut aligned = Vec::<u64>::with_capacity((size - 1) / mem::size_of::<u64>() + 1);
    let p = aligned.as_mut_ptr() as *mut u8;
    let cap = aligned.capacity() * (mem::size_of::<u64>() / mem::size_of::<u8>());

    mem::forget(aligned);

    let mut buf = Vec::from_raw_parts(p, 0, cap);
    buf.resize(size, 0);

    let protocols = buf.as_mut_ptr() as *mut sspi::SEC_APPLICATION_PROTOCOLS;
    // Make sure that our constant is correctly sized in case of API changes. We could run into OOB
    // memory accesses if this assertion fires.
    assert_eq!(
        &(*(*protocols).ProtocolLists.as_mut_ptr()).ProtocolList as *const _ as usize
            - protocols as usize,
        SEC_APPLICATION_PROTOCOL_HEADER_SIZE
    );

    (*protocols).ProtocolListsSize =
        (SEC_APPLICATION_PROTOCOL_LIST_HEADER_SIZE + alpn_wire_format.len()) as ctypes::c_ulong;

    let protocol = (*protocols).ProtocolLists.as_mut_ptr();
    (*protocol).ProtoNegoExt = sspi::SecApplicationProtocolNegotiationExt_ALPN;
    (*protocol).ProtocolListSize = alpn_wire_format.len() as ctypes::c_ushort;

    let protocol_list = (*protocol).ProtocolList.as_mut_ptr();
    ptr::copy_nonoverlapping(alpn_wire_format.as_ptr(), protocol_list, alpn_wire_format.len());
    buf
}
