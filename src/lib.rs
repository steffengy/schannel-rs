//! Bindings to the Windows SChannel APIs.
#![cfg(windows)]
#![warn(missing_docs)]
#![allow(non_upper_case_globals)]

extern crate winapi;

#[macro_use]
extern crate lazy_static;

use std::ptr;
use std::mem;
use winapi::ctypes;
use winapi::shared::sspi;

macro_rules! inner {
    ($t:path, $raw:ty) => {
        impl ::Inner<$raw> for $t {
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
    }
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

unsafe fn alpn_list(protos: &Vec<Vec<u8>>) -> Vec<u8> {
    //the buffer is expected to not include packing but the structs are packed
    //due to how they are defined, so we subract the size of a c_ushort, as this
    //is how much padding the structure will have
	//
	//Ideally this would be const, but const fn is not stable yet
    let sec_application_protocol_list_header_size: usize = mem::size_of::<sspi::SEC_APPLICATION_PROTOCOL_LIST>() - std::mem::size_of::<ctypes::c_ushort>();

    let mut protocol_lists_size = 0;
    for proto in protos {
        protocol_lists_size += proto.len() + 1;
    }
    let mut buf = vec![0; mem::size_of::<sspi::SEC_APPLICATION_PROTOCOLS>() + sec_application_protocol_list_header_size + protocol_lists_size];
    {
        let protocols = buf.as_mut_ptr() as *mut sspi::SEC_APPLICATION_PROTOCOLS;
        (*protocols).ProtocolListsSize = (sec_application_protocol_list_header_size + protocol_lists_size) as ctypes::c_ulong;
    }
    let mut offset = mem::size_of::<sspi::SEC_APPLICATION_PROTOCOLS>();
    {
        let protocol =
            (&mut buf[offset..]).as_mut_ptr() as *mut sspi::SEC_APPLICATION_PROTOCOL_LIST;
        (*protocol).ProtoNegoExt = sspi::SecApplicationProtocolNegotiationExt_ALPN;
        (*protocol).ProtocolListSize = protocol_lists_size as ctypes::c_ushort;
        offset += sec_application_protocol_list_header_size;
    }
    for proto in protos {
        buf[offset] = proto.len() as u8;
        offset += 1;
        for &byte in proto {
            buf[offset] = byte;
            offset += 1;
        }
    }
    buf
}