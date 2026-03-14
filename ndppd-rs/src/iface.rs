use std::ffi::CString;
use std::io::Error as IoError;
use std::mem::size_of;
use std::os::unix::io::RawFd;

use classic_bpf::{BPFFProg, BPFFilter, BPFOperations, BPF_ABS, BPF_B, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET};
use libc::{c_void, sockaddr_ll};

#[derive(Debug)]
pub struct Iface {
    pub name: String,
    ifindex: i32,
    fd: RawFd,
    pub mac: [u8; 6], 
}

impl Iface {
    pub fn new(name: &str) -> Result<Self, IoError> {
        let c_name = CString::new(name).unwrap();
        let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) } as i32;
        if ifindex == 0 { return Err(IoError::last_os_error()); }

        let fd = unsafe {
            libc::socket(libc::PF_PACKET, libc::SOCK_RAW, (libc::ETH_P_IPV6 as u16).to_be() as i32)
        };
        if fd < 0 { return Err(IoError::last_os_error()); }

        // Ativar Modo Promíscuo e capturar MAC
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        unsafe {
            std::ptr::copy_nonoverlapping(c_name.as_ptr(), ifr.ifr_name.as_mut_ptr(), name.len());
            
            // Pega o MAC
            if libc::ioctl(fd, libc::SIOCGIFHWADDR as _, &mut ifr) < 0 {
                return Err(IoError::last_os_error());
            }

            // Ativa Promisc
            let mut flags_ifr = ifr;
            if libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut flags_ifr) >= 0 {
                flags_ifr.ifr_ifru.ifru_flags |= libc::IFF_PROMISC as i16;
                libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &flags_ifr);
            }
        }
        
        let mut mac = [0u8; 6];
        for i in 0..6 { mac[i] = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data[i] } as u8; }

        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let iface = Self { name: name.to_string(), ifindex, fd, mac };
        iface.bind()?;
        iface.set_allmulti()?;
        iface.set_bpf_filter()?;

        Ok(iface)
    }

    fn bind(&self) -> Result<(), IoError> {
        let mut addr: sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::PF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_IPV6 as u16).to_be();
        addr.sll_ifindex = self.ifindex;
        let res = unsafe { libc::bind(self.fd, &addr as *const sockaddr_ll as *const libc::sockaddr, size_of::<sockaddr_ll>() as u32) };
        if res < 0 { Err(IoError::last_os_error()) } else { Ok(()) }
    }

    fn set_allmulti(&self) -> Result<(), IoError> {
        let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
        mreq.mr_ifindex = self.ifindex;
        mreq.mr_type = libc::PACKET_MR_ALLMULTI as u16;
        let res = unsafe { libc::setsockopt(self.fd, libc::SOL_PACKET, libc::PACKET_ADD_MEMBERSHIP, &mreq as *const libc::packet_mreq as *const c_void, size_of::<libc::packet_mreq>() as u32) };
        if res < 0 { Err(IoError::last_os_error()) } else { Ok(()) }
    }

    fn set_bpf_filter(&self) -> Result<(), IoError> {
        let filter = [
            // CORREÇÃO: Offset 20 (14 Ethernet + 6 IPv6 Next Header)
            BPFFilter::bpf_stmt((BPF_LD | BPF_B | BPF_ABS) as u16, 20),
            BPFFilter::bpf_jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, libc::IPPROTO_ICMPV6 as u32, 0, 3),
            // CORREÇÃO: Offset 54 (14 Ethernet + 40 ICMPv6 Type)
            BPFFilter::bpf_stmt((BPF_LD | BPF_B | BPF_ABS) as u16, 54),
            BPFFilter::bpf_jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, 135, 2, 0),
            BPFFilter::bpf_jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, 136, 1, 0),
            BPFFilter::bpf_stmt((BPF_RET | BPF_K) as u16, 0),
            BPFFilter::bpf_stmt((BPF_RET | BPF_K) as u16, u32::MAX),
        ];
        let fprog = BPFFProg::new(&filter);
        let _ = fprog.attach_filter(self.fd);
        Ok(())
    }

    pub fn as_raw_fd(&self) -> RawFd { self.fd }
}