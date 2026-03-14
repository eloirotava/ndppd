use std::ffi::CString;
use std::io::Error as IoError;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};

use classic_bpf::{BPFFProg, BPFFilter, BPF_ABS, BPF_B, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET};
use libc::{c_void, sockaddr_ll};

/// Representa uma interface de rede escutando pacotes NDP
#[derive(Debug)]
pub struct Iface {
    pub name: String,
    ifindex: i32,
    fd: RawFd,
}

impl Iface {
    /// Inicializa a interface, cria o socket bruto e aplica os filtros BPF
    pub fn new(name: &str) -> Result<Self, IoError> {
        // 1. Descobrir o index da interface (ex: eth0 -> 2)
        let c_name = CString::new(name).unwrap();
        let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) } as i32;
        if ifindex == 0 {
            return Err(IoError::last_os_error());
        }

        // 2. Criar um Raw Socket para capturar pacotes Ethernet com IPv6
        let fd = unsafe {
            libc::socket(
                libc::PF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_IPV6 as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(IoError::last_os_error());
        }

        let iface = Self {
            name: name.to_string(),
            ifindex,
            fd,
        };

        iface.bind()?;
        iface.set_allmulti()?;
        iface.set_bpf_filter()?;

        Ok(iface)
    }

    /// Liga o socket especificamente a esta interface
    fn bind(&self) -> Result<(), IoError> {
        let mut addr: sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::PF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_IPV6 as u16).to_be();
        addr.sll_ifindex = self.ifindex;

        let res = unsafe {
            libc::bind(
                self.fd,
                &addr as *const sockaddr_ll as *const libc::sockaddr,
                size_of::<sockaddr_ll>() as u32,
            )
        };

        if res < 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Pede ao Kernel para aceitar pacotes de grupos Multicast (vital para o NDP)
    fn set_allmulti(&self) -> Result<(), IoError> {
        let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
        mreq.mr_ifindex = self.ifindex;
        mreq.mr_type = libc::PACKET_MR_ALLMULTI as u16;

        let res = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mreq as *const libc::packet_mreq as *const c_void,
                size_of::<libc::packet_mreq>() as u32,
            )
        };

        if res < 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Injeta um filtro BPF no Kernel para ignorar lixo e só ler NS e NA
    /// Baseado na lógica do repositório 6-6-6/ndproxy
    fn set_bpf_filter(&self) -> Result<(), IoError> {
        let filter = [
            // Lê o campo 'Next Header' do IPv6 (offset 6 do cabeçalho IP)
            BPFFilter::bpf_stmt((BPF_LD | BPF_B | BPF_ABS) as u16, 6),
            // Pula se não for ICMPv6 (protocolo 58)
            BPFFilter::bpf_jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, libc::IPPROTO_ICMPV6 as u32, 0, 5),
            
            // Lê o campo 'Type' do ICMPv6 (offset 40 de cabeçalho IPv6 + 0)
            BPFFilter::bpf_stmt((BPF_LD | BPF_B | BPF_ABS) as u16, 40),
            
            // É um Neighbor Solicitation (135)? Passa.
            BPFFilter::bpf_jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, 135, 2, 0),
            // É um Neighbor Advertisement (136)? Passa.
            BPFFilter::bpf_jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, 136, 1, 0),
            
            // Rejeita o pacote (retorna 0)
            BPFFilter::bpf_stmt((BPF_RET | BPF_K) as u16, 0),
            // Aceita o pacote (retorna o pacote inteiro)
            BPFFilter::bpf_stmt((BPF_RET | BPF_K) as u16, u32::MAX),
        ];

        let fprog = BPFFProg::new(&filter);
        if fprog.attach_filter(self.fd).is_err() {
            return Err(IoError::last_os_error());
        }
        Ok(())
    }

    // Permitir obter o File Descriptor bruto para ligarmos isto ao Tokio (Async)
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Iface {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}