// Note: for StreamSocket, the client uses a server socket, the server uses a client socket.
// This is because of certificate management. The server needs to trust a client and its certificate
//
// StreamSender and StreamReceiver endpoints allow for convenient conversion of the header to/from
// bytes while still handling the additional byte buffer with zero copies and extra allocations.

// Performance analysis:
// We want to minimize the transmission time for various sizes of packets.
// The current code locks the write socket *per shard* and not *per packet*. This leds to the best
// performance outcome given that the possible packets can be either very small (one shard) or very
// large (hundreds/thousands of shards, for video). if we don't allow interleaving shards, a very
// small packet will need to wait a long time before getting received if there was an ongoing
// transmission of a big packet before. If we allow interleaving shards, small packets can be
// transmitted quicker, with only minimal latency increase for the ongoing transmission of the big
// packet.
// Note: We can't clone the underlying socket for each StreamSender and the mutex around the socket
// cannot be removed. This is because we need to make sure at least shards are written whole.

use crate::backend::{tcp, udp, SocketReader, SocketWriter};
use alvr_common::{
    anyhow::{anyhow, Result}, debug, parking_lot::Mutex, warn, error, AnyhowToCon, ConResult, HandleTryAgain, ToCon
};
use alvr_session::{DscpTos, SocketBufferSize, SocketProtocol};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    cmp::Ordering,
    collections::{ hash_map::Entry, HashMap, VecDeque},
    marker::PhantomData,
    mem,
    net::{IpAddr, TcpListener, UdpSocket},
    sync::{mpsc, Arc},
    time::Duration
};

const SHARD_PREFIX_SIZE: usize = mem::size_of::<u32>() // packet length - field itself (4 bytes)
    + mem::size_of::<u16>() // stream ID
    + mem::size_of::<u32>() // packet index
    + mem::size_of::<u32>() // shards count
    + mem::size_of::<u32>(); // shards index

/// Memory buffer that contains a hidden prefix
#[derive(Default)]
pub struct Buffer<H = ()> {
    inner: Vec<u8>,
    hidden_offset: usize, // this corresponds to prefix + header
    length: usize,
    _phantom: PhantomData<H>,
}

impl<H> Buffer<H> {
    /// Length of payload (without prefix)
    #[must_use]
    pub fn len(&self) -> usize {
        self.length
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the whole payload of the buffer
    pub fn get(&self) -> &[u8] {
        &self.inner[self.hidden_offset..][..self.length]
    }

    /// If the range is outside the valid range, new space will be allocated
    /// NB: the offset parameter is applied on top of the internal offset of the buffer
    pub fn get_range_mut(&mut self, offset: usize, size: usize) -> &mut [u8] {
        let required_size = self.hidden_offset + offset + size;
        if required_size > self.inner.len() {
            self.inner.resize(required_size, 0);
        }

        self.length = self.length.max(offset + size);

        &mut self.inner[self.hidden_offset + offset..][..size]
    }

    /// If length > current length, allocate more space
    pub fn set_len(&mut self, length: usize) {
        self.inner.resize(self.hidden_offset + length, 0);
        self.length = length;
    }
}

#[derive(Clone)]
pub struct StreamSender<H> {
    inner: Arc<Mutex<Box<dyn SocketWriter>>>,
    stream_id: u16,
    max_packet_size: usize,
    // if the packet index overflows the worst that happens is a false positive packet loss
    next_packet_index: u32,
    used_buffers: Vec<Vec<u8>>,
    _phantom: PhantomData<H>,
}

impl<H> StreamSender<H> {
    /// Shard and send a buffer with zero copies and zero allocations.
    /// The prefix of each shard is written over the previously sent shard to avoid reallocations.
    pub fn send(&mut self, mut buffer: Buffer<H>) -> Result<()> {
        let max_shard_data_size = self.max_packet_size - SHARD_PREFIX_SIZE;
        let actual_buffer_size = buffer.hidden_offset + buffer.length;
        let data_size = actual_buffer_size - SHARD_PREFIX_SIZE;
        let shards_count = (data_size as f32 / max_shard_data_size as f32).ceil() as usize;

        for idx in 0..shards_count {
            // this overlaps with the previous shard, this is intended behavior and allows to
            // reduce allocations
            let packet_start_position = idx * max_shard_data_size;
            let sub_buffer = &mut buffer.inner[packet_start_position..];

            // NB: true shard length (account for last shard that is smaller)
            let packet_length = usize::min(
                self.max_packet_size,
                actual_buffer_size - packet_start_position,
            );

            // todo: switch to little endian
            // todo: do not remove sizeof<u32> for packet length
            sub_buffer[0..4]
                .copy_from_slice(&((packet_length - mem::size_of::<u32>()) as u32).to_be_bytes());
            sub_buffer[4..6].copy_from_slice(&self.stream_id.to_be_bytes());
            sub_buffer[6..10].copy_from_slice(&self.next_packet_index.to_be_bytes());
            sub_buffer[10..14].copy_from_slice(&(shards_count as u32).to_be_bytes());
            sub_buffer[14..18].copy_from_slice(&(idx as u32).to_be_bytes());

            self.inner.lock().send(&sub_buffer[..packet_length])?;
        }

        self.next_packet_index += 1;

        self.used_buffers.push(buffer.inner);

        Ok(())
    }
}

impl<H: Serialize> StreamSender<H> {
    pub fn get_buffer(&mut self, header: &H) -> Result<Buffer<H>> {
        let mut buffer = self.used_buffers.pop().unwrap_or_default();

        let header_size = bincode::serialized_size(header)? as usize;
        let hidden_offset = SHARD_PREFIX_SIZE + header_size;

        if buffer.len() < hidden_offset {
            buffer.resize(hidden_offset, 0);
        }

        bincode::serialize_into(&mut buffer[SHARD_PREFIX_SIZE..hidden_offset], header)?;

        Ok(Buffer {
            inner: buffer,
            hidden_offset,
            length: 0,
            _phantom: PhantomData,
        })
    }

    pub fn send_header(&mut self, header: &H) -> Result<()> {
        let buffer = self.get_buffer(header)?;
        self.send(buffer)
    }
}

pub struct Shard {
    buffer: Vec<u8>,
    start_offset: usize,
    size: usize
}
impl Shard {
    pub fn data(&self) -> &[u8] {
        &self.buffer[self.start_offset..self.size]
    }
    pub fn skip(&mut self, size: usize) -> () {
        self.start_offset += size;
    }
    
    pub fn data_skip(&self, size: usize) -> &[u8] {
        &self.buffer[self.start_offset+size..self.size]
    }

    pub fn len(&self) -> usize {
        self.size-self.start_offset
    }
}


pub struct ReceiverData<H> {
    buffers: VecDeque<Shard>,
    used_buffers: Vec<Shard>, 
    used_buffer_queue: mpsc::Sender<Vec<u8>>,
    had_packet_loss: bool,
    _phantom: PhantomData<H>,
}

impl<H> ReceiverData<H> {
    pub fn had_packet_loss(&self) -> bool {
        self.had_packet_loss
    }
}

impl<H: DeserializeOwned> ReceiverData<H> {
    pub fn get_all(&self) -> Result<(H, Vec<u8>)> {
        let (header, front) = self.header()?;
        let mut shards = Vec::new();
        shards.push(front);
        shards.extend(self.buffers.iter().skip(1).map(|s| s.data()));
        Ok((header, shards.concat()))
    }

    pub fn extract_header(&mut self) -> Result<H> {
        let shard = self.buffers.front_mut().unwrap();
        let slice = shard.data();
        let header = bincode::deserialize_from(slice)?;
        shard.skip( shard.len()- slice.len());
        Ok(header)
    }

    pub fn get_shards(&self) -> Vec<&[u8]> {
        self.buffers.iter().map(|s| s.data()).collect()
    }
    

    pub fn header(&self) -> Result<(H, &[u8])> {
        match self.buffers.front() {
            Some(shard) => {
                let slice = shard.data();
                let header = bincode::deserialize_from(slice)?;
                Ok((header,shard.data_skip(shard.len()- slice.len())))
            }
            None => Err(anyhow!("test"))
        }        
    }

    pub fn get_header(&self) -> Result<H> {
        Ok(self.header()?.0)
    }

    pub fn len(&self) -> usize {
        self.buffers.len()
    }
}

impl<H> Drop for ReceiverData<H> {
    fn drop(&mut self) {
        while let Some(shard) = self.buffers.pop_front() {
            self.used_buffer_queue
            .send(shard.buffer)
            .ok();
        }
        while let Some(shard) =  self.used_buffers.pop() {
            self.used_buffer_queue
            .send(shard.buffer)
            .ok();
        }
    }
}

struct ReconstructedPacket {
    index: u32,
    buffers: VecDeque<Shard>
}

pub struct StreamReceiver<H> {
    packet_receiver: mpsc::Receiver<ReconstructedPacket>,
    used_buffer_queue: mpsc::Sender<Vec<u8>>,
    last_packet_index: Option<u32>,
    _phantom: PhantomData<H>,
}

fn wrapping_cmp(lhs: u32, rhs: u32) -> Ordering {
    let diff = lhs.wrapping_sub(rhs);
    if diff == 0 {
        Ordering::Equal
    } else if diff < u32::MAX / 2 {
        Ordering::Greater
    } else {
        // if diff > u32::MAX / 2, it means the sub operation wrapped
        Ordering::Less
    }
}

/// Get next packet reconstructing from shards.
/// Returns true if a packet has been recontructed and copied into the buffer.
impl<H: DeserializeOwned + Serialize> StreamReceiver<H> {
    pub fn recv(&mut self, timeout: Duration) -> ConResult<ReceiverData<H>> {
        let packet = self
            .packet_receiver
            .recv_timeout(timeout)
            .handle_try_again()?;

        let mut had_packet_loss = false;

        if let Some(last_idx) = self.last_packet_index {
            // Use wrapping arithmetics
            match wrapping_cmp(packet.index, last_idx.wrapping_add(1)) {
                Ordering::Equal => (),
                Ordering::Greater => {
                    // Skipped some indices
                    had_packet_loss = true
                }
                Ordering::Less => {
                    // Old packet, discard
                    let mut buffers = packet.buffers;
                    while let Some(shard) = buffers.pop_back() {
                        self.used_buffer_queue.send(shard.buffer).to_con()?;
                    }
                    return alvr_common::try_again();
                }
            }
        }
        self.last_packet_index = Some(packet.index);

        // info!("Got a packet {}", packet.buffers.len());
        Ok(ReceiverData {
            buffers: packet.buffers,
            used_buffers: vec![],
            used_buffer_queue: self.used_buffer_queue.clone(),
            had_packet_loss,
            _phantom: PhantomData,
        })
    }
}

pub enum StreamSocketBuilder {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

impl StreamSocketBuilder {
    pub fn listen_for_server(
        timeout: Duration,
        port: u16,
        stream_socket_config: SocketProtocol,
        stream_tos_config: Option<DscpTos>,
        send_buffer_bytes: SocketBufferSize,
        recv_buffer_bytes: SocketBufferSize,
    ) -> Result<Self> {
        Ok(match stream_socket_config {
            SocketProtocol::Udp => StreamSocketBuilder::Udp(udp::bind(
                port,
                stream_tos_config,
                send_buffer_bytes,
                recv_buffer_bytes,
            )?),
            SocketProtocol::Tcp => StreamSocketBuilder::Tcp(tcp::bind(
                timeout,
                port,
                stream_tos_config,
                send_buffer_bytes,
                recv_buffer_bytes,
            )?),
        })
    }

    pub fn accept_from_server(
        self,
        server_ip: IpAddr,
        port: u16,
        max_packet_size: usize,
        timeout: Duration,
    ) -> ConResult<StreamSocket> {
        let (send_socket, receive_socket): (Box<dyn SocketWriter>, Box<dyn SocketReader>) =
            match self {
                StreamSocketBuilder::Udp(socket) => {
                    let (send_socket, receive_socket) =
                        udp::connect(&socket, server_ip, port, timeout).to_con()?;

                    (Box::new(send_socket), Box::new(receive_socket))
                }
                StreamSocketBuilder::Tcp(listener) => {
                    let (send_socket, receive_socket) =
                        tcp::accept_from_server(&listener, Some(server_ip), timeout)?;

                    (Box::new(send_socket), Box::new(receive_socket))
                }
            };

        Ok(StreamSocket {
            // +4 is a workaround to retain compatibilty with old protocol
            // todo: remove +4
            max_packet_size: max_packet_size + 4,
            send_socket: Arc::new(Mutex::new(send_socket)),
            receive_socket,
            shard_recv_state: None,
            stream_recv_components: HashMap::new(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn connect_to_client(
        timeout: Duration,
        client_ip: IpAddr,
        port: u16,
        protocol: SocketProtocol,
        dscp: Option<DscpTos>,
        send_buffer_bytes: SocketBufferSize,
        recv_buffer_bytes: SocketBufferSize,
        max_packet_size: usize,
    ) -> ConResult<StreamSocket> {
        let (send_socket, receive_socket): (Box<dyn SocketWriter>, Box<dyn SocketReader>) =
            match protocol {
                SocketProtocol::Udp => {
                    let socket =
                        udp::bind(port, dscp, send_buffer_bytes, recv_buffer_bytes).to_con()?;
                    let (send_socket, receive_socket) =
                        udp::connect(&socket, client_ip, port, timeout).to_con()?;

                    (Box::new(send_socket), Box::new(receive_socket))
                }
                SocketProtocol::Tcp => {
                    let (send_socket, receive_socket) = tcp::connect_to_client(
                        timeout,
                        &[client_ip],
                        port,
                        send_buffer_bytes,
                        recv_buffer_bytes,
                    )?;

                    (Box::new(send_socket), Box::new(receive_socket))
                }
            };

        Ok(StreamSocket {
            // +4 is a workaround to retain compatibilty with old protocol
            // todo: remove +4
            max_packet_size: max_packet_size + 4,
            send_socket: Arc::new(Mutex::new(send_socket)),
            receive_socket,
            shard_recv_state: None,
            stream_recv_components: HashMap::new(),
        })
    }
}

struct RecvState {
    shard_length: usize, // contains prefix length itself
    stream_id: u16,
    packet_index: u32,
    shards_count: usize,
    shard_index: usize,
    should_discard: bool,
}

struct InProgressPacket {
    buffers: HashMap<usize,Shard>
}

struct StreamRecvComponents {
    used_buffer_sender: mpsc::Sender<Vec<u8>>,
    used_buffer_receiver: mpsc::Receiver<Vec<u8>>,
    packet_queue: mpsc::Sender<ReconstructedPacket>,
    in_progress_packets: HashMap<u32, InProgressPacket>,
}

// Note: used buffers don't *have* to be split by stream ID, but doing so improves memory usage
// todo: impose cap on number of created buffers to avoid OOM crashes
pub struct StreamSocket {
    max_packet_size: usize,
    send_socket: Arc<Mutex<Box<dyn SocketWriter>>>,
    receive_socket: Box<dyn SocketReader>,
    shard_recv_state: Option<RecvState>,
    stream_recv_components: HashMap<u16, StreamRecvComponents>,
}

impl StreamSocket {
    pub fn request_stream<T>(&self, stream_id: u16) -> StreamSender<T> {
        StreamSender {
            inner: Arc::clone(&self.send_socket),
            stream_id,
            max_packet_size: self.max_packet_size,
            next_packet_index: 0,
            used_buffers: vec![],
            _phantom: PhantomData,
        }
    }

    // max_concurrent_buffers: number of buffers allocated by this call which will be reused to
    // receive packets for this stream ID. If packets are not read fast enough, the shards received
    // for this particular stream will be discarded
    pub fn subscribe_to_stream<T>(
        &mut self,
        stream_id: u16,
        max_concurrent_buffers: usize,
    ) -> StreamReceiver<T> {
        let (packet_sender, packet_receiver) = mpsc::channel();
        let (used_buffer_sender, used_buffer_receiver) = mpsc::channel();

        self.stream_recv_components.insert(
            stream_id,
            StreamRecvComponents {
                used_buffer_sender: used_buffer_sender.clone(),
                used_buffer_receiver,
                packet_queue: packet_sender,
                in_progress_packets: HashMap::new(),
            },
        );

        StreamReceiver {
            packet_receiver,
            used_buffer_queue: used_buffer_sender,
            _phantom: PhantomData,
            last_packet_index: None,
        }
    }

    pub fn recv(&mut self) -> ConResult {
        let shard_recv_state_mut = if let Some(state) = &mut self.shard_recv_state {
            state
        } else {
            let mut bytes = [0; SHARD_PREFIX_SIZE];
            let count = self.receive_socket.peek(&mut bytes)?;
            if count < SHARD_PREFIX_SIZE {
                return alvr_common::try_again();
            }

            // todo: switch to little endian
            // todo: do not remove sizeof<u32> for packet length
            let shard_length = mem::size_of::<u32>()
                + u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
            let stream_id = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
            let packet_index = u32::from_be_bytes(bytes[6..10].try_into().unwrap());
            let shards_count = u32::from_be_bytes(bytes[10..14].try_into().unwrap()) as usize;
            let shard_index = u32::from_be_bytes(bytes[14..18].try_into().unwrap()) as usize;

            self.shard_recv_state.insert(RecvState {
                shard_length,
                stream_id,
                packet_index,
                shards_count,
                shard_index,
                should_discard: false,
            })
        };

        let Some(components) = self
            .stream_recv_components
            .get_mut(&shard_recv_state_mut.stream_id)
        else {
            debug!(
                "Received packet from stream {} before subscribing!",
                shard_recv_state_mut.stream_id
            );
            return alvr_common::try_again();
        };

        let mut available_shards = 0;
          // Keep only shards with later packet index (using wrapping logic)
         while let Some((idx, _)) = components.in_progress_packets.iter().find(|(idx, _)| {
            wrapping_cmp(**idx, shard_recv_state_mut.packet_index) == Ordering::Less
        }) {
            let idx = *idx; // fix borrow rule
            let packet = components.in_progress_packets.remove(&idx).unwrap();
            let mut values = packet.buffers.into_values().collect::<Vec<Shard>>();
            while let Some(shard) =  values.pop() {
                components.used_buffer_sender.send(shard.buffer).ok();
                available_shards +=1;
            }
        }
        //alocate
        if available_shards == 0 {
            components.used_buffer_sender.send(vec![]).ok();
        }

        let Some(mut buffer) = components.used_buffer_receiver.try_recv().ok()
         else {
            error!("Couldnt get buffer");
            return alvr_common::try_again();
        };

        let in_progress_packets = &mut components.in_progress_packets;

        let in_progress_packet = match in_progress_packets
            .entry(shard_recv_state_mut.packet_index)
        {
            Entry::Occupied(entry) => { 
                entry.into_mut() 
            }
            Entry::Vacant(entry) =>  { entry.insert(
                InProgressPacket {
                    buffers: HashMap::<usize, Shard>::with_capacity( shard_recv_state_mut.shards_count),
                })
            }
        };    
        buffer.resize(shard_recv_state_mut.shard_length, 0);


        // This loop may bail out at any time if a timeout is reached. 
        let mut cursor = 0;
        while cursor < shard_recv_state_mut.shard_length {
            match self.receive_socket.recv(&mut buffer[cursor..shard_recv_state_mut.shard_length]) {
                Ok(v) => {
                    cursor += v
                } 
                Err(e) => {
                    warn!("recycle");
                    components.used_buffer_sender.send(buffer).ok();
                    return Err(e)}
            }
        }

        
        if !shard_recv_state_mut.should_discard {
                in_progress_packet.buffers.insert(shard_recv_state_mut.shard_index, Shard {
                buffer,
                start_offset: SHARD_PREFIX_SIZE,
                size: shard_recv_state_mut.shard_length
            });
        } else {
            components.used_buffer_sender.send(buffer).ok();
        }

        // Check if packet is complete and send
        if in_progress_packet.buffers.len() == shard_recv_state_mut.shards_count {

            let mut opt_packet = 
                in_progress_packets
                .remove(&shard_recv_state_mut.packet_index);

            let finalized_packet = opt_packet.as_mut().unwrap();
        
            
            let total = finalized_packet.buffers.len();
            let mut shards: VecDeque<Shard> = VecDeque::<Shard>::with_capacity(finalized_packet.buffers.len());    
    

            for i in 0..total {
                // warn!("pushing {}", i);
                shards.push_back(finalized_packet.buffers.remove(&i).unwrap());
            }

            components
                .packet_queue
                .send(ReconstructedPacket {
                    index: shard_recv_state_mut.packet_index,
                    buffers: shards
                })
                .ok();
        }

        // Mark current shard as read and allow for a new shard to be read
        self.shard_recv_state = None;

        Ok(())
    }
}
