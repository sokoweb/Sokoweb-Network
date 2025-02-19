# node.py
import asyncio
import socket
import logging
import hashlib
import os
import json
import uuid
import time

from .routing_table import RoutingTable
from .messages import Message, StoreMessage
from .utils import generate_node_id
from .crypto import generate_key_pair, sign_message, verify_signature, serialize_public_key, derive_key, decrypt_data, encrypt_data
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from .product import Product
from .credit_manager import CreditManager
from .remote_node import RemoteNode
from .storage_messages import StorageMessage

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s: %(message)s')
logger = logging.getLogger(__name__)

MAX_UDP_PAYLOAD_SIZE = 1024
MAX_VALUE_SIZE = 512

class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, node):
        self.node = node
        self.transport = None
        self.port = None
        self.logger = logging.getLogger(__name__)
        self.message_queue = asyncio.Queue()
        self.processing = False
        self.tasks = set()

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        except (AttributeError, socket.error) as e:
            self.logger.warning(f"Could not set socket buffer size: {e}")

        sockname = transport.get_extra_info("sockname")
        self.port = sockname[1]
        self.node.transport = transport

        self.logger.info(
            f"UDP server started on {self.node.bind_ip}:{self.node.port} "
            f"(advertising as {self.node.advertise_ip}:{self.node.port})"
        )

        asyncio.create_task(self.process_messages())

    async def process_messages(self):
        self.processing = True
        while self.processing:
            try:
                data, addr = await self.message_queue.get()
                if data is None and addr is None:
                    # Sentinel to stop processing
                    break
                task = asyncio.create_task(self.node.handle_incoming_data(data, addr))
                self.tasks.add(task)
                task.add_done_callback(self.tasks.discard)
                self.message_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in message processing loop: {e}", exc_info=True)

    def datagram_received(self, data, addr):
        try:
            asyncio.create_task(self.message_queue.put((data, addr)))
            self.logger.debug(f"Queued message from {addr} for processing")
        except Exception as e:
            self.logger.error(f"Error queueing message from {addr}: {e}", exc_info=True)

    def error_received(self, exc):
        self.logger.error(f"UDP Protocol error: {exc}", exc_info=True)

    def connection_lost(self, exc):
        self.processing = False
        if exc:
            self.logger.error(f"UDP connection lost due to error: {exc}", exc_info=True)
        else:
            self.logger.info("UDP connection closed normally")

    async def shutdown(self):
        self.processing = False
        await self.message_queue.put((None, None))
        await self.message_queue.join()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)

class Node:
    def __init__(
        self,
        ip,
        port,
        key_pair=None,
        node_id=None,
        advertise_ip=None,
        alpha=1,
        k=3,
        credit_manager=None,
    ):
        self._init_basic_config(ip, port, advertise_ip)
        self._init_protocol_params(alpha, k)
        self._init_runtime_components()
        self._init_data_structures()
        self._init_background_tasks()
        self._init_local_crypto(key_pair, node_id)

        self.routing_table = RoutingTable(self.node_id, k=self.k)
        self.logger.info(
            f"Initialized local node {self.node_id} advertising as {self.advertise_ip}:{self.port}"
        )

    def _init_basic_config(self, ip, port, advertise_ip):
        self.ip = ip
        self.port = port
        self.advertise_ip = advertise_ip or ip
        ### CHANGED: We consistently store the bind IP separately
        self.bind_ip = ip
        self.logger = logger

    def _init_protocol_params(self, alpha, k):
        self.alpha = alpha
        self.k = k
        self.request_timeout = 30.0
        self.max_store_attempts = 3

    def _init_runtime_components(self):
        self.loop = asyncio.get_event_loop()
        self.transport = None
        self.protocol = None

    def _init_data_structures(self):
        self.data_store = {}
        self.data_store_lock = asyncio.Lock()
        self.pending_requests = {}
        self.pending_requests_lock = asyncio.Lock()
        self.send_lock = asyncio.Lock()

    def _init_background_tasks(self):
        self.cleanup_task = None
        self.republishing_task = None
        self.maintenance_task = None
        self.pending_requests_cleanup_task = None

    def _init_local_crypto(self, key_pair, node_id):
        if key_pair is not None:
            self.private_key, self.public_key = key_pair
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()

        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.node_id = node_id or hashlib.sha1(self.public_key_bytes).hexdigest()

        if self.node_id is None:
            self.logger.error("self.node_id is None after initialization")

    def __eq__(self, other):
        if isinstance(other, Node):
            return self.node_id == other.node_id
        return False

    def __hash__(self):
        return hash(self.node_id)

    async def start(self, bootstrap_nodes=None):
        self.logger.info(f"Starting node {self.node_id}")
        sock = None
        if self.loop is None:
            self.loop = asyncio.get_running_loop()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            sock.bind((self.bind_ip, self.port))

            transport, protocol = await self.loop.create_datagram_endpoint(
                lambda: UDPProtocol(self), sock=sock
            )

            self.transport = transport
            self.protocol = protocol

            if self.port == 0:
                self.port = self.transport.get_extra_info("socket").getsockname()[1]

            self.logger.info(
                f"UDP server started on {self.bind_ip}:{self.port} "
                f"(advertising as {self.advertise_ip}:{self.port})"
            )

            common_categories = ["Electronics", "Books", "Clothing", "Home & Kitchen"]
            await self.initialize_categories(common_categories)

            self.cleanup_task = asyncio.create_task(self.start_cleanup_task())
            self.republishing_task = asyncio.create_task(self.start_republishing_task())
            self.maintenance_task = asyncio.create_task(self.start_routing_table_maintenance())
            self.pending_requests_cleanup_task = asyncio.create_task(self.start_pending_requests_cleanup())

            if bootstrap_nodes:
                await self.bootstrap(bootstrap_nodes)
                self.logger.info(f"Bootstrapped with nodes: {bootstrap_nodes}")
            else:
                self.logger.info("No bootstrap nodes provided.")

            await self.find_nodes(self.node_id)
            self.logger.info(f"Performed FIND_NODE for own node_id {self.node_id}")

        except Exception as e:
            self.logger.error(f"Error starting node: {e}", exc_info=True)
            if sock:
                sock.close()
            raise

    async def stop(self):
        if self.transport:
            self.transport.close()
            self.logger.info(
                f"Node {self.node_id} at {self.advertise_ip}:{self.port} stopped"
            )

        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
            self.logger.info(f"Node {self.node_id}: Cleanup task stopped")

        if self.republishing_task:
            self.republishing_task.cancel()
            try:
                await self.republishing_task
            except asyncio.CancelledError:
                pass
            self.logger.info(f"Node {self.node_id}: Republishing task stopped")

        if self.maintenance_task:
            self.maintenance_task.cancel()
            try:
                await self.maintenance_task
            except asyncio.CancelledError:
                pass
            self.logger.info(f"Node {self.node_id}: Routing table maintenance task stopped")

        if self.pending_requests_cleanup_task:
            self.pending_requests_cleanup_task.cancel()
            try:
                await self.pending_requests_cleanup_task
            except asyncio.CancelledError:
                pass
            self.logger.info(f"Node {self.node_id}: Pending requests cleanup task stopped")

    async def handle_incoming_data(self, data, addr):
        try:
            message_json = data.decode("utf-8")
            if any(
                msg_type in message_json
                for msg_type in [
                    '"message_type": "STORE_CHUNK"',
                    '"message_type": "RETRIEVE_CHUNK"',
                    '"message_type": "CHUNK_RESPONSE"',
                    '"message_type": "STORE_SUB_CHUNK"',
                ]
            ):
                message = StorageMessage.from_json(message_json)
                await self.handle_storage_message(message, addr)
            else:
                message = Message.from_json(message_json)
                await self.handle_message(message, addr)
        except Exception as e:
            logger.error(f"Error handling data from {addr}: {e}")
            logger.debug(f"Data received: {data}")

    async def handle_message(self, message, addr):
        """
        Process incoming Message or StorageMessage from 'addr' (ip, port).
        We only match requests by request_id, ignoring IP/port mismatches.
        """
        try:
            request_id = message.data.get("request_id")
            self.logger.debug(
                f"{self.node_id}: Received {message.message_type} from {addr} "
                f"with request_id {request_id}"
            )

            # If this is a response (message_type ends with "_RESPONSE"):
            if request_id and message.message_type.endswith("_RESPONSE"):
                async with self.pending_requests_lock:
                    if request_id in self.pending_requests:
                        future, _ = self.pending_requests[request_id]
                        if not future.done():
                            future.set_result(message)
                        self.pending_requests.pop(request_id, None)
                    else:
                        # CHANGED: We'll just log debug instead of warning
                        self.logger.debug(
                            f"{self.node_id}: Response with unknown request_id={request_id} "
                            f"arrived from {addr}. Possibly NAT re-mapping or stale request."
                        )
                return  # We can stop here once we've set the future

            # Otherwise, if it's not a response, we handle the request
            if isinstance(message, StorageMessage):
                # handle_storage_message is where e.g. STORE_CHUNK, RETRIEVE_CHUNK, etc. go
                await self.handle_storage_message(message, addr)
                return

            # Extract or update sender node in routing table
            sender_id = message.sender_id
            if sender_id:
                # For the sender's IP, we always store "advertise_ip" in their node.
                # If you want, you can store the real 'addr[0]' or pass it along.
                # We'll keep it simpler: use the 'advertise_ip' from message's data if available
                # or fallback to the newly discovered 'addr'.
                sender_ip = message.data.get("sender_ip") or addr[0]
                sender_port = message.data.get("sender_port") or addr[1]
                sender_tcp_port = message.data.get("tcp_port") or sender_port

                # Attempt to find or create a RemoteNode
                existing_node = self.routing_table.get_node_by_id(sender_id)
                if existing_node:
                    existing_node.ip = sender_ip
                    existing_node.port = sender_port
                    existing_node.tcp_port = sender_tcp_port
                else:
                    new_node = RemoteNode(
                        ip=sender_ip,
                        port=sender_port,
                        tcp_port=sender_tcp_port,
                        node_id=sender_id,
                        public_key_bytes=bytes.fromhex(message.public_key)
                        if message.public_key else None
                    )
                    await self.routing_table.add_node(new_node)

            # Now handle the message types:
            if message.message_type == "PING":
                await self.handle_ping(message, addr)
            elif message.message_type == "STORE":
                await self.handle_store(message, addr)
            elif message.message_type == "FIND_NODE":
                await self.handle_find_node(message, addr)
            elif message.message_type == "FIND_VALUE":
                await self.handle_find_value(message, addr)
            elif message.message_type == "SUGGEST_CATEGORY":
                await self.handle_suggest_category(message, addr)
            elif message.message_type == "CATEGORY_APPROVAL":
                await self.handle_category_approval(message, addr)
            else:
                self.logger.warning(
                    f"{self.node_id}: Unknown or unhandled message type '{message.message_type}' from {addr}"
                )

        except Exception as e:
            # If anything goes wrong, log the error
            self.logger.error(
                f"{self.node_id}: Error handling message from {addr}: {e}", 
                exc_info=True
            )

    async def handle_ping(self, message, addr):
        try:
            self.logger.debug(f"{self.node_id}: Received PING from {addr}")
            request_id = message.data.get("request_id")
            if not request_id:
                self.logger.warning(
                    f"{self.node_id}: Received PING without request_id from {addr}"
                )
                return
            response_data = {
                "request_id": request_id,
                "sender_ip": self.advertise_ip,
                "sender_port": self.port,
            }
            response_message = self.create_message("PING_RESPONSE", response_data)
            await self.send_message(response_message, addr)
            self.logger.debug(f"{self.node_id}: Sent PING_RESPONSE to {addr}")
        except Exception as e:
            self.logger.error(f"{self.node_id}: Error handling PING from {addr}: {e}")

    async def ping_node(self, node):
        if node.is_unresponsive:
            self.logger.warning(
                f"{self.node_id}: Skipping ping to unresponsive node {node.ip}:{node.port}"
            )
            return False

        try:
            request_id = str(uuid.uuid4())
            ping_message = self.create_message("PING", data={"request_id": request_id})

            self.logger.debug(f"{self.node_id}: Pinging node at {node.ip}:{node.port}")
            response = await self.send_message_and_wait_for_response(
                ping_message, (node.ip, node.port), timeout=self.request_timeout
            )

            if response and response.message_type == "PING_RESPONSE":
                node.unresponsive_count = 0
                self.logger.debug(
                    f"{self.node_id}: Node at {node.ip}:{node.port} is responsive"
                )
                if response.sender_id is None:
                    self.logger.error(
                        f"{self.node_id}: Received PING_RESPONSE without sender_id from {node.ip}:{node.port}"
                    )
                    return False
                node.node_id = response.sender_id
                if not node.public_key_bytes and response.public_key:
                    node.public_key_bytes = bytes.fromhex(response.public_key)
                    node._setup_public_key()

                if self.routing_table and node.node_id:
                    await self.routing_table.add_node(node)
                return True
            else:
                node.unresponsive_count = getattr(node, 'unresponsive_count', 0) + 1
                self.logger.debug(
                    f"{self.node_id}: Node {node.node_id} unresponsive_count: {node.unresponsive_count}"
                )
                self.logger.warning(
                    f"{self.node_id}: Failed to receive PING_RESPONSE from {node.ip}:{node.port}"
                )
                return False
        except Exception as e:
            node.unresponsive_count = getattr(node, 'unresponsive_count', 0) + 1
            self.logger.debug(
                f"{self.node_id}: Node {node.node_id} unresponsive_count: {node.unresponsive_count}"
            )
            self.logger.error(
                f"{self.node_id}: Error pinging node {node.ip}:{node.port}: {e}",
                exc_info=True,
            )
            return False

    async def handle_store(self, message, addr):
        self.logger.debug(f"{self.node_id}: Received STORE request from {addr}")
        key = message.data.get("key")
        value = message.data.get("value")
        ttl = message.data.get("ttl")
        if key and value:
            expiration_time = time.time() + ttl if ttl else time.time() + 604800
            async with self.data_store_lock:
                self.data_store[key] = (value, expiration_time)
                self.logger.debug(
                    f"{self.node_id}: Stored key '{key}' with expiration at {expiration_time}"
                )
            response_data = {
                "request_id": message.data.get("request_id")
            }
            response_message = self.create_message("STORE_RESPONSE", response_data)
            await self.send_message(response_message, addr)
        else:
            self.logger.warning(f"{self.node_id}: Invalid STORE message from {addr}")

    async def handle_store_response(self, message, addr):
        self.logger.debug(f"{self.node_id}: Received STORE_RESPONSE from {addr}")
        await self._process_response(message)

    async def _process_response(self, message):
        request_id = message.data.get("request_id")
        if request_id:
            async with self.pending_requests_lock:
                future_entry = self.pending_requests.get(request_id)
                if future_entry:
                    future, _ = future_entry
                    if not future.done():
                        future.set_result(message)
                    self.pending_requests.pop(request_id, None)
        else:
            self.logger.warning(f"{self.node_id}: Received response without request_id")

    async def start_cleanup_task(self, interval=60):
        while True:
            try:
                await asyncio.sleep(interval)
                await self.cleanup_expired_entries()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Node {self.node_id}: Error in cleanup task: {e}")

    async def cleanup_expired_entries(self):
        current_time = time.time()
        keys_to_delete = []
        for key, (value, expiration_time) in self.data_store.items():
            if current_time >= expiration_time:
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del self.data_store[key]
            logger.debug(f"{self.node_id}: Removed expired key '{key}'")

    async def start_republishing_task(self, interval=3600):
        while True:
            try:
                await asyncio.sleep(interval)
                logger.info(f"Node {self.node_id}: Republishing stored values")
                await self.republish_values()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Node {self.node_id}: Error in republishing task: {e}")

    async def republish_values(self):
        current_time = time.time()
        for key, (value, expiration_time) in self.data_store.items():
            if current_time < expiration_time:
                ttl = expiration_time - current_time
                try:
                    await self.store_value(key, value, ttl)
                except Exception as e:
                    logger.error(
                        f"Node {self.node_id}: Failed to republish key '{key}': {e}"
                    )

    async def start_routing_table_maintenance(self, interval=10):
        while True:
            try:
                await asyncio.sleep(interval)
                await self.routing_table_maintenance()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    f"Node {self.node_id}: Error in routing table maintenance: {e}"
                )

    async def start_pending_requests_cleanup(self, interval=60, request_timeout=60):
        while True:
            try:
                await asyncio.sleep(interval)
                current_time = time.time()
                async with self.pending_requests_lock:
                    expired_requests = [
                        request_id
                        for request_id, (future, timestamp) in self.pending_requests.items()
                        if current_time - timestamp > request_timeout
                    ]
                    for rid in expired_requests:
                        fut, _ = self.pending_requests.pop(rid)
                        if not fut.done():
                            fut.set_exception(asyncio.TimeoutError())
                        self.logger.debug(
                            f"{self.node_id}: Cleaned up expired pending request {rid}"
                        )
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(
                    f"{self.node_id}: Error in pending requests cleanup task: {e}"
                )

    async def send_message_and_wait_for_response(self, message, addr, timeout=30):
        request_id = message.data.get("request_id")
        if not request_id:
            request_id = str(uuid.uuid4())
            message.data["request_id"] = request_id

        future = self.loop.create_future()
        timestamp = time.time()

        try:
            async with self.pending_requests_lock:
                self.pending_requests[request_id] = (future, timestamp)

            success = await self.send_message(message, addr)
            if not success:
                self.logger.warning(f"{self.node_id}: Failed to send message to {addr}")
                return None

            try:
                response = await asyncio.wait_for(future, timeout)
                self.logger.debug(
                    f"{self.node_id}: Received response for request {request_id} from {addr}"
                )
                return response
            except asyncio.TimeoutError:
                self.logger.warning(
                    f"{self.node_id}: Request {request_id} to {addr} timed out"
                )
                return None
        finally:
            async with self.pending_requests_lock:
                self.pending_requests.pop(request_id, None)

    async def send_message(self, message, addr):
        try:
            message_json = message.to_json().encode("utf-8")
            self.logger.debug(
                f"{self.node_id}: Preparing {message.message_type} of size {len(message_json)} bytes to {addr}"
            )
            if len(message_json) > MAX_UDP_PAYLOAD_SIZE:
                if message.message_type == "STORE":
                    self.logger.error(
                        f"{self.node_id}: 'STORE' message too large "
                        f"({len(message_json)} bytes) for UDP. Aborting."
                    )
                    return False
                return await self.send_message_tcp(message, addr)

            ip_addr = await self.resolve_address(addr, sock_type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
            if not ip_addr:
                self.logger.error(f"{self.node_id}: Could not resolve address {addr}")
                return False

            async with self.send_lock:
                self.transport.sendto(message_json, ip_addr)
                self.logger.debug(
                    f"{self.node_id}: Successfully sent {message.message_type} to {ip_addr} via UDP"
                )
            return True
        except Exception as e:
            self.logger.error(
                f"{self.node_id}: Error sending message to {addr}: {e}",
                exc_info=True
            )
            return False

    async def send_message_tcp(self, message, addr):
        try:
            message_json = message.to_json().encode("utf-8")
            ip_addr = await self.resolve_address(addr, sock_type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            if not ip_addr:
                self.logger.error(f"{self.node_id}: Could not resolve address {addr}")
                return False

            node = self.routing_table.get_node_by_address(addr)
            if node:
                tcp_port = node.tcp_port
            else:
                tcp_port = self.tcp_port

            self.logger.debug(
                f"{self.node_id}: Sending {message.message_type} to {ip_addr} via TCP on port {tcp_port} with request_id {message.data.get('request_id')}"
            )

            reader, writer = await asyncio.open_connection(ip_addr[0], tcp_port)

            message_length = len(message_json)
            writer.write(message_length.to_bytes(4, byteorder="big") + message_json)
            await writer.drain()

            data = await reader.readexactly(4)
            response_length = int.from_bytes(data, byteorder="big")
            response_data = await reader.readexactly(response_length)
            response = json.loads(response_data.decode("utf-8"))

            if response.get("status") != "OK":
                self.logger.error(
                    f"{self.node_id}: Failed to send message over TCP to {ip_addr}: {response.get('message')}"
                )
                return False

            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionResetError:
                self.logger.warning(
                    f"Connection reset by peer when closing the connection to {addr}"
                )

            self.logger.debug(
                f"{self.node_id}: Successfully sent {message.message_type} to {ip_addr} via TCP"
            )
            return True

        except Exception as e:
            self.logger.error(
                f"{self.node_id}: Error sending message over TCP to {addr}: {e}",
                exc_info=True,
            )
            return False

    async def resolve_address(self, addr, sock_type=None, proto=None):
        host, port = addr
        loop = asyncio.get_event_loop()
        try:
            infos = await loop.getaddrinfo(
                host,
                port,
                family=socket.AF_INET,
                type=sock_type,
                proto=proto,
            )
            ip = infos[0][4][0]
            return (ip, port)
        except Exception as e:
            self.logger.error(f"{self.node_id}: Failed to resolve hostname {host}: {e}")
            return None

    async def routing_table_maintenance(self):
        nodes_to_remove = []
        all_nodes = self.routing_table.get_all_nodes()
        for node in all_nodes:
            is_responsive = await self.ping_node(node)
            if not is_responsive:
                node.unresponsive_count = getattr(node, "unresponsive_count", 0) + 1
                if node.unresponsive_count >= 3:
                    nodes_to_remove.append(node)
        for n in nodes_to_remove:
            await self.routing_table.remove_node(n)
            logger.info(
                f"Node {self.node_id}: Removed unresponsive node {n.node_id} from routing table"
            )

    async def store_value(self, key, value, ttl=604800):
        try:
            expiration_time = time.time() + ttl
            self.logger.debug(
                f"{self.node_id}: Start storing value for key '{key}' with TTL {ttl}"
            )
            if isinstance(value, str):
                value_size = len(value.encode('utf-8'))
            elif isinstance(value, bytes):
                value_size = len(value)
            else:
                value_size = len(json.dumps(value).encode('utf-8'))

            if value_size > MAX_VALUE_SIZE:
                self.logger.debug(
                    f"{self.node_id}: Value for key '{key}' is large ({value_size} bytes), storing using storage service"
                )
                if isinstance(value, str):
                    value_bytes = value.encode('utf-8')
                elif isinstance(value, bytes):
                    value_bytes = value
                else:
                    value_bytes = json.dumps(value).encode('utf-8')

                value_hash = hashlib.sha1(value_bytes).hexdigest()
                await self.storage_service.store_file(value_hash, value_bytes)
                value_ref = {"type": "storage_ref", "hash": value_hash}
                value = json.dumps(value_ref)

            async with self.data_store_lock:
                self.data_store[key] = (value, expiration_time)

            self.logger.debug(f"{self.node_id}: Finding closest nodes to store key '{key}'")
            closest_nodes = await self.find_nodes(key)

            if not closest_nodes:
                self.logger.warning(
                    f"{self.node_id}: No close nodes found to store key '{key}'"
                )
                return

            store_tasks = []
            for n in closest_nodes:
                store_tasks.append(self.send_store(n, key, value, ttl))

            store_results = await asyncio.gather(*store_tasks, return_exceptions=True)

            for idx, result in enumerate(store_results):
                node = closest_nodes[idx]
                if isinstance(result, Exception):
                    self.logger.error(
                        f"{self.node_id}: Error sending STORE to node {node.node_id} for key '{key}': {result}"
                    )
                else:
                    self.logger.debug(
                        f"{self.node_id}: Successfully sent STORE to node {node.node_id} for key '{key}'"
                    )
        except Exception as e:
            self.logger.error(
                f"{self.node_id}: Exception in store_value: {e}", exc_info=True
            )

    async def send_store(self, target_node, key, value, ttl):
        self.logger.debug(
            f"{self.node_id}: Sending STORE to {target_node.node_id} with key '{key}' and TTL {ttl}"
        )
        store_message = self.create_message(
            message_type="STORE",
            data={"key": key, "value": value, "ttl": ttl, "request_id": str(uuid.uuid4())},
        )
        await self.send_message(store_message, (target_node.ip, target_node.port))

    async def handle_find_node_response(self, message, addr):
        self.logger.debug(f"{self.node_id}: Received FIND_NODE_RESPONSE from {addr}")
        await self._process_response(message)

    async def find_value(self, key):
        try:
            async with self.data_store_lock:
                if key in self.data_store:
                    value, expiration_time = self.data_store[key]
                    if time.time() < expiration_time:
                        self.logger.debug(
                            f"{self.node_id}: Found value for key '{key}' locally"
                        )
                        if self.is_storage_reference(value):
                            self.logger.debug(
                                f"{self.node_id}: Value for key '{key}' is a storage reference, retrieving actual value"
                            )
                            value = await self.retrieve_from_storage_reference(value)
                        return value
                    else:
                        del self.data_store[key]
                        self.logger.debug(
                            f"{self.node_id}: Local value for key '{key}' expired"
                        )

            self.logger.debug(f"{self.node_id}: Initiating FIND_VALUE for key '{key}'")

            k = self.routing_table.k
            alpha = self.alpha
            shortlist = self.routing_table.find_closest_nodes(key, k=k)

            self.logger.debug(
                f"{self.node_id}: Initial shortlist for '{key}' has {len(shortlist)} nodes"
            )
            contacted_nodes = set()
            closest_node_id = None

            while True:
                candidates = [node for node in shortlist if node not in contacted_nodes]
                to_query = candidates[:alpha]
                if not to_query:
                    self.logger.debug(f"{self.node_id}: No more nodes to query for '{key}'")
                    break

                tasks = []
                for node in to_query:
                    contacted_nodes.add(node)
                    tasks.append(self.send_find_value(node, key))

                responses = await asyncio.gather(*tasks, return_exceptions=True)

                found_value = None
                new_nodes = []
                for idx, response in enumerate(responses):
                    node = to_query[idx]
                    if isinstance(response, Exception):
                        self.logger.error(
                            f"{self.node_id}: Error during FIND_VALUE to {node.node_id} for key '{key}': {response}",
                            exc_info=True
                        )
                        continue
                    if not response:
                        continue
                    if response.message_type == "FIND_VALUE_RESPONSE" and "value" in response.data:
                        found_value = response.data["value"]
                        if self.is_storage_reference(found_value):
                            found_value = await self.retrieve_from_storage_reference(found_value)
                        async with self.data_store_lock:
                            self.data_store[key] = (found_value, time.time() + 3600)
                        return found_value
                    elif response.message_type == "FIND_VALUE_RESPONSE" and "nodes" in response.data:
                        nodes_info = response.data["nodes"]
                        for ni in nodes_info:
                            try:
                                node_id = ni["node_id"]
                                ip = ni["ip"]
                                port = ni["port"]
                                tcp_port = ni.get("tcp_port", port)
                                pk_bytes = bytes.fromhex(ni.get("public_key", ""))
                                n = RemoteNode(
                                    ip=ip,
                                    port=port,
                                    tcp_port=tcp_port,
                                    node_id=node_id,
                                    public_key_bytes=pk_bytes
                                )
                                if n not in contacted_nodes and n not in shortlist:
                                    new_nodes.append(n)
                                    await self.routing_table.add_node(n)
                            except Exception as e:
                                self.logger.error(
                                    f"{self.node_id}: Error processing node info in FIND_VALUE for key '{key}': {e}",
                                    exc_info=True
                                )

                shortlist.extend(new_nodes)
                shortlist = sorted(
                    set(shortlist),
                    key=lambda n: int(n.node_id, 16) ^ int(key, 16)
                )[:k]

                new_closest_node_id = shortlist[0].node_id if shortlist else None
                if new_closest_node_id == closest_node_id:
                    self.logger.debug(
                        f"{self.node_id}: Closest node unchanged during FIND_VALUE for '{key}'"
                    )
                    break
                closest_node_id = new_closest_node_id

                if all(n in contacted_nodes for n in shortlist):
                    break

            self.logger.warning(f"{self.node_id}: Value '{key}' not found")
            return None
        except Exception as e:
            self.logger.error(f"{self.node_id}: Error in find_value: {e}", exc_info=True)
            return None

    def is_storage_reference(self, value):
        try:
            data = json.loads(value)
            return isinstance(data, dict) and data.get("type") == "storage_ref"
        except:
            return False

    async def retrieve_from_storage_reference(self, value):
        try:
            data = json.loads(value)
            if data.get("type") == "storage_ref":
                value_hash = data.get("hash")
                self.logger.debug(
                    f"{self.node_id}: Attempting to retrieve from storage service with hash '{value_hash}'"
                )
                value_bytes = await self.storage_service.retrieve_file_from_network(value_hash)
                if value_bytes:
                    return value_bytes.decode('utf-8')
                self.logger.warning(
                    f"{self.node_id}: Failed to retrieve from storage service with hash '{value_hash}'"
                )
                return None
            return value
        except Exception as e:
            self.logger.error(
                f"{self.node_id}: Error retrieving from storage reference: {e}",
                exc_info=True
            )
            return None

    async def send_find_value(self, node, key):
        message = self.create_message(
            message_type="FIND_VALUE",
            data={"key": key, "request_id": str(uuid.uuid4())},
        )
        response = await self.send_message_and_wait_for_response(
            message, (node.ip, node.port)
        )
        return response

    async def find_nodes(self, target_id):
        try:
            logger.debug(f"{self.node_id}: Initiating iterative FIND_NODE for '{target_id}'")
            k = self.routing_table.k
            shortlist = self.routing_table.find_closest_nodes(target_id, k=k)
            contacted_nodes = set()
            closest_distance = int(self.node_id, 16) ^ int(target_id, 16)

            while True:
                candidates = [n for n in shortlist if n not in contacted_nodes]
                to_query = candidates[: self.alpha]
                if not to_query:
                    logger.debug(
                        f"{self.node_id}: No more nodes to query for target '{target_id}'"
                    )
                    break

                tasks = []
                for node in to_query:
                    contacted_nodes.add(node)
                    tasks.append(self.send_find_node(node, target_id))

                responses = await asyncio.gather(*tasks, return_exceptions=True)

                new_nodes = []
                for resp in responses:
                    if isinstance(resp, Exception):
                        logger.error(f"Error in network request: {resp}", exc_info=True)
                        continue
                    if resp and resp.data.get("nodes"):
                        for info in resp.data["nodes"]:
                            try:
                                node_id = info["node_id"]
                                ip = info["ip"]
                                port = info["port"]
                                tcp_port = info.get("tcp_port", port)
                                pk_bytes = bytes.fromhex(info.get("public_key", ""))
                                new_node = RemoteNode(
                                    ip=ip,
                                    port=port,
                                    tcp_port=tcp_port,
                                    node_id=node_id,
                                    public_key_bytes=pk_bytes,
                                )
                                if new_node not in contacted_nodes and new_node not in shortlist:
                                    new_nodes.append(new_node)
                                    await self.routing_table.add_node(new_node)
                            except Exception as e:
                                logger.error(f"Error processing node info: {e}", exc_info=True)

                shortlist.extend(new_nodes)
                shortlist = sorted(
                    set(shortlist),
                    key=lambda n: int(n.node_id, 16) ^ int(target_id, 16),
                )
                shortlist = shortlist[:k]

                new_closest_distance = int(shortlist[0].node_id, 16) ^ int(target_id, 16)
                if new_closest_distance >= closest_distance:
                    logger.debug(
                        f"{self.node_id}: Closest node unchanged, terminating search for '{target_id}'"
                    )
                    break
                closest_distance = new_closest_distance

                if all(n in contacted_nodes for n in shortlist):
                    logger.debug(
                        f"{self.node_id}: All nodes in shortlist have been queried for '{target_id}'"
                    )
                    break

            return shortlist
        except Exception as e:
            logger.error(f"Error in find_nodes: {e}", exc_info=True)
            return []

    async def send_find_node(self, node, target_id):
        request_id = str(uuid.uuid4())
        message = self.create_message(
            message_type="FIND_NODE",
            data={
                "target_id": target_id,
                "request_id": request_id,
            },
        )
        response = await self.send_message_and_wait_for_response(
            message, (node.ip, node.port)
        )
        return response

    async def send_value(self, addr, key, value):
        response_message = Message(
            message_type="FIND_VALUE_RESPONSE",
            sender_id=self.node_id,
            data={"key": key, "value": value},
            signature=None,
            public_key=self.public_key_bytes.hex(),
        )
        signature_bytes = sign_message(
            self.private_key, response_message.to_json_unsigned().encode("utf-8")
        )
        response_message.signature = signature_bytes.hex()
        await self.send_message(response_message, addr)

    async def handle_find_value(self, message, addr):
        self.logger.debug(f"{self.node_id}: Received FIND_VALUE from {addr}")
        key = message.data.get("key")
        if key:
            async with self.data_store_lock:
                value_entry = self.data_store.get(key)
            if value_entry:
                value, expiration = value_entry
                response_data = {
                    "request_id": message.data.get("request_id"),
                    "value": value,
                }
                response_message = self.create_message("FIND_VALUE_RESPONSE", response_data)
                await self.send_message(response_message, addr)
            else:
                closest_nodes = self.routing_table.find_closest_nodes(key, k=self.routing_table.k)
                nodes_data = [
                    {
                        "node_id": n.node_id,
                        "ip": n.ip,
                        "port": n.port,
                        "tcp_port": n.tcp_port,
                        "public_key": n.public_key_bytes.hex() if n.public_key_bytes else "",
                    }
                    for n in closest_nodes
                ]
                response_data = {
                    "request_id": message.data.get("request_id"),
                    "nodes": nodes_data,
                }
                response_message = self.create_message("FIND_VALUE_RESPONSE", response_data)
                await self.send_message(response_message, addr)
        else:
            self.logger.warning(f"{self.node_id}: Invalid FIND_VALUE message from {addr}")

    async def handle_find_node(self, message, addr):
        self.logger.debug(f"{self.node_id}: Received FIND_NODE from {addr}")
        target_id = message.data.get("target_id")
        if target_id and self.routing_table:
            closest_nodes = self.routing_table.find_closest_nodes(
                target_id, k=self.routing_table.k
            )
            nodes_data = [
                {
                    "node_id": n.node_id,
                    "ip": n.ip,
                    "port": n.port,
                    "tcp_port": n.tcp_port,
                    "public_key": n.public_key_bytes.hex() if n.public_key_bytes else "",
                }
                for n in closest_nodes
            ]
            response_data = {
                "request_id": message.data.get("request_id"),
                "nodes": nodes_data,
            }
            response_message = self.create_message("FIND_NODE_RESPONSE", response_data)
            await self.send_message(response_message, addr)
        else:
            self.logger.warning(f"{self.node_id}: Invalid FIND_NODE message from {addr}")

    async def store_product(self, product, encryption_password, ttl=604800):
        """Store a product with optional TTL.
        
        Args:
            product: Product object to store
            encryption_password: Password for encrypting seller phone
            ttl: Time-to-live in seconds (default: 1 hour)
        """
        logger.info(f"{self.node_id}: Storing product '{product.product_id}'")
        
        if not product.seller_phone_encrypted:
            product.encrypt_seller_phone(encryption_password)
        
        product_json = product.to_json()
        product_key = hashlib.sha1(product.product_id.encode("utf-8")).hexdigest()

        # Handle large payloads by storing in file storage
        if len(product_json.encode("utf-8")) > MAX_UDP_PAYLOAD_SIZE - 512:
            product_hash = hashlib.sha256(product_json.encode("utf-8")).hexdigest()
            await self.storage_service.store_file(
                product_hash, 
                product_json.encode("utf-8")
            )
            product_ref = {
                "type": "storage_ref", 
                "hash": product_hash
            }
            await self.store_value(product_key, json.dumps(product_ref), ttl=ttl)
        else:
            await self.store_value(product_key, product_json, ttl=ttl)

    async def find_product(self, product_id, encryption_password):
        logger.info(f"{self.node_id}: Finding product '{product_id}'")
        product_key = hashlib.sha1(product_id.encode("utf-8")).hexdigest()
        value = await self.find_value(product_key)
        if value:
            try:
                data = json.loads(value)
                if isinstance(data, dict) and data.get("type") == "storage_ref":
                    product_hash = data.get("hash")
                    product_data = await self.storage_service.retrieve_file_from_network(
                        product_hash
                    )
                    if not product_data:
                        logger.warning(
                            f"Product data for '{product_id}' not found in storage service"
                        )
                        return None
                    calculated_hash = hashlib.sha256(product_data).hexdigest()
                    if calculated_hash != product_hash:
                        logger.error(
                            f"Product hash mismatch for '{product_id}': expected {product_hash}, got {calculated_hash}"
                        )
                        return None
                    product = Product.from_json(product_data.decode("utf-8"))
                else:
                    product = Product.from_json(value)
                product.decrypt_seller_phone(encryption_password)
                return product
            except Exception as e:
                logger.error(f"Error parsing product data for '{product_id}': {e}")
                return None
        else:
            logger.warning(f"Product '{product_id}' not found")
            return None

    async def index_product(self, product: Product):
        attributes_to_index = ["category", "shop_name", "seller_location"]
        for attribute in attributes_to_index:
            try:
                value = product.core.get(attribute)
                if value:
                    if attribute == "seller_location":
                        lat, lon = value
                        lat_bin = round(float(lat) / 0.1) * 0.1
                        lon_bin = round(float(lon) / 0.1) * 0.1
                        index_value = f"{round(lat_bin,2)},{round(lon_bin,2)}"
                        original_value = value
                    else:
                        original_value = value
                        index_value = str(value).strip().lower()
                    logger.debug(
                        f"Indexing product {product.product_id} under {attribute}: '{original_value}' => '{index_value}'"
                    )
                    await self.index_product_attribute(
                        attribute, index_value, product.product_id
                    )
            except Exception as e:
                logger.error(
                    f"Error indexing attribute {attribute} for product {product.product_id}: {str(e)}",
                    exc_info=True,
                )

    async def index_product_attribute(self, attribute: str, value: str, product_id: str):
        index_key = f"index:{attribute}:{value}"
        index_key_hash = hashlib.sha1(index_key.encode("utf-8")).hexdigest()

        existing_index_json = await self.find_value(index_key_hash)
        if existing_index_json:
            existing_index = json.loads(existing_index_json)
        else:
            existing_index = []

        if product_id not in existing_index:
            existing_index.append(product_id)
            await self.store_value(index_key_hash, json.dumps(existing_index))
        else:
            logger.debug(f"Product_id {product_id} already in index {index_key}")

    async def search_products_by_attribute(self, attribute: str, value: str, encryption_password: str):
        original_value = value
        value = str(value).strip().lower()
        index_key = f"index:{attribute}:{value}"
        index_key_hash = hashlib.sha1(index_key.encode("utf-8")).hexdigest()

        index_json = await self.find_value(index_key_hash)
        if not index_json:
            logger.debug(f"No index found for {attribute}: {value}")
            return []
        product_ids = json.loads(index_json)
        products = []
        for pid in product_ids:
            p = await self.find_product(pid, encryption_password)
            if p:
                products.append(p)
        return products

    async def bootstrap(self, known_nodes):
        self.logger.info(
            f"{self.node_id}: Starting bootstrap with known nodes: {known_nodes}"
        )
        max_retries = 10
        delay = 5
        for attempt in range(max_retries):
            success = False
            for (node_ip, node_port) in known_nodes:
                if node_ip == self.advertise_ip and node_port == self.port:
                    continue
                try:
                    bootstrap_node = RemoteNode(ip=node_ip, port=node_port)
                    success = await self.ping_node(bootstrap_node)
                    if success:
                        self.logger.info(
                            f"{self.node_id}: Successfully bootstrapped with {node_ip}:{node_port}"
                        )
                        break
                    else:
                        self.logger.warning(
                            f"{self.node_id}: Bootstrap node {node_ip}:{node_port} is unresponsive"
                        )
                except Exception as e:
                    self.logger.error(
                        f"{self.node_id}: Error bootstrapping with {node_ip}:{node_port}: {e}",
                        exc_info=True,
                    )
            if success:
                break
            self.logger.info(
                f"{self.node_id}: Retry {attempt + 1}/{max_retries} - Waiting {delay} seconds before retrying bootstrap"
            )
            await asyncio.sleep(delay)
        else:
            self.logger.warning(
                f"{self.node_id}: Bootstrap failed with all known nodes after {max_retries} attempts"
            )
            return False
        return True

    async def initialize_categories(self, categories):
        logger.info(f"{self.node_id}: Initializing categories if not already present")
        categories_key = hashlib.sha1("categories".encode("utf-8")).hexdigest()
        existing_categories_json = await self.find_value(categories_key)
        if existing_categories_json:
            logger.debug(f"{self.node_id}: Categories already initialized")
            return
        categories_json = json.dumps(categories)
        await self.store_value(categories_key, categories_json)
        logger.debug(
            f"{self.node_id}: Stored initial categories under key '{categories_key}'"
        )

    async def suggest_category(self, category_name):
        logger.info(f"{self.node_id}: Suggesting new category '{category_name}'")
        validator_nodes = self.get_validator_nodes()
        if not validator_nodes:
            logger.warning(f"{self.node_id}: No validator nodes available")
            return False
        tasks = []
        for node in validator_nodes:
            tasks.append(self.send_category_suggestion(node, category_name))
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        approvals = sum(
            1 for r in responses if isinstance(r, Message) and r.data.get("approved")
        )
        if approvals > len(responses) // 2:
            logger.info(
                f"{self.node_id}: Category '{category_name}' approved by validators"
            )
            await self.add_category(category_name)
            return True
        else:
            logger.info(
                f"{self.node_id}: Category '{category_name}' not approved by validators"
            )
            return False

    def get_validator_nodes(self):
        validators = self.routing_table.get_all_nodes()
        logger.debug(f"{self.node_id}: Found {len(validators)} validator nodes")
        return validators

    async def send_category_suggestion(self, node, category_name):
        message = Message(
            message_type="SUGGEST_CATEGORY",
            sender_id=self.node_id,
            data={"category_name": category_name},
            signature=None,
            public_key=self.public_key_bytes.hex(),
        )
        request_id = str(uuid.uuid4())
        message.data["request_id"] = request_id
        signature_bytes = sign_message(
            self.private_key, message.to_json_unsigned().encode("utf-8")
        )
        message.signature = signature_bytes.hex()
        response = await self.send_message_and_wait_for_response(
            message, (node.ip, node.port)
        )
        return response

    async def add_category(self, category_name):
        try:
            categories_key = hashlib.sha1("categories".encode("utf-8")).hexdigest()
            try:
                categories_json = await self.find_value(categories_key)
                if categories_json:
                    categories = json.loads(categories_json)
                    if category_name not in categories:
                        categories.append(category_name)
                        new_categories_json = json.dumps(categories)
                        try:
                            await self.store_value(categories_key, new_categories_json)
                        except Exception as e:
                            logger.error(f"Error storing updated categories: {e}", exc_info=True)
                            raise
                    else:
                        logger.debug(f"{self.node_id}: Category '{category_name}' already exists")
                else:
                    categories = [category_name]
                    categories_json = json.dumps(categories)
                    try:
                        await self.store_value(categories_key, categories_json)
                    except Exception as e:
                        logger.error(f"Error storing initial categories: {e}", exc_info=True)
                        raise
            except Exception as e:
                logger.error(f"Error retrieving categories: {e}", exc_info=True)
                raise
        except Exception as e:
            logger.error(f"Error adding category '{category_name}': {e}", exc_info=True)
            raise

    async def handle_suggest_category(self, message, addr):
        self.logger.debug(f"{self.node_id}: Received SUGGEST_CATEGORY from {addr}")
        category_name = message.data.get("category_name")
        request_id = message.data.get("request_id")

        if not self.is_validator_node():
            self.logger.debug(
                f"{self.node_id}: Not a validator node, ignoring SUGGEST_CATEGORY"
            )
            return

        approved = self.validate_category(category_name)
        self.logger.debug(
            f"{self.node_id}: Category '{category_name}' validation result: {approved}"
        )

        response_data = {
            "request_id": request_id,
            "approved": approved,
        }
        response_message = self.create_message("CATEGORY_APPROVAL", response_data)
        await self.send_message(response_message, addr)

    async def handle_category_approval(self, message, addr):
        self.logger.debug(f"{self.node_id}: Received CATEGORY_APPROVAL from {addr}")
        request_id = message.data.get("request_id")
        approved = message.data.get("approved")

        if request_id:
            async with self.pending_requests_lock:
                entry = self.pending_requests.get(request_id)
                if entry:
                    future, _ = entry
                    if not future.done():
                        future.set_result(message)
                    self.pending_requests.pop(request_id, None)
                else:
                    self.logger.warning(
                        f"{self.node_id}: Received CATEGORY_APPROVAL with unknown request_id {request_id}"
                    )
        else:
            self.logger.warning(
                f"{self.node_id}: Received CATEGORY_APPROVAL without request_id"
            )

    def is_validator_node(self):
        return os.getenv("IS_VALIDATOR", "false").lower() == "true"

    def validate_category(self, category_name):
        prohibited_words = ["spam", "illegal"]
        if any(word in category_name.lower() for word in prohibited_words):
            return False
        if len(category_name) < 2 or len(category_name) > 50:
            return False
        return True

    def create_message(self, message_type, data=None):
        if data is None:
            data = {}
        data = {
            **data,
            "sender_ip": self.advertise_ip,
            "sender_port": self.port,
            "tcp_port": getattr(self, "tcp_port", self.port),
            "timestamp": time.time(),
        }
        message = Message(
            message_type=message_type,
            sender_id=self.node_id,
            data=data,
            signature=None,
            public_key=self.public_key_bytes.hex(),
        )
        signature_bytes = sign_message(
            self.private_key, message.to_json_unsigned().encode("utf-8")
        )
        message.signature = signature_bytes.hex()
        return message

    async def store_sub_chunks(self, chunk_hash, sub_chunks, ttl=604800):
        self.logger.debug(
            f"{self.node_id}: Storing {len(sub_chunks)} sub-chunks for chunk {chunk_hash}"
        )
        k = self.routing_table.k
        closest_nodes = self.routing_table.find_closest_nodes(chunk_hash, k=k)
        if not closest_nodes:
            self.logger.warning(
                f"{self.node_id}: No nodes available to store sub-chunks for {chunk_hash}"
            )
            return

        tasks = []
        for idx, node in enumerate(closest_nodes):
            sub_chunk_idx = idx % len(sub_chunks)
            sub_chunk_data = sub_chunks[sub_chunk_idx]
            sub_chunk_hash = hashlib.sha256(sub_chunk_data).hexdigest()

            message_data = {
                "chunk_hash": chunk_hash,
                "sub_chunk_index": sub_chunk_idx,
                "sub_chunk_hash": sub_chunk_hash,
                "data": sub_chunk_data.hex(),
                "ttl": ttl,
                "request_id": str(uuid.uuid4()),
            }

            msg = StorageMessage(
                message_type="STORE_SUB_CHUNK",
                sender_id=self.node_id,
                data=message_data,
                signature=None,
                public_key=self.public_key_bytes.hex(),
            )
            signature_bytes = sign_message(
                self.private_key, msg.to_json_unsigned().encode("utf-8")
            )
            msg.signature = signature_bytes.hex()

            tasks.append(self.send_storage_message(msg, (node.ip, node.port)))

        await asyncio.gather(*tasks)