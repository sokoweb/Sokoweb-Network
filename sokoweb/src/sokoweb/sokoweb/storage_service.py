# storage_service.py

import asyncio
import hashlib
import json
import logging
import time
import os
import struct
import aiofiles
import aiofiles.os as aioos

class StorageService:
    def __init__(
        self,
        node,
        storage_dir="storage_chunks",
        cleanup_interval=60,
        republish_interval=3600,
    ):
        self.node = node
        self.loop = asyncio.get_event_loop()
        self.cleanup_task = None
        self.republish_task = None
        self.logger = logging.getLogger(__name__)

        self.storage_dir = storage_dir
        self.chunks_dir = os.path.join(self.storage_dir, "chunks")
        self.sub_chunks_dir = os.path.join(self.storage_dir, "sub_chunks")

        os.makedirs(self.chunks_dir, exist_ok=True)
        os.makedirs(self.sub_chunks_dir, exist_ok=True)

        self.cleanup_interval = cleanup_interval
        self.republish_interval = republish_interval

        self.chunk_store = {}
        self.metadata_file = os.path.join(self.storage_dir, "chunk_store_meta.json")
        self._init_task = asyncio.create_task(self.load_chunk_store())

        self.logger.info(f"Initialized StorageService for node {self.node.node_id}")

    async def wait_for_initialization(self):
        await self._init_task

    async def start(self):
        self.cleanup_task = asyncio.create_task(
            self.cleanup_expired_chunks(self.cleanup_interval)
        )
        self.republish_task = asyncio.create_task(
            self.republish_chunks(self.republish_interval)
        )
        self.logger.info(f"StorageService started periodic tasks for {self.node.node_id}")

    async def stop(self):
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
            self.logger.info(f"StorageService cleanup task stopped for {self.node.node_id}")

        if self.republish_task:
            self.republish_task.cancel()
            try:
                await self.republish_task
            except asyncio.CancelledError:
                pass
            self.logger.info(f"StorageService republish task stopped for {self.node.node_id}")

        await self.save_chunk_store()
        self.logger.info(f"StorageService chunk_store saved for {self.node.node_id}")

    async def save_chunk_store(self):
        async with aiofiles.open(self.metadata_file, "w") as f:
            chunk_store_data = {k: str(v) for k, v in self.chunk_store.items()}
            await f.write(json.dumps(chunk_store_data))
        self.logger.debug(f"Saved chunk_store metadata: {chunk_store_data}")

    async def load_chunk_store(self):
        if await aioos.path.exists(self.metadata_file):
            async with aiofiles.open(self.metadata_file, "r") as f:
                content = await f.read()
                chunk_store_data = json.loads(content)
                self.chunk_store = {k: float(v) for k, v in chunk_store_data.items()}
            self.logger.debug(f"Loaded chunk_store metadata: {chunk_store_data}")
        else:
            self.chunk_store = {}

    async def distribute_file_to_network(self, file_hash, file_data, ttl):
        try:
            k = self.node.routing_table.k
            closest_nodes = await self.node.find_nodes(file_hash)
            if not closest_nodes:
                self.logger.warning(
                    f"{self.node.node_id}: No nodes available to store file {file_hash}"
                )
                return
            for n in closest_nodes:
                if n.node_id == self.node.node_id:
                    continue
                try:
                    await self.send_file_over_tcp(n, file_hash, file_data, ttl)
                except Exception as e:
                    self.logger.error(
                        f"Failed to send file {file_hash} to node {n.node_id} over TCP: {e}"
                    )
        except Exception as e:
            self.logger.error(
                f"Error distributing file {file_hash} to network: {e}", exc_info=True
            )

    async def handle_store_file(self, message, reader, writer):
        file_hash = message.get("file_hash")
        ttl = message.get("ttl", 604800)
        self.logger.debug(f"Received STORE_FILE message: {message}")

        if not file_hash:
            self.logger.error("Invalid STORE_FILE message received")
            if not writer.is_closing():
                writer.close()
            return
        try:
            file_size_data = await reader.readexactly(8)
            file_size = int.from_bytes(file_size_data, byteorder="big")
            self.logger.debug(f"Expecting {file_size} bytes of file data.")

            file_data = await reader.readexactly(file_size)
            self.logger.debug(f"Read {len(file_data)} bytes of file data.")

            calculated_hash = hashlib.sha256(file_data).hexdigest()
            if calculated_hash != file_hash:
                self.logger.error(
                    f"File hash mismatch: expected {file_hash}, got {calculated_hash}"
                )
                response = {"status": "ERROR", "error": "File hash mismatch"}
                rsp = json.dumps(response).encode("utf-8")
                l = len(rsp).to_bytes(4, byteorder="big")
                writer.write(l + rsp)
                await writer.drain()
                return

            await self.save_chunk_to_file(file_hash, file_data)

            expiration_time = time.time() + ttl
            self.chunk_store[file_hash] = expiration_time
            self.logger.info(f"Stored file {file_hash} of size {file_size} bytes")

            response = {"status": "OK"}
            rsp = json.dumps(response).encode("utf-8")
            l = len(rsp).to_bytes(4, byteorder="big")
            writer.write(l + rsp)
            await writer.drain()

        except Exception as e:
            self.logger.error(f"Failed to store file {file_hash}: {e}", exc_info=True)
            response = {"status": "ERROR", "error": str(e)}
            rsp = json.dumps(response).encode("utf-8")
            l = len(rsp).to_bytes(4, byteorder="big")
            try:
                writer.write(l + rsp)
                await writer.drain()
            except Exception as we:
                self.logger.error(f"Error sending error response for {file_hash}: {we}", exc_info=True)
            finally:
                if not writer.is_closing():
                    writer.close()

    async def handle_tcp_connection(self, reader, writer, message_json):
        addr = writer.get_extra_info("peername")
        self.logger.debug(f"Handling TCP from {addr} in StorageService")

        try:
            message = json.loads(message_json)
            message_type = message.get("message_type")
            if message_type == "STORE_FILE":
                await self.handle_store_file(message, reader, writer)
            elif message_type == "RETRIEVE_FILE":
                await self.handle_retrieve_file_tcp(message, reader, writer)
            else:
                self.logger.warning(f"Unknown storage message type over TCP: {message_type}")
        except (asyncio.CancelledError, GeneratorExit):
            self.logger.warning(
                f"TCP connection from {addr} was cancelled or encountered GeneratorExit."
            )
            raise
        except Exception as e:
            self.logger.error(f"Error handling TCP connection from {addr}: {e}", exc_info=True)
            response = {"status": "ERROR", "message": str(e)}
            rsp = json.dumps(response).encode("utf-8")
            try:
                writer.write(len(rsp).to_bytes(4, byteorder="big") + rsp)
                await writer.drain()
            except Exception as we:
                self.logger.error(f"Error sending error response to {addr}: {we}", exc_info=True)
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()

    async def handle_retrieve_file_tcp(self, message, reader, writer):
        file_hash = message.get("file_hash")
        if file_hash:
            file_path = os.path.join(self.storage_dir, file_hash)
            if await aioos.path.exists(file_path):
                async with aiofiles.open(file_path, "rb") as f:
                    file_data = await f.read()
                response = {"status": "OK", "file_size": len(file_data)}
                rsp = json.dumps(response).encode("utf-8")
                length = len(rsp).to_bytes(4, byteorder="big")
                writer.write(length + rsp)
                await writer.drain()

                writer.write(file_data)
                await writer.drain()
            else:
                self.logger.warning(f"Requested file {file_hash} not found.")
                response = {"status": "ERROR", "message": "File not found"}
                rsp = json.dumps(response).encode("utf-8")
                length = len(rsp).to_bytes(4, byteorder="big")
                writer.write(length + rsp)
                await writer.drain()
        else:
            self.logger.warning("Invalid RETRIEVE_FILE message over TCP.")
            response = {"status": "ERROR", "message": "Invalid request"}
            rsp = json.dumps(response).encode("utf-8")
            length = len(rsp).to_bytes(4, byteorder="big")
            writer.write(length + rsp)
            await writer.drain()

    async def handle_store_chunk_tcp(self, message, reader, writer):
        chunk_hash = message.get("chunk_hash")
        chunk_size = message.get("chunk_size")
        ttl = message.get("ttl", 604800)
        if chunk_hash and chunk_size:
            data = await reader.readexactly(chunk_size)
            calc_hash = hashlib.sha256(data).hexdigest()
            if calc_hash == chunk_hash:
                await self.save_chunk_to_file(chunk_hash, data)
                expiration_time = time.time() + ttl
                self.chunk_store[chunk_hash] = expiration_time
                self.logger.info(f"Stored chunk {chunk_hash} from TCP connection")
                response = {"status": "OK"}
                rsp = json.dumps(response).encode("utf-8")
                writer.write(len(rsp).to_bytes(4, byteorder="big") + rsp)
                await writer.drain()
            else:
                self.logger.warning(f"Chunk hash mismatch for {chunk_hash} over TCP")
                response = {"status": "ERROR", "message": "Hash mismatch"}
                rsp = json.dumps(response).encode("utf-8")
                writer.write(len(rsp).to_bytes(4, byteorder="big") + rsp)
                await writer.drain()
        else:
            self.logger.warning("Invalid STORE_CHUNK message over TCP")
            response = {"status": "ERROR", "message": "Invalid request"}
            rsp = json.dumps(response).encode("utf-8")
            writer.write(len(rsp).to_bytes(4, byteorder="big") + rsp)
            await writer.drain()

    async def handle_retrieve_chunk_tcp(self, message, reader, writer):
        chunk_hash = message.get("chunk_hash")
        if (
            chunk_hash in self.chunk_store
            and time.time() < self.chunk_store[chunk_hash]
        ):
            data = await self.read_chunk_from_file(chunk_hash)
            if data:
                response = {"status": "OK", "chunk_size": len(data)}
                rsp = json.dumps(response).encode("utf-8")
                writer.write(len(rsp).to_bytes(4, byteorder="big") + rsp)
                await writer.drain()

                writer.write(data)
                await writer.drain()
            else:
                response = {"status": "ERROR", "message": "Chunk data not found"}
                rsp = json.dumps(response).encode("utf-8")
                writer.write(len(rsp).to_bytes(4, byteorder="big") + rsp)
                await writer.drain()
        else:
            response = {"status": "ERROR", "message": "Chunk not available"}
            rsp = json.dumps(response).encode("utf-8")
            writer.write(len(rsp).to_bytes(4, byteorder="big") + rsp)
            await writer.drain()

    async def save_chunk_to_file(self, file_hash: str, data: bytes) -> None:
        file_path = os.path.join(self.storage_dir, file_hash)
        async with aiofiles.open(file_path, "wb") as f:
            await f.write(data)
        self.logger.debug(f"Saved file {file_hash} to local storage.")

    async def read_chunk_from_file(self, file_hash):
        file_path = os.path.join(self.chunks_dir, file_hash)
        if await aioos.path.exists(file_path):
            async with aiofiles.open(file_path, "rb") as f:
                data = await f.read()
            self.logger.debug(f"Read chunk {file_hash} from {file_path}")
            return data
        else:
            self.logger.debug(f"Chunk file {file_path} does not exist")
            return None

    async def cleanup_expired_chunks(self, interval=60):
        while True:
            try:
                await asyncio.sleep(interval)
                current_time = time.time()
                expired = [
                    ch for ch, exp in self.chunk_store.items() if current_time >= exp
                ]
                for ch in expired:
                    await self.delete_chunk(ch)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in cleanup_expired_chunks: {e}")

    async def delete_chunk(self, chunk_hash):
        if chunk_hash in self.chunk_store:
            del self.chunk_store[chunk_hash]
        file_path = os.path.join(self.chunks_dir, chunk_hash)
        if await aioos.path.exists(file_path):
            await aioos.remove(file_path)
            self.logger.debug(f"Deleted chunk file {chunk_hash}")

    async def republish_chunks(self, interval=3600):
        while True:
            try:
                await asyncio.sleep(interval)
                self.logger.debug("Running republish_chunks task")
                current_time = time.time()
                for ch, exp_time in self.chunk_store.items():
                    if current_time < exp_time:
                        data = await self.read_chunk_from_file(ch)
                        if data:
                            remaining_ttl = exp_time - current_time
                            await self.store_chunk(ch, data, ttl=remaining_ttl)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in republish_chunks: {e}")

    async def store_chunk(self, chunk_hash: str, chunk_data: bytes, ttl=604800) -> None:
        await self.save_chunk_to_file(chunk_hash, chunk_data)
        expiration_time = time.time() + ttl
        self.chunk_store[chunk_hash] = expiration_time

        closest_nodes = await self.node.find_nodes(chunk_hash)
        if not closest_nodes:
            self.logger.warning(
                f"{self.node.node_id}: No nodes available to store chunk {chunk_hash}"
            )
            return

        for n in closest_nodes:
            try:
                await self.send_chunk_over_tcp(n, chunk_hash, chunk_data, ttl)
            except Exception as e:
                self.logger.error(
                    f"Failed to send chunk {chunk_hash} to node {n.node_id} over TCP: {e}"
                )

    async def send_chunk_over_tcp(self, node, chunk_hash, chunk_data, ttl):
        reader, writer = await asyncio.open_connection(node.ip, node.tcp_port)
        try:
            message = {
                "message_type": "STORE_CHUNK",
                "chunk_hash": chunk_hash,
                "chunk_size": len(chunk_data),
                "ttl": ttl,
            }
            msg_json = json.dumps(message).encode("utf-8")
            writer.write(len(msg_json).to_bytes(4, byteorder="big") + msg_json)
            await writer.drain()
            writer.write(chunk_data)
            await writer.drain()

            data = await reader.readexactly(4)
            rsp_len = int.from_bytes(data, byteorder="big")
            rsp_data = await reader.readexactly(rsp_len)
            rsp = json.loads(rsp_data.decode("utf-8"))
            if rsp.get("status") != "OK":
                raise Exception(f"Failed to store chunk on node {node.node_id}: {rsp.get('message')}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def retrieve_chunk_from_network(self, chunk_hash):
        closest_nodes = await self.node.find_nodes(chunk_hash)
        for n in closest_nodes:
            try:
                chunk_data = await self.request_chunk_over_tcp(n, chunk_hash)
                if chunk_data:
                    if hashlib.sha256(chunk_data).hexdigest() == chunk_hash:
                        return chunk_data
                    else:
                        self.logger.warning(
                            f"Received corrupt chunk from node {n.node_id}"
                        )
            except Exception as e:
                self.logger.error(
                    f"Error retrieving chunk from node {n.node_id}: {e}"
                )
        return None

    async def request_chunk_over_tcp(self, node, chunk_hash):
        reader, writer = await asyncio.open_connection(node.ip, node.tcp_port)
        try:
            message = {"message_type": "RETRIEVE_CHUNK", "chunk_hash": chunk_hash}
            msg_json = json.dumps(message).encode("utf-8")
            writer.write(len(msg_json).to_bytes(4, byteorder="big") + msg_json)
            await writer.drain()

            data = await reader.readexactly(4)
            rsp_len = int.from_bytes(data, byteorder="big")
            rsp_data = await reader.readexactly(rsp_len)
            rsp = json.loads(rsp_data.decode("utf-8"))
            if rsp.get("status") == "OK":
                csize = rsp.get("chunk_size")
                cdata = await reader.readexactly(csize)
                return cdata
            else:
                self.logger.warning(
                    f"Failed to retrieve chunk {chunk_hash} from node {node.node_id}: {rsp.get('message')}"
                )
                return None
        finally:
            writer.close()
            await writer.wait_closed()

    async def store_file(self, file_hash: str, file_data: bytes, ttl=604800) -> None:
        await self.save_chunk_to_file(file_hash, file_data)
        expiration_time = time.time() + ttl
        self.chunk_store[file_hash] = expiration_time

        closest_nodes = await self.node.find_nodes(file_hash)
        if not closest_nodes:
            self.logger.warning(
                f"{self.node.node_id}: No nodes available to store file {file_hash}"
            )
            return

        for n in closest_nodes:
            if n.node_id == self.node.node_id:
                continue
            success = await self.send_file_over_tcp(n, file_hash, file_data, ttl)
            if not success:
                self.logger.error(
                    f"Failed to send file {file_hash} to node {n.node_id} over TCP"
                )

    async def send_file_over_tcp(self, node, file_hash, file_data, ttl):
        try:
            reader, writer = await asyncio.open_connection(node.ip, node.tcp_port)
            message = {
                "message_type": "STORE_FILE",
                "file_hash": file_hash,
                "file_size": len(file_data),
                "ttl": ttl,
            }
            msg = json.dumps(message).encode("utf-8")
            msg_len = len(msg).to_bytes(4, byteorder="big")
            writer.write(msg_len + msg)
            await writer.drain()

            file_len = len(file_data).to_bytes(8, byteorder="big")
            writer.write(file_len + file_data)
            await writer.drain()

            try:
                resp_len_data = await asyncio.wait_for(reader.readexactly(4), timeout=30)
                resp_len = int.from_bytes(resp_len_data, byteorder="big")
                resp_data = await reader.readexactly(resp_len)
                resp = json.loads(resp_data.decode("utf-8"))
                if resp.get("status") == "OK":
                    self.logger.info(f"File {file_hash} sent successfully to {node.node_id}")
                    return True
                else:
                    self.logger.error(
                        f"Failed to send file {file_hash} to node {node.node_id}: {resp.get('error', 'Unknown error')}"
                    )
                    return False
            except asyncio.TimeoutError:
                self.logger.error(f"Timeout waiting for ack from node {node.node_id}")
                return False
            except asyncio.IncompleteReadError as e:
                self.logger.error(f"Incomplete read waiting for ack from {node.node_id}: {e}")
                return False
        except Exception as e:
            self.logger.error(f"Error sending file to node {node.node_id}: {e}", exc_info=True)
            return False
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

    async def retrieve_file_from_network(self, file_hash: str) -> bytes:
        file_path = os.path.join(self.storage_dir, file_hash)
        try:
            if await aioos.path.exists(file_path):
                self.logger.debug(f"File {file_hash} found locally.")
                async with aiofiles.open(file_path, "rb") as f:
                    return await f.read()
        except Exception as e:
            self.logger.error(f"Error reading local file {file_hash}: {e}")

        closest_nodes = await self.node.find_nodes(file_hash)
        if not closest_nodes:
            self.logger.warning(f"No nodes found close to file hash {file_hash}.")
            return None

        for n in closest_nodes:
            try:
                self.logger.debug(
                    f"Attempting to retrieve file {file_hash} from node {n.node_id}."
                )
                file_data = await self.request_file_over_tcp(n, file_hash)
                if file_data:
                    calc_hash = hashlib.sha256(file_data).hexdigest()
                    if calc_hash != file_hash:
                        raise Exception(
                            f"File hash mismatch: expected {file_hash}, got {calc_hash}"
                        )
                    await self.save_chunk_to_file(file_hash, file_data)
                    self.chunk_store[file_hash] = time.time() + 604800
                    self.logger.debug(
                        f"Retrieved and stored file {file_hash} from node {n.node_id}."
                    )
                    return file_data
            except Exception as e:
                self.logger.error(f"Failed to retrieve file {file_hash} from {n.node_id}: {e}")
        self.logger.warning(f"Failed to retrieve file {file_hash} from any node.")
        return None

    async def request_file_over_tcp(self, node, file_hash):
        try:
            reader, writer = await asyncio.open_connection(node.ip, node.tcp_port)
            try:
                msg = {
                    "message_type": "RETRIEVE_FILE",
                    "file_hash": file_hash,
                }
                msg_json = json.dumps(msg).encode("utf-8")
                writer.write(len(msg_json).to_bytes(4, byteorder="big") + msg_json)
                await writer.drain()

                resp_len_data = await reader.readexactly(4)
                resp_len = int.from_bytes(resp_len_data, byteorder="big")
                resp_data = await reader.readexactly(resp_len)
                resp = json.loads(resp_data.decode("utf-8"))

                if resp.get("status") == "OK":
                    file_size = resp.get("file_size")
                    if file_size is None:
                        raise Exception("Missing file_size in response")
                    file_size = int(file_size)
                    self.logger.debug(
                        f"Expecting {file_size} bytes from node {node.node_id}"
                    )
                    file_data = await reader.readexactly(file_size)
                    self.logger.debug(
                        f"Read {len(file_data)} bytes of file data from node {node.node_id}"
                    )
                    calc_hash = hashlib.sha256(file_data).hexdigest()
                    if calc_hash != file_hash:
                        raise Exception(
                            f"File hash mismatch: expected {file_hash}, got {calc_hash}"
                        )
                    return file_data
                else:
                    self.logger.warning(
                        f"Node {node.node_id} responded with error: {resp.get('message')}"
                    )
                    return None
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            self.logger.error(
                f"Error requesting file {file_hash} from node {node.node_id}: {e}"
            )
            return None