# storage_node.py

import asyncio
from .node import Node
from .storage_service import StorageService
from .messages import Message
import logging
import json

logger = logging.getLogger(__name__)

class StorageNode(Node):
    def __init__(
        self,
        ip,
        port,
        key_pair=None,
        node_id=None,
        advertise_ip=None,
        alpha=3,
        k=20,
        credit_manager=None,
        storage_dir="storage_chunks",
        cleanup_interval=60,
        republish_interval=3600,
        tcp_port=None,
    ):
        super().__init__(
            ip=ip,
            port=port,
            key_pair=key_pair,
            node_id=node_id,
            advertise_ip=advertise_ip,
            alpha=alpha,
            k=k,
            credit_manager=credit_manager,
        )
        self.tcp_port = tcp_port or (self.port + 500)
        self.tcp_server = None
        self.storage_service = StorageService(
            self,
            storage_dir=storage_dir,
            cleanup_interval=cleanup_interval,
            republish_interval=republish_interval,
        )
        logger.info(f"Initialized StorageNode at {self.ip}:{self.port} with TCP port {self.tcp_port}")

    async def start(self, bootstrap_nodes=None):
        await self.start_tcp_server()
        await self.storage_service.start()
        await super().start(bootstrap_nodes=bootstrap_nodes)

    async def stop(self):
        await self.storage_service.stop()
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
            logger.info(f"TCP server stopped for node {self.node_id}")
        await super().stop()

    async def start_tcp_server(self):
        self.tcp_server = await asyncio.start_server(
            self.handle_tcp_connection, self.bind_ip, self.tcp_port
        )
        self.logger.info(f"TCP server started on {self.bind_ip}:{self.tcp_port}")

    async def handle_tcp_connection(self, reader, writer):
        addr = writer.get_extra_info("peername")
        self.logger.debug(f"Accepted TCP connection from {addr}")

        try:
            data = await reader.readexactly(4)
            message_length = int.from_bytes(data, byteorder="big")
            message_data = await reader.readexactly(message_length)
            message_json = message_data.decode("utf-8")

            if any(
                m in message_json
                for m in [
                    '"message_type": "STORE_CHUNK"',
                    '"message_type": "RETRIEVE_CHUNK"',
                    '"message_type": "CHUNK_RESPONSE"',
                    '"message_type": "STORE_SUB_CHUNK"',
                    '"message_type": "STORE_FILE"',
                    '"message_type": "RETRIEVE_FILE"',
                ]
            ):
                await self.storage_service.handle_tcp_connection(
                    reader, writer, message_json
                )
                return
            else:
                message = Message.from_json(message_json)
                await self.handle_message(message, addr)

                response = {"status": "OK"}
                resp_data = json.dumps(response).encode("utf-8")
                writer.write(len(resp_data).to_bytes(4, byteorder="big") + resp_data)
                await writer.drain()

        except (asyncio.CancelledError, GeneratorExit):
            self.logger.warning(
                f"TCP connection from {addr} was cancelled or encountered GeneratorExit."
            )
            raise
        except Exception as e:
            self.logger.error(
                f"Error handling TCP connection from {addr}: {e}", exc_info=True
            )
            response = {"status": "ERROR", "message": str(e)}
            resp_data = json.dumps(response).encode("utf-8")
            try:
                writer.write(len(resp_data).to_bytes(4, byteorder="big") + resp_data)
                await writer.drain()
            except Exception as werr:
                self.logger.error(
                    f"Error sending error response to {addr}: {werr}", exc_info=True
                )
        finally:
            if not writer.is_closing():
                writer.close()