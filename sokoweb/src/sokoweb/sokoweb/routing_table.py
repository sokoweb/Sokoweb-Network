# routing_table.py
import asyncio
import logging
from .kbucket import KBucket
from .utils import xor_distance

logger = logging.getLogger(__name__)

class RoutingTable:
    """
    Implements the routing table for a Kademlia node.
    """

    def __init__(self, node_id, k=20):
        self.node_id = node_id
        self.k = k
        self.logger = logging.getLogger(__name__)
        self.buckets = [KBucket(0, 2**160 - 1)]
        self.lock = asyncio.Lock()

    async def add_node(self, node):
        needs_re_add = False
        async with self.lock:
            bucket_index = self._find_bucket_index(node.node_id)
            bucket = self.buckets[bucket_index]

            if node in bucket.nodes:
                bucket.nodes.remove(node)
                bucket.nodes.append(node)
                logger.debug(f"Node {node.node_id} moved to end of bucket {bucket_index}")
            elif len(bucket.nodes) < self.k:
                bucket.nodes.append(node)
                logger.info(f"Added node {node.node_id} to bucket {bucket_index}")
            else:
                if bucket.in_range(self.node_id) and bucket.can_split():
                    await self._split_bucket(bucket_index)
                    logger.debug(f"Bucket {bucket_index} split")
                    needs_re_add = True
                else:
                    oldest_node = bucket.nodes[0]
                    if await self._is_node_responsive(oldest_node):
                        logger.debug(
                            f"Bucket {bucket_index} full; node {node.node_id} not added"
                        )
                    else:
                        bucket.nodes.pop(0)
                        bucket.nodes.append(node)
                        logger.debug(
                            f"Unresponsive node replaced with {node.node_id} in bucket {bucket_index}"
                        )

        if needs_re_add:
            await self.add_node(node)

    async def remove_node(self, node):
        async with self.lock:
            bucket_index = self._find_bucket_index(node.node_id)
            bucket = self.buckets[bucket_index]
            if node in bucket.nodes:
                bucket.nodes.remove(node)
                logger.debug(f"Node {node.node_id} removed from bucket {bucket_index}")

    def find_closest_nodes(self, target_id, k=None):
        k = k or self.k
        all_nodes = []
        for b in self.buckets:
            all_nodes.extend(b.nodes)
        all_nodes = list(set(all_nodes))
        all_nodes.sort(key=lambda n: int(n.node_id, 16) ^ int(target_id, 16))
        return all_nodes[:k]

    def _find_bucket_index(self, node_id):
        node_id_int = int(node_id, 16)
        for i, b in enumerate(self.buckets):
            if b.range_lower <= node_id_int <= b.range_upper:
                return i
        raise ValueError(f"No bucket found for node ID {node_id}")

    async def _split_bucket(self, index):
        b = self.buckets[index]
        result = b.split()
        if result:
            left_bucket, right_bucket = result
            self.buckets[index] = left_bucket
            self.buckets.insert(index + 1, right_bucket)

    async def _is_node_responsive(self, node):
        await asyncio.sleep(0.01)
        return True

    def handle_timeout(self, addr):
        node_id = self.get_node_id_by_address(addr)
        if node_id:
            logger.warning(
                f"{self.node_id}: Node {node_id} at {addr} timed out, removing from routing table."
            )
            self.remove_node(node_id)

    def get_node_id_by_address(self, addr):
        for b in self.buckets:
            for nd in b.nodes:
                if (nd.ip, nd.port) == addr:
                    return nd.node_id
        return None

    async def remove_node_by_addr(self, addr):
        async with self.lock:
            for b in self.buckets:
                to_remove = [n for n in b.nodes if (n.ip, n.port) == addr]
                for nd in to_remove:
                    b.remove_node(nd)
                    self.logger.info(
                        f"Removed unresponsive node {nd.node_id} at {addr} from routing table"
                    )

    def get_all_nodes(self):
        nodes = []
        for b in self.buckets:
            nodes.extend(b.nodes)
        return nodes

    def get_node_by_id(self, node_id):
        for b in self.buckets:
            for n in b.nodes:
                if n.node_id == node_id:
                    return n
        return None

    def get_node_by_address(self, addr):
        for b in self.buckets:
            for nd in b.nodes:
                if (nd.ip, nd.port) == addr:
                    return nd
        return None