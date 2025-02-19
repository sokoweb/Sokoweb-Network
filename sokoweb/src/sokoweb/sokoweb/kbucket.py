
import logging

logger = logging.getLogger(__name__)


class KBucket:
    """
    Represents a bucket in the Kademlia routing table.
    Each bucket covers a specific range of node IDs.
    """

    def __init__(self, range_lower, range_upper, k=20):
      self.range_lower = int(range_lower)
      self.range_upper = int(range_upper)
      self.nodes = []
      self.k = k

    def in_range(self, node_id):
      node_id_int = int(node_id, 16)  # Interpret node_id as hexadecimal
      return self.range_lower <= node_id_int <= self.range_upper

    def add_node(self, node):
        """
        Add a node to the bucket.
        :param node: The node to add.
        :return: True if the node was added, False otherwise.
        """
        if node in self.nodes:
            # Move node to the end to mark it as most recently seen
            self.nodes.remove(node)
            self.nodes.append(node)
            logger.debug(f"Node {node.node_id} moved to end of bucket.")
            return True
        elif len(self.nodes) < self.k:
            self.nodes.append(node)
            logger.debug(f"Node {node.node_id} added to bucket.")
            return True
        else:
            # Bucket is full
            logger.debug(f"Bucket is full. Cannot add node {node.node_id}.")
            return False

    def remove_node(self, node):
        """
        Remove a node from the bucket.
        :param node: The node to remove.
        :return: True if the node was removed, False otherwise.
        """
        if node in self.nodes:
            self.nodes.remove(node)
            logger.debug(f"Node {node.node_id} removed from bucket.")
            return True
        else:
            logger.debug(f"Node {node.node_id} not found in bucket.")
            return False

    def can_split(self):
        """
        Determine if the bucket can be split further.
        :return: True if the bucket's range can be divided, False otherwise.
        """
        return self.range_upper > self.range_lower

    def split(self):
        if not self.can_split():
            return None

        midpoint = self.range_lower + (self.range_upper - self.range_lower) // 2
        print(f"Splitting bucket with range {self.range_lower}-{self.range_upper}")
        print(f"Midpoint: {midpoint}")

        left_bucket = KBucket(self.range_lower, midpoint, k=self.k)
        right_bucket = KBucket(midpoint + 1, self.range_upper, k=self.k)

        print(f"Left Bucket Range: {left_bucket.range_lower}-{left_bucket.range_upper}")
        print(f"Right Bucket Range: {right_bucket.range_lower}-{right_bucket.range_upper}")


        for node in self.nodes:
            if left_bucket.in_range(node.node_id):
                left_bucket.nodes.append(node)
            else:
                right_bucket.nodes.append(node)

        return left_bucket, right_bucket


    def __contains__(self, node):
        """
        Allows checking if a node is in the bucket using the 'in' keyword.
        :param node: The node to check.
        :return: True if the node is in the bucket, False otherwise.
        """
        return node in self.nodes

    def __len__(self):
        """
        Return the number of nodes in the bucket.
        :return: Integer count of nodes.
        """
        return len(self.nodes)

    def __repr__(self):
        """
        Return a string representation of the bucket.
        """
        return (
            f"KBucket({self.range_lower}, {self.range_upper}, nodes={len(self.nodes)})"
        )
