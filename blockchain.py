import time
import hashlib
from typing import List, Dict
from ecc_math import ecdsa_sign, ecdsa_verify, get_public_key

class Transaction:
    def __init__(self, sender, recipient, amount, signature=None, pubkey=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature  # (r, s)
        self.pubkey = pubkey  # (x, y)

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'signature': self.signature,
            'pubkey': self.pubkey
        }

    def message(self):
        return f"{self.sender}->{self.recipient}:{self.amount}".encode()

class Block:
    def __init__(self, index, transactions, prev_hash, timestamp=None, nonce=0):
        self.index = index
        self.transactions = transactions  # List[Transaction]
        self.prev_hash = prev_hash
        self.timestamp = timestamp or time.time()
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        tx_str = ''.join([str(tx.to_dict()) for tx in self.transactions])
        block_str = f"{self.index}{tx_str}{self.prev_hash}{self.timestamp}{self.nonce}"
        return hashlib.sha256(block_str.encode()).hexdigest()

class Blockchain:
    def __init__(self, curve):
        self.chain: List[Block] = []
        self.pending: List[Transaction] = []
        self.curve = curve
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis = Block(0, [], '0')
        self.chain.append(genesis)

    def add_transaction(self, sender, recipient, amount, priv_key=None):
        """Create and sign a transaction. If priv_key is provided, sign with ECDSA."""
        if priv_key is not None:
            G = self.curve['G']
            pubkey = get_public_key(priv_key, G, self.curve['a'], self.curve['p'])
            msg = f"{sender}->{recipient}:{amount}".encode()
            r, s = ecdsa_sign(msg, priv_key, G, self.curve['a'], self.curve['p'], self.curve['n'])
            tx = Transaction(sender, recipient, amount, signature=(r, s), pubkey=pubkey)
        else:
            tx = Transaction(sender, recipient, amount)
        self.pending.append(tx)
        return tx

    def mine_block(self):
        """Add a block with pending transactions."""
        if not self.pending:
            raise ValueError("No pending transactions to mine.")
        prev_hash = self.chain[-1].hash
        block = Block(len(self.chain), self.pending, prev_hash)
        self.chain.append(block)
        self.pending = []
        return block

    def verify_chain(self):
        """Verify the integrity and ECDSA signatures of the blockchain."""
        for i, block in enumerate(self.chain):
            if block.hash != block.compute_hash():
                return False, f"Block {i} hash mismatch"
            if i > 0 and block.prev_hash != self.chain[i-1].hash:
                return False, f"Block {i} prev_hash mismatch"
            for tx in block.transactions:
                if tx.signature and tx.pubkey:
                    G = self.curve['G']
                    valid = ecdsa_verify(
                        tx.message(),
                        tx.signature,
                        tx.pubkey,
                        G,
                        self.curve['a'],
                        self.curve['p'],
                        self.curve['n']
                    )
                    if not valid:
                        return False, f"Invalid signature in block {i}"
        return True, "Chain is valid"

    def to_dict(self):
        return [
            {
                'index': block.index,
                'transactions': [tx.to_dict() for tx in block.transactions],
                'prev_hash': block.prev_hash,
                'hash': block.hash,
                'timestamp': block.timestamp
            }
            for block in self.chain
        ] 