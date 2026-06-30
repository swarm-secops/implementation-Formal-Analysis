

import hashlib
import hmac
import math
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HASH_LEN  = 32        
KE_LEN    = 32        
NONCE_LEN = 12        


_PADDING_LEAF = hashlib.sha256(b'\x00' * HASH_LEN).digest()


# ---------------------------------------------------------------------------
# Hash primitive
# ---------------------------------------------------------------------------

def H(*parts: bytes) -> bytes:

    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def trunc(data: bytes, n: int) -> bytes:
   
    assert len(data) >= n, f"trunc: need {n} bytes, got {len(data)}"
    return data[:n]


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------

def _ceil_log2(n: int) -> int:
    
    return (n - 1).bit_length()


def merkle_build(leaves: list[bytes]) -> tuple[list[list[bytes]], bytes]:

    assert leaves, "merkle_build: leaf list must not be empty"

   
    depth = _ceil_log2(max(len(leaves), 1))
    size  = 1 << depth
    padded = list(leaves) + [_PADDING_LEAF] * (size - len(leaves))

    levels = [padded]
    current = padded
    while len(current) > 1:
        next_level = [H(current[i], current[i + 1])
                      for i in range(0, len(current), 2)]
        levels.append(next_level)
        current = next_level

    return levels, current[0]


def merkle_proof(levels: list[list[bytes]], idx: int) -> list[bytes]:
  
    path = []
    for level in levels[:-1]:          # every level except the root
        sibling_idx = idx ^ 1
        path.append(level[sibling_idx])
        idx >>= 1
    return path


def merkle_verify(leaf: bytes, path: list[bytes], root: bytes, idx: int) -> bool:

    current = leaf
    for sibling in path:
        if idx & 1:
            current = H(sibling, current)
        else:
            current = H(current, sibling)
        idx >>= 1
    return hmac.compare_digest(current, root)


# ---------------------------------------------------------------------------
# FORS — Forest of Random Subsets
# ---------------------------------------------------------------------------

def _encode_u32(v: int) -> bytes:
    return v.to_bytes(4, 'big')


def _fors_digest_indices(digest: bytes, k: int, a: int) -> list[int]:

    assert k * a <= len(digest) * 8, (
        f"FORS parameters k={k}, a={a} require {k*a} bits "
        f"but digest is only {len(digest)*8} bits"
    )
    bits = int.from_bytes(digest, 'big')
    total_bits = len(digest) * 8
    mask = (1 << a) - 1
    indices = []
    for j in range(k):
        # Extract window starting at bit position j*a from the MSB end
        shift = total_bits - (j + 1) * a
        indices.append((bits >> shift) & mask)
    return indices


class FORS:


    def __init__(self, k: int, a: int):
        self.k = k
        self.a = a
        self.leaves_per_tree = 1 << a



    def _secret_leaf(
        self,
        seed_l: bytes,
        mission: bytes,
        id_l: bytes,
        q: int,
        j: int,
        v: int,
    ) -> bytes:
        return H(seed_l, mission, id_l,
                 _encode_u32(q), _encode_u32(j), _encode_u32(v),
                 b"ctok")



    def _pk_leaves(
        self,
        seed_l: bytes,
        mission: bytes,
        id_l: bytes,
        q: int,
        j: int,
    ) -> list[bytes]:
        return [
            H(self._secret_leaf(seed_l, mission, id_l, q, j, v))
            for v in range(self.leaves_per_tree)
        ]

 

    def compute_token(
        self,
        seed_l: bytes,
        mission: bytes,
        id_l: bytes,
        q: int,
    ) -> bytes:
        roots = []
        for j in range(self.k):
            pk = self._pk_leaves(seed_l, mission, id_l, q, j)
            _, root = merkle_build(pk)
            roots.append(root)
        return H(*roots)



    def sign(
        self,
        seed_l: bytes,
        mission: bytes,
        id_l: bytes,
        q: int,
        digest: bytes,
    ) -> dict:

        indices = _fors_digest_indices(digest, self.k, self.a)
        leaves_out = []
        paths_out  = []

        for j in range(self.k):
            v  = indices[j]
            pk = self._pk_leaves(seed_l, mission, id_l, q, j)
            levels, _ = merkle_build(pk)
            leaves_out.append(self._secret_leaf(seed_l, mission, id_l, q, j, v))
            paths_out.append(merkle_proof(levels, v))

        return {"leaves": leaves_out, "paths": paths_out}



    def verify(
        self,
        token: bytes,
        digest: bytes,
        sigma: dict,
    ) -> bool:
        indices = _fors_digest_indices(digest, self.k, self.a)

        reconstructed_roots = []
        for j in range(self.k):
            v          = indices[j]
            pk_leaf    = H(sigma["leaves"][j])           # pk_{q,j,v_j}
            path       = sigma["paths"][j]

            current = pk_leaf
            pos     = v
            for sibling in path:
                if pos & 1:
                    current = H(sibling, current)
                else:
                    current = H(current, sibling)
                pos >>= 1
            reconstructed_roots.append(current)

        candidate_token = H(*reconstructed_roots)
        return hmac.compare_digest(candidate_token, token)


# ---------------------------------------------------------------------------
# AES-256-GCM AEAD
# ---------------------------------------------------------------------------

def aead_enc(ke: bytes, nonce: bytes, plaintext: bytes, ad: bytes) -> bytes:
    """
    AES-256-GCM encryption.
    Returns ciphertext concatenated with 16-byte authentication tag.
    """
    assert len(ke) == KE_LEN,    f"K_E must be {KE_LEN} bytes, got {len(ke)}"
    assert len(nonce) == NONCE_LEN, f"nonce must be {NONCE_LEN} bytes"
    return AESGCM(ke).encrypt(nonce, plaintext, ad)


def aead_dec(ke: bytes, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    """
    AES-256-GCM decryption and authentication.
    Raises cryptography.exceptions.InvalidTag on any authentication failure.
    """
    assert len(ke) == KE_LEN,    f"K_E must be {KE_LEN} bytes, got {len(ke)}"
    assert len(nonce) == NONCE_LEN, f"nonce must be {NONCE_LEN} bytes"
    return AESGCM(ke).decrypt(nonce, ciphertext, ad)


# ---------------------------------------------------------------------------
# Key wrapping  (Eq. 6–8)
# ---------------------------------------------------------------------------

def derive_wrap_mask(s_i: bytes, mission: bytes, R: bytes, id_i: bytes) -> bytes:
    """
    Z_i = H(s_i || M || R || ID_i || "wrap"),  then Trunc_{|K_E|}
    (Eq. 6)
    """
    return trunc(H(s_i, mission, R, id_i, b"wrap"), KE_LEN)


def wrap_key(ke: bytes, mask: bytes) -> bytes:
    """W_i = K_E XOR Trunc_{|K_E|}(Z_i)  (Eq. 7)"""
    assert len(ke) == KE_LEN and len(mask) == KE_LEN
    return bytes(a ^ b for a, b in zip(ke, mask))


def unwrap_key(wi: bytes, mask: bytes) -> bytes:
    """K_E = W_i XOR Trunc_{|K_E|}(Z_i)  (Eq. 8)"""
    assert len(wi) == KE_LEN and len(mask) == KE_LEN
    return bytes(a ^ b for a, b in zip(wi, mask))




def _pack_bytes(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def _unpack_bytes(buf: bytes, offset: int) -> tuple[bytes, int]:
    ln = struct.unpack_from(">H", buf, offset)[0]
    offset += 2
    return buf[offset: offset + ln], offset + ln


def serialise_sigma(sigma: dict, k: int, a: int) -> bytes:

    out = bytearray()
    for j in range(k):
        out += sigma["leaves"][j]               # 32 bytes
        assert len(sigma["paths"][j]) == a, (
            f"FORS tree {j} path length {len(sigma['paths'][j])} != a={a}")
        for node in sigma["paths"][j]:
            out += node                         # 32 bytes each
    return bytes(out)


def deserialise_sigma(buf: bytes, offset: int, k: int, a: int) -> tuple[dict, int]:

    leaves = []
    paths  = []
    for j in range(k):
        leaf = buf[offset: offset + HASH_LEN]; offset += HASH_LEN
        path = []
        for _ in range(a):
            node = buf[offset: offset + HASH_LEN]; offset += HASH_LEN
            path.append(node)
        leaves.append(leaf)
        paths.append(path)
    return {"leaves": leaves, "paths": paths}, offset


def serialise_msg(msg: dict, k: int, a: int) -> bytes:

    out = bytearray()

    
    out += _pack_bytes(msg["id_l"])

    
    out += struct.pack(">I", msg["q"])

    
    assert len(msg["nonce"]) == NONCE_LEN
    out += msg["nonce"]

    
    out += _pack_bytes(msg["ciphertext"])

    out += serialise_sigma(msg["sigma"], k, a)

    assert len(msg["token"]) == HASH_LEN
    out += msg["token"]

    depth = len(msg["merkle_proof"])
    out += struct.pack(">H", depth)
    for node in msg["merkle_proof"]:
        assert len(node) == HASH_LEN
        out += node

    return bytes(out)


def deserialise_msg(buf: bytes, k: int, a: int) -> dict:
    offset = 0

    # ID_L
    id_l, offset    = _unpack_bytes(buf, offset)

    # q
    q = struct.unpack_from(">I", buf, offset)[0]; offset += 4

    # N_q
    nonce = buf[offset: offset + NONCE_LEN]; offset += NONCE_LEN

    # X_q
    ciphertext, offset = _unpack_bytes(buf, offset)

    # sigma_q
    sigma, offset = deserialise_sigma(buf, offset, k, a)

    # p_{L,q}
    token = buf[offset: offset + HASH_LEN]; offset += HASH_LEN

    # Omega_q
    depth = struct.unpack_from(">H", buf, offset)[0]; offset += 2
    merkle_proof_nodes = []
    for _ in range(depth):
        merkle_proof_nodes.append(buf[offset: offset + HASH_LEN])
        offset += HASH_LEN

    return {
        "id_l":         id_l,
        "q":            q,
        "nonce":        nonce,
        "ciphertext":   ciphertext,
        "sigma":        sigma,
        "token":        token,
        "merkle_proof": merkle_proof_nodes,
    }
