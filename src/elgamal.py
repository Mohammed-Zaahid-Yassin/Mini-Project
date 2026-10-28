"""
Lifted ElGamal public-key cryptosystem over NIST P-256 (secp256r1).
Additive homomorphic encryption for IoT sensor aggregation.
"""

from dataclasses import dataclass
import secrets
from typing import Tuple, Dict, Any
from fastecdsa.curve import P256
from fastecdsa.point import Point
from src.config import (
    P256_CURVE,
    G,
    CURVE_ORDER,
    FIELD_PRIME,
    POINT_SEC1_BYTES,
    POINT_INFINITY_BYTES,
)


def is_infinity(pt: Point) -> bool:
    """
    Determines whether an elliptic curve point is the Point at Infinity (identity element O).

    In elliptic curve cryptography, the Point at Infinity O serves as the additive identity:
        P + O = P
        P + (-P) = O
    It is not an ordinary Cartesian coordinate pair (X, Y) but a projective element where Z = 0.
    In fastecdsa, it is represented as a Point instance with z == 0 or string '<Point at Infinity>'.

    Args:
        pt: The Point object to inspect.

    Returns:
        True if pt is the point at infinity, False otherwise.
    """
    if pt is None:
        return False
    if hasattr(pt, "z") and pt.z == 0:
        return True
    if str(pt) == "<Point at Infinity>":
        return True
    try:
        return pt == (0 * P256.G)
    except Exception:
        return False


def get_infinity_point() -> Point:
    """Returns the canonical Point at Infinity O for P-256."""
    return 0 * P256.G


def is_point_on_curve(pt: Point, curve=P256_CURVE) -> bool:
    """
    Validates whether a given point lies on the specified Weierstrass elliptic curve.

    Curve equation:
        y^2 = x^3 + a*x + b  (mod p)

    Args:
        pt: The Point to check.
        curve: Elliptic curve definition (defaults to P-256).

    Returns:
        True if the point satisfies the curve equation or is the Point at Infinity.
    """
    if is_infinity(pt):
        return True

    if not isinstance(pt, Point):
        return False

    # Check finite field membership
    if not (0 <= pt.x < curve.p and 0 <= pt.y < curve.p):
        return False

    # Verify Weierstrass curve equation
    lhs = (pt.y * pt.y) % curve.p
    rhs = (pow(pt.x, 3, curve.p) + (curve.a * pt.x) + curve.b) % curve.p
    return lhs == rhs


def point_to_bytes(pt: Point) -> bytes:
    """
    Serializes an elliptic curve point into a canonical 65-byte fixed-width format.

    Format:
        - Affine Point: 0x04 || X (32 bytes big-endian) || Y (32 bytes big-endian)
        - Point at Infinity (O): 65 zero bytes (0x00 * 65)

    Why Canonical Fixed-Width Serialization is Critical:
        For HMAC authentication (Hop-1 and Hop-2), byte-level ambiguity allows malleability.
        By guaranteeing that every point is serialized to exactly 65 bytes, message boundary
        confusion and padding oracle vulnerabilities are avoided.

    Args:
        pt: Point on P-256.

    Returns:
        65-byte canonical representation.
    """
    if is_infinity(pt):
        return POINT_INFINITY_BYTES

    # Uncompressed SEC1 format with 32-byte big-endian coordinates
    x_bytes = pt.x.to_bytes(32, byteorder="big")
    y_bytes = pt.y.to_bytes(32, byteorder="big")
    return b"\x04" + x_bytes + y_bytes


def bytes_to_point(data: bytes, curve=P256_CURVE) -> Point:
    """
    Deserializes a 65-byte canonical byte string back into an elliptic curve Point on P-256.

    Args:
        data: 65-byte canonical representation.
        curve: Target curve (defaults to P-256).

    Returns:
        Deserialized Point object.

    Raises:
        ValueError: If byte length != 65, prefix is invalid, or coordinates are not on curve.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Expected bytes, got {type(data).__name__}")

    if len(data) != POINT_SEC1_BYTES:
        raise ValueError(
            f"Invalid point byte length: expected {POINT_SEC1_BYTES} bytes, got {len(data)}"
        )

    # Check for canonical Point at Infinity
    if data == POINT_INFINITY_BYTES or data == (b"\x00" * POINT_SEC1_BYTES):
        return get_infinity_point()

    if data[0] != 0x04:
        raise ValueError(
            f"Invalid uncompressed point prefix: {data[0]:#04x}, expected 0x04"
        )

    x = int.from_bytes(data[1:33], byteorder="big")
    y = int.from_bytes(data[33:65], byteorder="big")

    pt = Point(x, y, curve=curve)
    if not is_point_on_curve(pt, curve=curve):
        raise ValueError("Deserialized coordinates do not lie on curve P-256")

    return pt


@dataclass(frozen=True)
class Ciphertext:
    """
    Represents an EC Lifted ElGamal ciphertext pair (C1, C2).

    Mathematical Structure:
        C1 = r * G           (Ephemeral public key / blinding point)
        C2 = M * G + r * Y   (Message masked by shared Diffie-Hellman secret)

    Properties:
        Additive Homomorphism:
            CT_agg = CT_1 + CT_2 = (C1_1 + C1_2, C2_1 + C2_2)
                   = ((r_1 + r_2) * G, (M_1 + M_2) * G + (r_1 + r_2) * Y)
    """

    c1: Point
    c2: Point

    def __post_init__(self):
        """Validate points upon instantiation."""
        if not is_point_on_curve(self.c1):
            raise ValueError("Ciphertext C1 does not lie on curve P-256")
        if not is_point_on_curve(self.c2):
            raise ValueError("Ciphertext C2 does not lie on curve P-256")

    def to_bytes(self) -> bytes:
        """Serializes (C1, C2) to exactly 130 bytes (65 + 65)."""
        return point_to_bytes(self.c1) + point_to_bytes(self.c2)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Ciphertext":
        """Deserializes a 130-byte stream into a Ciphertext instance."""
        if len(data) != 130:
            raise ValueError(f"Ciphertext bytes must be exactly 130 bytes, got {len(data)}")
        c1 = bytes_to_point(data[:65])
        c2 = bytes_to_point(data[65:130])
        return cls(c1=c1, c2=c2)

    def to_dict(self) -> Dict[str, str]:
        """Provides a safe dictionary representation for inspection and JSON logging."""
        return {
            "c1_hex": point_to_bytes(self.c1).hex(),
            "c2_hex": point_to_bytes(self.c2).hex(),
            "c1_is_inf": is_infinity(self.c1),
            "c2_is_inf": is_infinity(self.c2),
        }


def generate_keypair() -> Tuple[int, Point]:
    """
    Generates a cryptographically secure P-256 keypair (x, Y).

    Security:
        - Private key x: scalar sampled uniformly from [1, q - 1] using CSPRNG (`secrets`).
        - Public key Y: scalar multiplication Y = x * G.

    Returns:
        Tuple of (private_key_scalar, public_key_point).
    """
    # Sample private key x uniformly in [1, CURVE_ORDER - 1]
    private_key = secrets.randbelow(CURVE_ORDER - 1) + 1
    public_key = private_key * G
    return private_key, public_key


def validate_keypair(private_key: int, public_key: Point) -> bool:
    """
    Validates whether a public key corresponds to a given private key.
    Never exposes or logs private_key.
    """
    if not isinstance(private_key, int) or isinstance(private_key, bool):
        return False
    if not (1 <= private_key < CURVE_ORDER):
        return False
    if not is_point_on_curve(public_key):
        return False
    return (private_key * G) == public_key


def encrypt(encoded_m: int, public_key: Point) -> Ciphertext:
    """
    Encrypts an encoded integer M using EC Lifted ElGamal.

    Mathematical Algorithm:
        1. Sample a fresh, cryptographically secure ephemeral scalar r in [1, q - 1].
        2. Compute blinding point: C1 = r * G.
        3. Compute shared secret point: S = r * Y.
        4. Compute encoded message point: M_pt = encoded_m * G.
        5. Mask message: C2 = M_pt + S = (encoded_m * G) + (r * Y).
        6. Return Ciphertext(C1, C2).

    Security Note:
        The ephemeral scalar r MUST be fresh and unpredictable for every single encryption.
        Reusing r across two ciphertexts allows an attacker to compute the difference between
        the plaintexts via: C2_a - C2_b = (M_a - M_b) * G.

    Args:
        encoded_m: Encoded integer message (scalar M).
        public_key: Decryptor's public key point Y.

    Returns:
        Ciphertext object containing (C1, C2).

    Raises:
        TypeError: If arguments are wrong types.
        ValueError: If public key is invalid or on wrong curve.
    """
    if not isinstance(encoded_m, int) or isinstance(encoded_m, bool):
        raise TypeError(f"Encoded message M must be an integer, got {type(encoded_m).__name__}")
    if not is_point_on_curve(public_key) or is_infinity(public_key):
        raise ValueError("Invalid public key: must be a valid non-identity point on P-256")

    # Sample fresh ephemeral scalar r using OS-level CSPRNG
    r = secrets.randbelow(CURVE_ORDER - 1) + 1

    # C1 = r * G
    c1 = r * G

    # C2 = (M * G) + (r * Y)
    # If encoded_m is 0, 0 * G is the point at infinity O
    m_point = encoded_m * G
    shared_secret = r * public_key
    c2 = m_point + shared_secret

    return Ciphertext(c1=c1, c2=c2)


def decrypt_point(ciphertext: Ciphertext, private_key: int) -> Point:
    """
    Computes the decrypted elliptic curve point P from a single Lifted ElGamal ciphertext.

    Formula:
        P = C2 - (x * C1)
          = (M * G + r * Y) - x * (r * G)
          = M * G + r(x * G) - r(x * G)
          = M * G

    IMPORTANT Cryptographic Boundary (Weeks 1–4):
        This function computes the curve point P = M * G.
        It does NOT solve the discrete logarithm problem to recover the integer scalar M.
        In standard Lifted ElGamal, plaintext recovery requires solving the Bounded ECDLP
        (e.g., using BSGS or Kangaroo in Weeks 5+).
        For Weeks 1–4, verification is performed against known test candidates.

    Args:
        ciphertext: Ciphertext pair (C1, C2).
        private_key: Private key scalar x.

    Returns:
        Decrypted curve point P = M * G.
    """
    if not isinstance(ciphertext, Ciphertext):
        raise TypeError(f"Expected Ciphertext instance, got {type(ciphertext).__name__}")
    if not isinstance(private_key, int) or isinstance(private_key, bool):
        raise TypeError(f"Private key must be integer, got {type(private_key).__name__}")
    if not (1 <= private_key < CURVE_ORDER):
        raise ValueError("Private key scalar is outside valid range [1, q - 1]")

    # Unmasking: P = C2 - (x * C1)
    shared_secret_c1 = private_key * ciphertext.c1
    p_decrypted = ciphertext.c2 - shared_secret_c1
    return p_decrypted
