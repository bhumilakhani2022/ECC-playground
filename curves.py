# Preset curve definitions and utilities

from typing import Dict, Tuple

Curve = Dict[str, object]  # name, a, b, p, G (base point), n (order)

PRESET_CURVES = {
    'secp256k1': {
        'name': 'secp256k1',
        'a': 0,
        'b': 7,
        'p': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        'G': (55066263022277343669578718895168534326250603453777594175500187360389116729240,
              32670510020758816978083085130507043184471273380659243275938904335757337482424),
        'n': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    },
    'NIST P-192': {
        'name': 'NIST P-192',
        'a': -3,
        'b': 2455155546008943817740293915197451784769108058161191238065,
        'p': 6277101735386680763835789423207666416083908700390324961279,
        'G': (602046282375688656758213480587526111916698976636884684818,
              174050332293622031404857552280219410364023488927386650641),
        'n': 6277101735386680763835789423176059013767194773182842284081
    },
    'Toy Curve': {
        'name': 'Toy Curve',
        'a': 2,
        'b': 2,
        'p': 17,
        'G': (5, 1),
        'n': 19
    }
}

def get_preset_curves() -> Dict[str, Curve]:
    return PRESET_CURVES

def make_custom_curve(a: int, b: int, p: int, G: Tuple[int, int], n: int) -> Curve:
    return {'name': 'Custom', 'a': a, 'b': b, 'p': p, 'G': G, 'n': n}