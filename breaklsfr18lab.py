#!/usr/bin/env python3

from typing import List, Tuple, Dict

WIDTH_REG1 = 12
WIDTH_REG2 = 19

RAW_TAPS_REG1 = [2, 7]
RAW_TAPS_REG2 = [5, 11]

# PNG header
PNG_HEADER = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])


# LFSR parameters

def convert_taps(raw_taps: List[int], width: int) -> List[int]:
    
    taps = []
    for t in raw_taps:
        idx_from_msb_0based = t - 1               # 1-based -> 0-based from MSB
        pos_from_lsb = (width - 1) - idx_from_msb_0based
        taps.append(pos_from_lsb)
    return taps


def lfsr_next_bit(state: int, width: int, taps: List[int]) -> Tuple[int, int]:
    
    # Output bit
    out_bit = state & 1

    # Compute feedback bit from taps
    fb = 0
    for pos in taps:
        fb ^= (state >> pos) & 1

    # Right shift, insert feedback at MSB
    state >>= 1
    state |= (fb << (width - 1))
    # Mask to keep only 'width' bits
    state &= (1 << width) - 1

    return out_bit, state


def lfsr_next_byte(seed: int, width: int, taps: List[int]) -> Tuple[int, int]:
   
    state = seed
    b = 0
    for i in range(8):
        bit, state = lfsr_next_bit(state, width, taps)
        b |= (bit << i)
    return b, state


def lfsr_stream(seed: int, width: int, taps: List[int], nbytes: int) -> List[int]:
  
    state = seed
    out = []
    for _ in range(nbytes):
        b, state = lfsr_next_byte(state, width, taps)
        out.append(b)
    return out


# Meet-in-the-middle attack

def mitm_recover_seeds(keystream_header: List[int]) -> Tuple[int, int]:

    n = len(keystream_header)

    taps1 = convert_taps(RAW_TAPS_REG1, WIDTH_REG1)
    taps2 = convert_taps(RAW_TAPS_REG2, WIDTH_REG2)


    max_seed1 = 1 << WIDTH_REG1
    max_seed2 = 1 << WIDTH_REG2

    #  Precompute all possible sequences from LFSR2
    print(f"computing sequences for LFSR2 (0..{max_seed2 - 1})")
    seq_to_seed2: Dict[Tuple[int, ...], int] = {}

    for seed2 in range(max_seed2):
        seq2 = tuple(lfsr_stream(seed2, WIDTH_REG2, taps2, n))
        if seq2 not in seq_to_seed2:
            seq_to_seed2[seq2] = seed2

    print(f"Stored {len(seq_to_seed2)} unique sequences for LFSR2")

    # For each LFSR1 seed comapre to LSFR2 and look it up
    print(f"Iterating over LFSR1 seeds (0.{max_seed1 - 1})")
    for seed1 in range(max_seed1):
        seq1 = lfsr_stream(seed1, WIDTH_REG1, taps1, n)

        needed_seq2 = []
        for k, b1 in zip(keystream_header, seq1):
            b2 = (k - b1) % 255
            needed_seq2.append(b2)
        needed_seq2 = tuple(needed_seq2)

        seed2 = seq_to_seed2.get(needed_seq2)
        if seed2 is not None:
            print(f"Matched seeds: LFSR1={seed1}, LFSR2={seed2}")
            return seed1, seed2



def generate_full_keystream(seed1: int, seed2: int, nbytes: int) -> bytes:
   
    taps1 = convert_taps(RAW_TAPS_REG1, WIDTH_REG1)
    taps2 = convert_taps(RAW_TAPS_REG2, WIDTH_REG2)

    s1 = seed1
    s2 = seed2
    out = bytearray()

    for _ in range(nbytes):
        b1, s1 = lfsr_next_byte(s1, WIDTH_REG1, taps1)
        b2, s2 = lfsr_next_byte(s2, WIDTH_REG2, taps2)
        rnd = (b1 + b2) % 255
        out.append(rnd)

    return bytes(out)



def main():
    # Load ciphertext
    with open("flag.enc", "rb") as f:
        cipher = f.read()
    print(f"Loaded flag.enc ({len(cipher)} bytes)")

    # Derive first keystream bytes using known PNG header
    if len(cipher) < len(PNG_HEADER):
        raise RuntimeError("Ciphertext not valid")
    header_ct = cipher[:len(PNG_HEADER)]
    keystream_header = [c ^ p for c, p in zip(header_ct, PNG_HEADER)]
    print("Keystream header bytes:", keystream_header)

    # Meet in the middle to recover both LFSR seeds
    seed1, seed2 = mitm_recover_seeds(keystream_header)
    print(f" LFSR1={seed1}, LFSR2={seed2}")

    #  Generate full keystream and decrypt
    ks = generate_full_keystream(seed1, seed2, len(cipher))
    plain = bytes(c ^ k for c, k in zip(cipher, ks))

    # Write output PNG
    with open("flag.png", "wb") as f:
        f.write(plain)
    print("Wrote flag.png")

    if plain.startswith(PNG_HEADER):
        print("Decrypted file is completed")


if __name__ == "__main__":
    main()
