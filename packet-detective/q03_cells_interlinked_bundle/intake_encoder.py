"""TYRELL INTAKE MACHINE - TRANSCRIPT ENCODER (ROM DUMP)

Recovered from the intake bench, sector 2219-B.
The machine encodes every baseline transcript before filing:

  * each character of the transcript becomes TWO letters of the
    sixteen-letter wheel below (the first letter carries the character's
    high four bits, the second its low four bits)
  * every letter of that intermediate text is then shifted forward on
    the same wheel by ONE key letter

The key is not stored in this ROM. The machine's manual page, recovered
with it, reads:

        "THE KEY IS THE LAST LETTER OF THE CLEARANCE PHRASE."
        (intake desks receive their key letter with the nightly
         relay drop; the drop's clearance phrase ends on the key)

Filing format: transcripts are stored as the final shifted text, one
block per line, letters only.
"""

ALPHABET = "pabcdefghijklmno"          # the sixteen-letter wheel


def b16_encode(plain):
    enc = ""
    for c in plain:
        binary = "{0:08b}".format(ord(c))
        enc += ALPHABET[int(binary[:4], 2)]
        enc += ALPHABET[int(binary[4:], 2)]
    return enc


def shift(c, k):
    # Wheel-INDEX arithmetic (not letter-position): with a rotated
    # wheel, position-in-the-alphabet and index-in-the-wheel differ,
    # and only index math keeps encode/decode exact inverses.
    t1 = ALPHABET.index(c)
    t2 = ALPHABET.index(k)
    return ALPHABET[(t1 + t2) % len(ALPHABET)]


def encode(plain, key):
    key = key.strip().lower()          # the bench types N as often as n
    if len(key) != 1 or key not in ALPHABET:
        # audit minors register: a bare AssertionError gave players no
        # usage hint when they passed the whole clearance phrase
        raise ValueError(
            "key must be a single letter of the wheel %r (got %r)"
            % (ALPHABET, key))
    b16 = b16_encode(plain)
    return "".join(shift(c, key) for c in b16)


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3:
        print(encode(sys.argv[1], sys.argv[2]))
    else:
        print("usage: python3 intake_encoder.py <plaintext> <key letter>")
        print("  the machine filed this transcript with its nightly key.")
