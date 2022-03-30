use std::io::{self, Read};

const ROUND_CONSTANT: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn main() -> Result<(), std::io::Error> {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();

    let mut s256 = Sha256::new();

    loop {
        let read = s256.update(&mut stdin)?;
        if read != 64 {
            break;
        }
        s256.buffer.fill(0);
    }

    // Compute hash
    for c in s256.sum() {
        for b in c.to_be_bytes() {
            print!("{:02x?}", b);
        }
        //        print!(" ")
    }
    println!();

    Ok(())
}

struct Sha256 {
    state: [u32; 8],
    message_length: usize,
    buffer: [u8; 128],
    block_read: usize,
}

impl Sha256 {
    const fn new() -> Self {
        Self {
            state: IV,
            message_length: 0,
            buffer: [0; 128],
            block_read: 0,
        }
    }

    fn update<R: Read>(&mut self, r: &mut R) -> Result<usize, std::io::Error> {
        let read = r.read(&mut self.buffer[..64])?;

        self.block_read = read;
        self.message_length += read;

        self.compress();

        Ok(read)
    }

    fn sum(&mut self) -> [u32; 8] {
        if self.block_read != 64 {
            self.pad();
        }

        self.compress();

        self.state
    }

    fn pad(&mut self) {
        let pad_bytes_count = (self.message_length + 8) % 64;
        let filler_bytes = 64 - pad_bytes_count;
        let zero_bytes = filler_bytes - 1;

        // Append 0x80
        self.buffer[self.block_read] = 0x80;

        for i in self.block_read + 1..self.block_read + zero_bytes {
            self.buffer[i] = 0x0;
        }

        let message_length = (8 * self.message_length).to_be_bytes();

        self.buffer[self.block_read + zero_bytes + 1..self.block_read + zero_bytes + 1 + 8]
            .copy_from_slice(&message_length);
    }

    fn compress(&mut self) {
        let msg = self.message_schedule();

        let mut state = self.state;

        for i in 0..64 {
            state = round(state, ROUND_CONSTANT[i], msg[i]);
        }

        self.state[0] = self.state[0].wrapping_add(state[0]);
        self.state[1] = self.state[1].wrapping_add(state[1]);
        self.state[2] = self.state[2].wrapping_add(state[2]);
        self.state[3] = self.state[3].wrapping_add(state[3]);
        self.state[4] = self.state[4].wrapping_add(state[4]);
        self.state[5] = self.state[5].wrapping_add(state[5]);
        self.state[6] = self.state[6].wrapping_add(state[6]);
        self.state[7] = self.state[7].wrapping_add(state[7]);
    }

    fn message_schedule(&mut self) -> [u32; 64] {
        let mut block = [0u32; 64];
        for (i, buf) in self.buffer.chunks(4).enumerate() {
            block[i] = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
        }

        for i in 16..64 {
            block[i] = u32::wrapping_add(
                u32::wrapping_add(
                    u32::wrapping_add(block[i - 16], little_sigma0(block[i - 15])),
                    block[i - 7],
                ),
                little_sigma1(block[i - 2]),
            );
        }

        block
    }
}

#[inline]
const fn round(state: [u32; 8], round_constant: u32, word: u32) -> [u32; 8] {
    let ch = choice(state[4], state[5], state[6]);
    let tmp1 = u32::wrapping_add(
        u32::wrapping_add(state[7], big_sigma1(state[4])),
        u32::wrapping_add(u32::wrapping_add(ch, round_constant), word),
    );

    let maj = majority(state[0], state[1], state[2]);
    let tmp2 = u32::wrapping_add(big_sigma0(state[0]), maj);

    [
        u32::wrapping_add(tmp1, tmp2),
        state[0],
        state[1],
        state[2],
        u32::wrapping_add(state[3], tmp1),
        state[4],
        state[5],
        state[6],
    ]
}

#[inline]
const fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
const fn choice(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

// little_sigma0 is the substitution operation on blocks in sha256
#[inline]
const fn little_sigma0(x: u32) -> u32 {
    rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3)
}

#[inline]
const fn big_sigma0(x: u32) -> u32 {
    rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)
}

#[inline]
const fn little_sigma1(x: u32) -> u32 {
    rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10)
}

#[inline]
const fn big_sigma1(x: u32) -> u32 {
    rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)
}

#[inline]
const fn rotate_right(mut num: u32, rotate_by: u8) -> u32 {
    let mask = (1 << rotate_by) - 1;
    let bits = num & mask;

    num >>= rotate_by;

    num |= bits << (32 - rotate_by);

    num
}

#[test]
fn rotate_right_test() {
    assert_eq!(rotate_right(0b1111, 2), 0b11000000000000000000000000000011);
}

#[test]
fn sha256_test() {
    let mut s256 = Sha256::new();

    let expected_padded_input = {
        let mut tmp = [0; 128];

        for (i, c) in [
            b'\x80', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
            b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
            b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
            b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
            b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
            b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
            b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
            b'\x00',
        ]
        .iter()
        .enumerate()
        {
            tmp[i] = *c;
        }
        tmp
    };

    s256.pad();

    assert_eq!(expected_padded_input, s256.buffer);

    let expected_message = [
        2147483648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2147483648, 0, 2117632, 0,
        570427392, 0, 84448578, 2147483648, 1476919296, 4235264, 1451269, 1711282176, 3592562048,
        337794312, 3594910044, 3374850048, 3287351444, 676112230, 109604294, 2742808854,
        1904000662, 4274181962, 2813755136, 2165675682, 2561075048, 62000258, 1562224585,
        2975250741, 3286092305, 614207615, 3297584367, 1575308336, 3741240933, 748767245,
        1008022316, 30329261, 369937616, 195877528, 907775968, 3526495142, 43741191, 1967544444,
        133517113, 4161330627, 3704256008, 1581412744, 1153231965, 996066459,
    ];

    assert_eq!(expected_message, s256.message_schedule());

    let expected_compression = [
        3820012610, 2566659092, 2600203464, 2574235940, 665731556, 1687917388, 2761267483,
        2018687061,
    ];

    assert_eq!(expected_compression, s256.sum());
}

#[test]
fn sha256_test2() {
    let mut s256 = Sha256::new();
    s256.buffer = [0; 128];
    s256.buffer[0] = b'A';
    s256.buffer[1] = b'B';
    s256.buffer[2] = b'C';
    s256.block_read = 3;
    s256.message_length = 3;

    let expected_padded_input = {
        let mut tmp = [0; 128];

        for (i, c) in [
            65, 66, 67, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 24,
        ]
        .iter()
        .enumerate()
        {
            tmp[i] = *c;
        }
        tmp
    };

    s256.pad();

    assert_eq!(expected_padded_input, s256.buffer);

    let expected_message = [
        1094861696, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 1094861696, 983040, 1772124185,
        1610613702, 857076218, 25426944, 1187945132, 3267535758, 2652968984, 1864794538, 254335064,
        3289490897, 2024327239, 758282639, 1878924548, 2859021432, 1034160308, 3987916839,
        858236621, 2756660483, 2268060095, 3079286356, 3057658158, 3090293436, 2529363232,
        2137209215, 1745384904, 4207320789, 3927577153, 40024766, 478833927, 3105315289, 412113274,
        325510091, 369381143, 3582318330, 1812658626, 1738216777, 2045971039, 1268037967,
        3455161973, 3785832060, 1248694331, 4272040619, 2661585251, 1669237636, 3036669893,
        4247847033,
    ];

    assert_eq!(expected_message, s256.message_schedule());

    let expected_compression = [
        3050570844, 1061580713, 534957162, 3195609898, 441961969, 83337838, 1903036958, 663347064,
    ];

    assert_eq!(expected_compression, s256.sum());
}
