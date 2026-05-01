use core::marker::PhantomData;

use cipher::{
    array::Array,
    typenum::{self, IsGreaterOrEqual, Unsigned},
    BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, Key, KeyInit, KeyIvInit, KeySizeUser,
    StreamCipher,
};
use zeroize::Zeroize;

use super::nh::NhPoly1305;

/// The Adiantum cipher. Implements `KeyInit` where key size is equal to key size of the underlying stream cipher.
pub struct Cipher<StreamAlg, BlockAlg>
where
    StreamAlg: KeySizeUser,
{
    key: Key<StreamAlg>,
    block: BlockAlg,
    hash: NhPoly1305,
    phantom_data: PhantomData<StreamAlg>,
}

impl<StreamAlg, BlockAlg> Drop for Cipher<StreamAlg, BlockAlg>
where
    StreamAlg: KeySizeUser,
{
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<StreamAlg, BlockAlg> KeySizeUser for Cipher<StreamAlg, BlockAlg>
where
    StreamAlg: KeySizeUser,
{
    type KeySize = StreamAlg::KeySize;
}

impl<StreamAlg, BlockAlg> KeyInit for Cipher<StreamAlg, BlockAlg>
where
    StreamAlg: KeyIvInit + StreamCipher,
    BlockAlg: KeyInit,
{
    fn new(key: &Key<Self>) -> Self {
        let mut nonce = Array::default();
        nonce[0] = 1;
        let mut stream = StreamAlg::new(key, &nonce);

        Cipher {
            key: key.clone(),
            block: {
                let mut key = Array::default();
                stream.apply_keystream(&mut key);
                BlockAlg::new(&key)
            },
            hash: NhPoly1305::new(&mut stream),
            phantom_data: PhantomData,
        }
    }
}

impl<StreamAlg, BlockAlg> Cipher<StreamAlg, BlockAlg>
where
    StreamAlg: KeyIvInit,
    StreamAlg::IvSize: IsGreaterOrEqual<typenum::U16>,
{
    fn stream(&self, r: &[u8; 0x10]) -> StreamAlg {
        let mut nonce = Array::default();
        nonce[..0x10].clone_from_slice(r);
        if <StreamAlg::IvSize as Unsigned>::USIZE > 0x10 {
            nonce[0x10] = 1;
        }
        StreamAlg::new(&self.key, &nonce)
    }
}

impl<StreamAlg, BlockAlg> Cipher<StreamAlg, BlockAlg>
where
    StreamAlg: KeyIvInit + StreamCipher,
    StreamAlg::IvSize: IsGreaterOrEqual<typenum::U16>,
    BlockAlg: BlockCipherEncrypt + BlockSizeUser<BlockSize = typenum::U16>,
{
    /// `page` length must be in 0x10..=0x1000 range and divisible by 0x10
    /// `tweak` must be not greater 0x20
    pub fn encrypt(&self, page: &mut [u8], tweak: &[u8]) {
        let (l, r) = split_last_chunk_mut::<_, 0x10>(page).unwrap();
        let hash = self.hash.compute(l, tweak);
        *r = u128::from_le_bytes(*r).wrapping_add(hash).to_le_bytes();
        self.block
            .encrypt_block(Array::slice_as_mut_array(&mut *r).unwrap());
        self.stream(r).apply_keystream(l);
        let hash = self.hash.compute(l, tweak);
        *r = u128::from_le_bytes(*r).wrapping_sub(hash).to_le_bytes();
    }
}

impl<StreamAlg, BlockAlg> Cipher<StreamAlg, BlockAlg>
where
    StreamAlg: KeyIvInit + StreamCipher,
    StreamAlg::IvSize: IsGreaterOrEqual<typenum::U16>,
    BlockAlg: BlockCipherDecrypt + BlockSizeUser<BlockSize = typenum::U16>,
{
    /// `page` length must be in 0x10..=0x1000 and divisible by 0x10
    /// `tweak` must be not greater 0x20
    pub fn decrypt(&self, page: &mut [u8], tweak: &[u8]) {
        let (l, r) = split_last_chunk_mut::<_, 0x10>(page).unwrap();
        let hash = self.hash.compute(l, tweak);
        *r = u128::from_le_bytes(*r).wrapping_add(hash).to_le_bytes();
        self.stream(r).apply_keystream(l);
        self.block
            .decrypt_block(Array::slice_as_mut_array(&mut *r).unwrap());
        let hash = self.hash.compute(l, tweak);
        *r = u128::from_le_bytes(*r).wrapping_sub(hash).to_le_bytes();
    }
}

#[rustversion::before(1.77)]
fn split_last_chunk_mut<T, const N: usize>(src: &mut [T]) -> Option<(&mut [T], &mut [T; N])> {
    if src.len() < N {
        None
    } else {
        let (init, last) = src.split_at_mut(src.len() - N);
        Some((init, unsafe { &mut *(last.as_mut_ptr().cast::<[T; N]>()) }))
    }
}

#[rustversion::since(1.77)]
fn split_last_chunk_mut<T, const N: usize>(src: &mut [T]) -> Option<(&mut [T], &mut [T; N])> {
    src.split_last_chunk_mut::<N>()
}
