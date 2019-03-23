//! This eax implementation uses a block cipher in counter mode for encryption
//! and the block cipher in CBC mode to generate the OMAC/CMAC/CBCMAC.
//!
//! EAX is an AEAD (Authenticated Encryption with Associated Data) encryption
//! scheme.

use block_cipher_trait::generic_array::functional::FunctionalSequence;
use block_cipher_trait::generic_array::typenum::U16;
use block_cipher_trait::generic_array::{ArrayLength, GenericArray};
use block_cipher_trait::BlockCipher;
use cmac::crypto_mac::MacResult;
use cmac::{Cmac, Mac};
use ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use subtle::ConstantTimeEq;

pub struct Eax<C: BlockCipher<BlockSize = U16> + Clone>
where C::ParBlocks: ArrayLength<GenericArray<u8, U16>>
{
	phantom: std::marker::PhantomData<C>,
}

impl<C: BlockCipher<BlockSize = U16> + Clone> Eax<C>
where C::ParBlocks: ArrayLength<GenericArray<u8, U16>>
{
	/// Encrypt and authenticate data.
	///
	/// # Arguments
	/// - `key`: The key to use for encryption.
	/// - `nonce`: The nonce to use for encryption.
	/// - `header`: Associated data, which will also be authenticated.
	/// - `data`: The data which will be encrypted in-place.
	///
	/// # Return value
	/// tag/mac
	pub fn encrypt(
		key: &GenericArray<u8, C::KeySize>,
		nonce: &GenericArray<u8, C::KeySize>,
		header: &[u8],
		data: &mut [u8],
	) -> GenericArray<u8, <Cmac<C> as Mac>::OutputSize>
	{
		// https://crypto.stackexchange.com/questions/26948/eax-cipher-mode-with-nonce-equal-header
		// has an explanation of eax.

		// l = block cipher size = 128 (for AES-128) = 16 byte
		// 1. n ← OMAC(0 || Nonce)
		// (the 0 means the number zero in l bits)
		let n = Self::cmac_with_iv(key, 0, nonce).code();

		// 2. h ← OMAC(1 || associated data)
		let h = Self::cmac_with_iv(key, 1, header).code();

		// 3. enc ← CTR(M) using n as iv
		let mut cipher = ctr::Ctr128::<C>::new(key, &n);
		cipher.apply_keystream(data);

		// 4. c ← OMAC(2 || enc)
		let c = Self::cmac_with_iv(key, 2, data).code();

		// 5. tag ← n ^ h ^ c
		// (^ means xor)
		n.zip(h, |a, b| a ^ b).zip(c, |a, b| a ^ b)
	}

	/// Check authentication and decrypt data.
	pub fn decrypt(
		key: &GenericArray<u8, C::KeySize>,
		nonce: &GenericArray<u8, C::KeySize>,
		header: &[u8],
		data: &mut [u8],
		mac: &[u8],
	) -> Result<(), cmac::crypto_mac::MacError>
	{
		// 2. n ← OMAC(0 || Nonce)
		let n = Self::cmac_with_iv(key, 0, nonce).code();

		// 2. h ← OMAC(1 || associated data)
		let h = Self::cmac_with_iv(key, 1, header).code();

		// 4. c ← OMAC(2 || enc)
		let c = Self::cmac_with_iv(key, 2, data).code();

		let mac2 = n.zip(h, |a, b| a ^ b).zip(c, |a, b| a ^ b);

		// Take only the needed length
		let mac2 = &mac2[..mac.len()];

		// Check mac using secure comparison
		if mac.ct_eq(mac2).unwrap_u8() != 1 {
			return Err(cmac::crypto_mac::MacError);
		}

		// Decrypt
		let mut cipher = ctr::Ctr128::<C>::new(key, &n);
		cipher.apply_keystream(data);
		Ok(())
	}

	/// CMAC/OMAC1
	///
	/// To avoid constructing new buffers on the heap, an iv encoded into 16
	/// bytes is prepended inside this function.
	fn cmac_with_iv(
		key: &GenericArray<u8, C::KeySize>,
		iv: u8,
		data: &[u8],
	) -> MacResult<<Cmac<C> as Mac>::OutputSize>
	{
		let mut mac = Cmac::<C>::new(key);
		mac.input(&[0; 15]);
		mac.input(&[iv]);
		mac.input(data);

		mac.result()
	}
}
