import unittest

import generate_wallet as gw


class PublishedVectorTests(unittest.TestCase):
    def test_bip39_official_vector_entropy_to_mnemonic_and_seed(self):
        entropy = bytes.fromhex('00000000000000000000000000000000')
        words = gw.Mnemonic('english').to_mnemonic(entropy)
        self.assertEqual(words, 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
        seed = gw.Mnemonic('english').to_seed(words, 'TREZOR').hex()
        self.assertEqual(seed, 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553'
                               '1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04')

    def test_slip0010_ed25519_vector_1_master_and_m_0h(self):
        seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        k, c = gw.slip10_ed25519_master(seed)
        self.assertEqual(k.hex(), '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7')
        self.assertEqual(c.hex(), '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb')
        self.assertEqual((b'\x00' + gw.nacl.signing.SigningKey(k).verify_key.encode()).hex(),
                         '00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed')
        k, c = gw.slip10_ed25519_ckd(k, c, 0)
        self.assertEqual(k.hex(), '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3')
        self.assertEqual(c.hex(), '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69')
        self.assertEqual((b'\x00' + gw.nacl.signing.SigningKey(k).verify_key.encode()).hex(),
                         '008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c')

    def test_end_to_end_solana_bip39_to_phantom_address_golden_vector(self):
        words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        seed = gw.Mnemonic('english').to_seed(words, '')
        address, _secret32 = gw.sol_from_seed(seed, (44, 501, 0, 0))
        self.assertEqual(address, 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk')

    def test_end_to_end_solana_account_1_golden_vector(self):
        words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        seed = gw.Mnemonic('english').to_seed(words, '')
        address, _secret32 = gw.sol_from_seed(seed, (44, 501, 1, 0))
        self.assertEqual(address, 'Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb')

    def test_end_to_end_solana_passphrase_golden_vector(self):
        words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        seed = gw.Mnemonic('english').to_seed(words, 'TREZOR')
        address, _secret32 = gw.sol_from_seed(seed, (44, 501, 0, 0))
        self.assertEqual(address, '7zSmbu6gKkb6HB7UDPtHYjwCWuBHU1D4TpNZFm4sndQe')

    def test_solana_derivation_path_must_be_explicit(self):
        with self.assertRaises(TypeError):
            gw.sol_from_seed(b'0' * 64)

    def test_base58_known_vector(self):
        self.assertEqual(gw.b58encode(b'\x00\x00\x01'), '112')

    def test_hash_roll_quality_does_not_emit_von_neumann_pair_warning(self):
        rolls = [1, 2, 3, 4, 5, 6] * 25
        q = gw.analyze_roll_quality(rolls, None, None)
        self.assertNotIn('insufficient unbiased bit yield', q['warnings'])


if __name__ == '__main__':
    unittest.main()
