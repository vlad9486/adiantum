use poly1305::Poly1305;
use cipher::{StreamCipher, KeyInit as _, array::Array};

const STRIDE: usize = 2;
const ROUNDS: usize = 4;
const W: usize = 4;
const MSG_SIZE: usize = 1024;

// TODO: use SIMD
fn nh(key: &[u8; MSG_SIZE + 2 * STRIDE * W * (ROUNDS - 1)], msg: &[u8]) -> [u8; 0x20] {
    use core::{slice, mem};

    let mut o = [0u64; 4];

    // messy and unsafe
    let mut key = {
        type T = [u32; 4];
        unsafe { slice::from_raw_parts(key.as_ptr().cast::<T>(), key.len() / mem::size_of::<T>()) }
    };

    for chunk in msg.chunks(16) {
        let mut msg_b = [0; 0x10];
        msg_b[..chunk.len()].clone_from_slice(chunk);
        let m0 = u32::from_le_bytes(msg_b[0x0..0x4].try_into().expect("cannot fail"));
        let m1 = u32::from_le_bytes(msg_b[0x4..0x8].try_into().expect("cannot fail"));
        let m2 = u32::from_le_bytes(msg_b[0x8..0xc].try_into().expect("cannot fail"));
        let m3 = u32::from_le_bytes(msg_b[0xc..].try_into().expect("cannot fail"));

        let [k0, k1, k2, k3] = key[0];
        let [k4, k5, k6, k7] = key[1];
        let [k8, k9, ka, kb] = key[2];
        let [kc, kd, ke, kf] = key[3];

        o[0] = o[0].wrapping_add(u64::from(m0.wrapping_add(k0)) * u64::from(m2.wrapping_add(k2)));
        o[1] = o[1].wrapping_add(u64::from(m0.wrapping_add(k4)) * u64::from(m2.wrapping_add(k6)));
        o[2] = o[2].wrapping_add(u64::from(m0.wrapping_add(k8)) * u64::from(m2.wrapping_add(ka)));
        o[3] = o[3].wrapping_add(u64::from(m0.wrapping_add(kc)) * u64::from(m2.wrapping_add(ke)));

        o[0] = o[0].wrapping_add(u64::from(m1.wrapping_add(k1)) * u64::from(m3.wrapping_add(k3)));
        o[1] = o[1].wrapping_add(u64::from(m1.wrapping_add(k5)) * u64::from(m3.wrapping_add(k7)));
        o[2] = o[2].wrapping_add(u64::from(m1.wrapping_add(k9)) * u64::from(m3.wrapping_add(kb)));
        o[3] = o[3].wrapping_add(u64::from(m1.wrapping_add(kd)) * u64::from(m3.wrapping_add(kf)));

        key = &key[1..];
    }

    unsafe { *o.as_ptr().cast() }
}

// TODO: load test vectors
#[cfg(test)]
#[test]
fn nh_test() {
    let key = hex::decode("225b80c81805370976144b67c4507f2b2cff56c5d566456835e6d29ae5d0c1fbac59811a60b03d814ba35ba9ccb3fe2dc24dd926ad36cf8c05113b8a991581c823f55a94102f928038c5b26380d5dca36c2faa03964a75334ca8600596bfe57ac84f5c22f992744a755fa22a8d3fe243fdd9048c8eea84cc4d3f9496ed1a51bb2fc46328310bda921e4de21d82b565b47569d76f29e4be7eccbd95bd7a62eafa33348058bffa007ea7b4c9327cc78f8a2827ddebb91c01adecf4305ece3baa2260bd84d99eafe84c44b6842d5ce626ee8aa20de397edf547db50724a5e9a8d10c225dd5bd039c45b2a7981b75cdaed771753b58b1e5ff34830ac977d29e3c918e12b31a008e9155929db842a33988ad4c3fcf7ca65024d9fe2b15ea66a01f9cf7ea609d91690145f3af8d83438d61f890c81c268c46578f3fe2748703843485ac124c56f65631bb05bb4071e69088ffc932904166a8bb33d0fba5f46fffe77a1b9dc29669ad108dd32e3217bcc2e5cf77968d4c18b3c5d0ed426a6199245f7190ea217d81c7f8dd668376cbfb18a5e364bc0ca210224699b2b190a1be3173057f6fcd6663630c211088dc58467a089c3744815ca6e0c6d7866157385f98bbab209da79e600082ada6bd7d1a78b5f1187961b23b06c55b686fbffe369ac43cd8f8ae71c3ca06ad5638066d87fb5b896d4e22040536d0d8b6dd55d51fb4d8082011497969b13b81d767aa1ca1990ec7be08ea8b4f233670e10b1a282ea8182a2c67851a6d325e49cf26ba8ecfbd41d5ba4796662b82b6f9e0fcccb9e926f06dbf097ce3f90a21fbe3b7b10f023300cc50c6c78fca87162cf98a2b144b5c63b5c63831d35f2c742675dc12636c86e1df6d55235a49ece4c3b922086b78963731a8ba635feb9df5e0e530bf2b34d341d66331f08f5f50aab7619de822fcf11a6cbb317ec8dafcbf0921eb8a3040aac2caec50bc44eef0ae2dae9d7752d95c71bf30b431916d7c6902d6be1b2cebed07d15992437bcb68c897a8ccba7f70b5fd4968df580a3cef59eed600092a567c921790bfbe2570edfb61690d375f6b0a34e439ab7f473d83446c6be80ec4ac07f9eb6b058c2aea1f360046211ea0f90a9ea6f0c4ccfe8d0eabfdbf2530c094dd4edf3221099c64fcfcf96c9d96b083bf0622dac5538d55c57ad51c3f5d23745b33f6daf106257b95840b33c6a98971a9ceb66f1a5930be78b290fff2cd090f267a069cdd359adadf11fd7ad247429cd06d54290f9964ad9a037e4648e132a2ae7c21ef6b2d3dc9f33320c5088378b9bfe6ffd0596266c967373e10928f37fa659c52ef4d3d5da6bca4205e5ed13e24ecdd5d0fb6ef78a3e919d6bc533050786b226416ef838387af06c275a01d803e59133aa20cda74f18a0912874c058270f9ba885b0e0fd5bdb5bb88679946dde26642d6cb9bac7f0d7aa6868d04071db945462a57f98eae34ce4449a03f91c2036eb0da4412406cb9486352262801916ba2c103896").unwrap();
    let msg = hex::decode("d382e70435ccf7a4f9b2c5ed5ad958eb").unwrap();
    let expected =
        hex::decode("41d9ad545a0dcc5348f64c75435ddd77daca7dec913b53165c4b58dc700a7b37").unwrap();

    let actual = nh(key.as_slice().try_into().unwrap(), &msg);
    assert_eq!(actual.as_slice(), &expected);
}

pub struct NhPoly1305 {
    t: Poly1305,
    m: Poly1305,
    key_nh: [u8; 0x430],
}

impl NhPoly1305 {
    pub fn new(kdf: &mut impl StreamCipher) -> Self {
        let mut key_t = [0; 0x20];
        kdf.apply_keystream(&mut key_t[..0x10]);
        let mut key_m = [0; 0x20];
        kdf.apply_keystream(&mut key_m[..0x10]);
        let mut key_nh = [0; 0x430];
        kdf.apply_keystream(&mut key_nh);

        NhPoly1305 {
            t: Poly1305::new(Array::slice_as_array(&key_t).unwrap()),
            m: Poly1305::new(Array::slice_as_array(&key_m).unwrap()),
            key_nh,
        }
    }

    /// `msg` length must be not greater 0x1000
    /// `tweak` must be not greater 0x20
    pub fn compute(&self, msg: &[u8], tweak: &[u8]) -> u128 {
        let t = self.compute_t(tweak, msg.len());
        let m = self.compute_m(msg);

        t.wrapping_add(m)
    }

    fn compute_t(&self, tweak: &[u8], len: usize) -> u128 {
        let mut t_buf = [0; 0x30];
        let len = u128::try_from(8 * len).expect("`usize` must be 128 bit or smaller");
        t_buf[..0x10].clone_from_slice(&len.to_le_bytes());
        t_buf[0x10..][..tweak.len()].clone_from_slice(tweak);
        let t = self
            .t
            .clone()
            .compute_unpadded(&t_buf[..(0x10 + tweak.len())]);
        u128::from_le_bytes(t.into())
    }

    fn compute_m(&self, msg: &[u8]) -> u128 {
        let mut m_buf = [0; 0x80];
        for (m_buf, msg) in m_buf.chunks_mut(32).zip(msg.chunks(0x400)) {
            m_buf.clone_from_slice(&nh(&self.key_nh, msg));
        }
        let n = div_ceil(msg.len(), 0x400);
        let m = self.m.clone().compute_unpadded(&m_buf[..(n * 0x20)]);
        u128::from_le_bytes(m.into())
    }
}

#[rustversion::before(1.73)]
fn div_ceil(a: usize, b: usize) -> usize {
    let d = a / b;
    let r = a % b;
    if r > 0 && b > 0 {
        d + 1
    } else {
        d
    }
}

#[rustversion::since(1.73)]
fn div_ceil(a: usize, b: usize) -> usize {
    a.div_ceil(b)
}

// TODO: load test vectors
#[cfg(test)]
#[test]
fn nh_poly1305_test() {
    let key = hex::decode("1b822e1b1723b96ddc9cda9907e35fd8d2f843808d867d801ad0cc13b911053f7ecf7e800ed825488baa638392d072f54f677e501825a4d1e07e1ebad8a76edb1acc0dfe9f6d2235e1e6e0a87b9cb166a3f8ff4d908428bcdc19c79149fcf633c96e657f286f682edf1a75e9c20c96b93122c407c60a2ffd36065f5cc5b13af45e48a4452b88a7eea98b52cc99d92fb8a4580a13eb715afae55ebef264ad75bc0b5b34133b23139a69301e9ab803b88b3e46186d38d9b3d8bff1d028e65157805e99fbd0ce1e83f7e9075a63a9efcea5fb3f3717fc0b370ebb4b2162b7830ea99eb0c4ad47be35e751b2f2ac2b657b48e33f5fb609040c58ce99a9152f4ec1f22448c0d86cd37617835de6e3fd018ef742a5042930dff9004adc71221a3315b6d772fb9ab8eb2b38eaa861a890119d732e6cce81545a9fcdcfd5bd265d66dbfbdc1e7c10fe588210162401ce675551d1dd6b44a3208ea9a606a829776e00385bde4d58d81f34dff92cac3eadfb920d7239a4ac4410c043c4a4773bfcc40d37d30584da5371f880d33444db09b42b8ee30075509e4322000b7c70abd441f193cd252d8474b5f292cd0a28ea9a490296cb859e2f3303861ddc1d31d5fc9daac5e99ac457f535edf44b3d34c229138636425dbf90861377e5c362b4fe0b7039356502eaf6ce570cbb7429e3fd6090fd1038d54e86bd3770f097a6ab3b836452ca662ff9a4ca3a556bb0e83a34db9e48502f3beffd082d5fc1375dbe73e4d8e9acca8aaa487c5cf4a6965ffa70a6b78b50cba6f5a9bd7b754c220b19402ec93939328303a8a498e68e16b9de08c5fcbfad39a8c7936c6f23afc1abe1dfbb39ae93290e7d808d3e65f3fd96066590a128644b69f9a8842750fc87f7bf558e5613587b85b46a720f40f14f83811f76de15647a7a80e4c75e630191d76bea0b9ba2993b6c88d8fd593c8d228656beaba137080150856929ee9fdf213e2020f5b0bb6bd09c4138ec546f2dbd0fe1bdf12b6e605629e57a701ce2fc97826867d93d1ffbd8079fbf9674ba6a0e104820d8131eb544f2ccb18bfbbbecd737701f7c55d24bb9fd705ea39173635213475a06fb0167a5c0d0491956669a7764af8c259152870e18f35f97fd7113f805a539cc65d3cc635bdb5f7e5f6eadc4f4a0c5c22b4d97384fbcfa3317b447b94324158dd2ed806884db0480ca5e6a352c2ce7c5035f54b05e4f1d40543d789aacda80274d154c1a6e80c9c43b840ed92e93018cc3c8914bb3aa0704685b93a5e7c49de707eef53b4089cc60349db4061bef92e6c12a7d0f81aa56e3d7eda7d4a73a49c4ad815c83558e9154b77d65a50616d59a16c1b0a206d89847737e73a0b823b152bf68745d0bcbfa8c46e324e6abd4698d8cf28a59be4846508c9ae8e331550a06ed4ff8b74fe3851730bdd520e75bb232cf6b1644d2f57ed7d12fee643e9d10ef2735436467fb7a7be062319a4ddfa5abc020bb01e97b54f1deb279506c4b91db7fbb50c15544389ae09fe8296f15f84ea6eca060").unwrap();
    let msg = hex::decode("15689e2fad1552dff04262242a2deabfc7f3b41af5edb20815601c0077bf0b0eb72ccf323ac70177efa675d029c76820b29225bf1234e9a4fd327b3f7cbda5023841dec9c109d9fc6e78228318f7508d8f9c2d02a530acffea632e803783b058da2fef2155ba7bb1b6edf5d24daa8ca9dddb0fb4cec19ab1c1dcbdab86c2df0be12cf9bef6d8da6272dd980952c0c4b67b175cf5d84b88d66bbf844a3ff54dd294e29cffc73cd9c83738bc8cf3e7b7d01d78c43907c85e79b65a905b6e97c9d4829cf3837ae797fc1dbbefdbcee082adca076c54626f81e67a5a966e803aa2376fc6a429c39e19949fb03e38fb3c2b7daab874da542351124b96368f914f193783c9ddc71a322dabc789e207476ce8a6706b8e0cda5c6a5927330ee1e120e8c8aedcd0e36da8a60641b4d4d4cf913e06b09af7f1aaa623921086f094d17c2e0730fbc5d8f312a9e8221c971aad96b0a1726a6bb4fdf7e8fae274d8658d35174b00235c8c70ad71a2cac56c59bfb4c06d86983e195a9092b166576a91687cbcf3f1db94f848f136d878ac1ca9ccd627ba915422f5e6053fccc28f2c3b2bc32b2b3bb8b629b72f94b67bfc943ed07a41597b1f9a09a6ed4a829d341cbd4e1c3a6680740e9a4f55544716ba2a0a033599a35c638da2728b1715683973ebecf2e8f5953227d6c4feb051d50c50c5cd6d16b3a31e9569ad789506b946f26d245a9976736a91a6ac12e12879bc084e97009863071c4ed168f3b381a8a65ff101c9c1af3a96f99db55a5f8f7ec17e770a40c88efc0eede10db0e55e5e6ff57fab337dcdf0094bb21137dc65973262713a2954b9c7a4bf750ff940a98dd78ba7e09abe15c6dad80014691aaf5f79c3f5bb6c2a9ddd3c5f9721e13a03846ae976111fd3d5f054204dc291c3a43625be1b2a06b7f3d1d05529814c83a3a6841e5cd1d06c90a411f0d7636a4805bc481853cdb08ddbdcfe55115c51b3abab633e315a8b936334a9ba2b691ac0e3cb41bcd7f57f823e01a33c72f4fedfbeb167172b37600dca6fc3942cd2926d9d751877aa293896ed0e207092d5d0b400c031f2c9430e751d4b64f21ff2296c7b7fec597d8c0dd4d3ac534ca3de4292956da34fd0e63de7ec7a4d68f1fe6766098322b198438cabb845e66ddf5e5071cef54e40932bfa860ee830bd82cc1c9c5fadfd0831be52e7e6f206016225159974335152573f578761b97f293dcd925ea65c3bf1ed5feb82ed567b61e7fd02470e2a15a4ce43869be12b4c2ad94297f79ae5474648d3556f4dd9eb4bdd7b212fb3a83628dfcaf1f6d910f61cfd2e0c27e001b3ff6d47084dd40025ee554ae9e85bd8f75612d450b2e5516f346369d24e964ebc79bf18aec613809277b0b40f29946f4cbb531136c39f428e968a91c8e9fcfebf7c2d6ff9b844891b09530a2a92c3547a3af9e2e47587a05e4b037a0d8af45559942b63960ef5").unwrap();
    let expected = hex::decode("b5b908b3243e03f0d60b57bc0a6d8959").unwrap();

    let mut key_st = [0; 0x20];
    key_st[..0x10].clone_from_slice(&key[..0x10]);
    let s = NhPoly1305 {
        t: Poly1305::new(Array::slice_as_array(&key_st).unwrap()),
        m: Poly1305::new(Array::slice_as_array(&key_st).unwrap()),
        key_nh: key[0x10..].try_into().unwrap(),
    };
    let actual = s.compute_m(&msg);
    assert_eq!(actual.to_le_bytes().as_slice(), &expected);
}
