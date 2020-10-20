use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

criterion_group!(benches, bench_rsa, bench_ecdsa);
criterion_main!(benches);

const ECDSA_PRIVATE_KEY_PEM: &[u8] = include_bytes!("../keys/ec-secp256k1-private.pem");
const ECDSA_PUBLIC_KEY_PEM: &[u8] = include_bytes!("../keys/ec-secp256k1-public.pem");
const RSA_PRIVATE_KEY_PEM: &[u8] = include_bytes!("../keys/rsa-private.pem");
const RSA_PUBLIC_KEY_PEM: &[u8] = include_bytes!("../keys/rsa-public.pem");

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Claims {
    iat: u64,
    nbf: u64,
    exp: u64,
}

fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn bench_rsa(c: &mut Criterion) {
    let encoding_key = EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_PEM).unwrap();
    let decoding_key = DecodingKey::from_rsa_pem(RSA_PUBLIC_KEY_PEM).unwrap();

    let header = Header::new(Algorithm::RS256);
    let validation = Validation::new(Algorithm::RS256);

    let now = now();
    let claims = Claims {
        iat: now,
        nbf: now,
        exp: now + 3600,
    };

    c.bench_function("rs256_encode", |b| {
        b.iter(|| {
            let jwt = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();
            black_box(&jwt);
        });
    });

    let jwt = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

    c.bench_function("rs256_decode", |b| {
        b.iter(|| {
            let decoded_jwt =
                jsonwebtoken::decode::<Claims>(&jwt, &decoding_key, &validation).unwrap();
            black_box(&decoded_jwt);
        });
    });

    let decoded_jwt = jsonwebtoken::decode::<Claims>(&jwt, &decoding_key, &validation).unwrap();
    assert_eq!(claims, decoded_jwt.claims);
}

fn bench_ecdsa(c: &mut Criterion) {
    let encoding_key = EncodingKey::from_ec_pem(ECDSA_PRIVATE_KEY_PEM).unwrap();
    let decoding_key = DecodingKey::from_ec_pem(ECDSA_PUBLIC_KEY_PEM).unwrap();

    let header = Header::new(Algorithm::ES256);
    let validation = Validation::new(Algorithm::ES256);

    let now = now();
    let claims = Claims {
        iat: now,
        nbf: now,
        exp: now + 3600,
    };

    c.bench_function("es256_encode", |b| {
        b.iter(|| {
            let jwt = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();
            black_box(&jwt);
        });
    });

    let jwt = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

    c.bench_function("es256_decode", |b| {
        b.iter(|| {
            let decoded_jwt =
                jsonwebtoken::decode::<Claims>(&jwt, &decoding_key, &validation).unwrap();
            black_box(&decoded_jwt);
        });
    });

    let decoded_jwt = jsonwebtoken::decode::<Claims>(&jwt, &decoding_key, &validation).unwrap();
    assert_eq!(claims, decoded_jwt.claims);
}
