// Copyright 2025, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Tests

use crate::{
    handle::PasswordHandle,
    traits::{HmacKey, HmacSha256, OpaqueOr, Rng},
    Error, FailureRecord,
};
use alloc::{vec, vec::Vec};
use gk_wire as wire;
use hal_wire::AsCborValue;
use wire::{MillisecondsSinceEpoch, SecureUserId};

#[test]
fn test_invalid_data() {
    // Cross-check that the hand-encoded invalid CBOR data matches an auto-encoded equivalent.
    let rsp = wire::PerformOpResponse::Err(wire::ApiStatus::GeneralFailure as i32);
    let rsp_data = rsp.into_vec().unwrap();
    assert_eq!(hex::encode(rsp_data), hex::encode(super::invalid_cbor_rsp_data()));
}

#[test]
fn test_failure_record_roundtrip() {
    let tests = [(1, 100, 0), (-1, -100, 5), (i64::MAX, 22593600, 5), (i64::MIN, 22593600, 5)];
    for (sid, ts, count) in tests {
        let want = FailureRecord {
            sid: SecureUserId(sid),
            last_checked_timestamp: MillisecondsSinceEpoch(ts),
            failure_counter: count,
        };
        let data = want.to_vec().unwrap();
        let got = FailureRecord::from_slice(&data).unwrap();
        assert_eq!(got, want, "for input {want:?}");
    }
}

#[test]
fn test_password_handle_roundtrip() {
    let hmac_key = OpaqueOr::Explicit(HmacKey(vec![1, 2, 3]));

    struct Fakery;
    impl HmacSha256 for Fakery {
        fn sign(&self, _key: &OpaqueOr<HmacKey>, _data: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(vec![0xdd; 32])
        }
    }
    impl Rng for Fakery {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(2);
        }
    }

    let want = PasswordHandle::new(
        &hmac_key,
        &Fakery,
        &mut Fakery,
        &wire::Password(vec![1, 2, 3]),
        SecureUserId(43),
    )
    .unwrap();
    let data = want.to_wire().unwrap();
    let got = PasswordHandle::from_wire(&data).unwrap();
    assert_eq!(got, want)
}

#[test]
fn test_retry_timeout() {
    const ONE_DAY: u32 = 24 * 60 * 60 * 1000;
    let tests = [
        (0, 0),
        (1, 0),
        (1, 0),
        (5, 30_000),
        (6, 0),
        (7, 0),
        (8, 0),
        (9, 0),
        (10, 0),
        (11, 30_000),
        (18, 30_000),
        (22, 30_000),
        (29, 30_000),
        (30, 30_000),
        (31, 30_000),
        (32, 30_000),
        (39, 30_000),
        (40, 60_000),
        (49, 60_000),
        (50, 120_000),
        (59, 120_000),
        (60, 240_000),
        (69, 240_000),
        (70, 480_000),
        (79, 480_000),
        (80, 960_000),
        (89, 960_000),
        (90, 1_920_000),
        (99, 1_920_000),
        (100, 3_840_000),
        (109, 3_840_000),
        (110, 7_680_000),
        (119, 7_680_000),
        (120, 15_360_000),
        (129, 15_360_000),
        (130, 30_720_000),
        (139, 30_720_000),
        (140, ONE_DAY),
        (141, ONE_DAY),
        (14100, ONE_DAY),
    ];
    for (count, want) in tests {
        let record = FailureRecord {
            sid: SecureUserId(1),
            last_checked_timestamp: MillisecondsSinceEpoch(1),
            failure_counter: count,
        };
        let got = record.compute_retry_timeout();
        assert_eq!(got, want, "for count={count}");
    }
}
