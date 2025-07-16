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
    let expected_timeouts_in_minutes = [
        /* 0  */ 0, //
        /* 1  */ 0, //
        /* 2  */ 0, //
        /* 3  */ 0, //
        /* 4  */ 0, //
        /* 5  */ 1, //
        /* 6  */ 5, //
        /* 7  */ 15, //
        /* 8  */ 30, //
        /* 9  */ 90, //
        /* 10 */ 243, // 3^(10-5) minutes = 4.05 hours
        /* 11 */ 729, // 3^(11-5) minutes = 12.15 hours
        /* 12 */ 2187, // 3^(12-5) minutes = 36.45 hours
        /* 13 */ 6561, // 3^(13-5) minutes = 4.56 days
        /* 14 */ 19683, // 3^(14-5) minutes = 13.67 days
        /* 15 */ 59049, // 3^(15-5) minutes = 41.01 days
        /* 16 */ 177147, // 3^(16-5) minutes = 123.02 days
        /* 17 */ 531441, // 3^(17-5) minutes = 1.01 years
        /* 18 */ 1594323, // 3^(18-5) minutes = 3.03 years
        /* 19 */ 4782969, // 3^(19-5) minutes = 9.09 years
    ];
    for count in 0..20 {
        let want = Ok(expected_timeouts_in_minutes[count as usize] * 60000);
        let record = FailureRecord {
            sid: SecureUserId(1),
            last_checked_timestamp: MillisecondsSinceEpoch(1),
            failure_counter: count,
        };
        let got = record.compute_retry_timeout();
        assert_eq!(got, want, "for count={count}");
    }
    for count in 20..100 {
        let want = Err(Error::RetryTimeout(i32::MAX));
        let record = FailureRecord {
            sid: SecureUserId(1),
            last_checked_timestamp: MillisecondsSinceEpoch(1),
            failure_counter: count,
        };
        let got = record.compute_retry_timeout();
        assert_eq!(got, want, "for count={count}");
    }
}
