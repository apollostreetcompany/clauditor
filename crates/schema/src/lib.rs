use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
	Start,
	Stop,
	Message,
	Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
	pub timestamp: DateTime<Utc>,
	pub pid: u32,
	pub uid: u32,
	pub event_kind: EventKind,
	pub session_id: String,
	pub prev_hash: Option<[u8; 32]>,
	pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
	HashMismatch { index: usize },
	GenesisPrevHashMustBeNone { found: Option<[u8; 32]> },
	Gap {
		index: usize,
		expected_prev_hash: [u8; 32],
		found_prev_hash: Option<[u8; 32]>,
	},
}

impl Event {
	pub fn new_genesis(
		key: &[u8],
		timestamp: DateTime<Utc>,
		pid: u32,
		uid: u32,
		event_kind: EventKind,
		session_id: impl Into<String>,
	) -> Self {
		let mut event = Self {
			timestamp,
			pid,
			uid,
			event_kind,
			session_id: session_id.into(),
			prev_hash: None,
			hash: [0u8; 32],
		};
		event.hash = event.compute_hash(key);
		event
	}

	pub fn new_next(
		key: &[u8],
		prev: &Event,
		timestamp: DateTime<Utc>,
		pid: u32,
		uid: u32,
		event_kind: EventKind,
		session_id: impl Into<String>,
	) -> Self {
		let mut event = Self {
			timestamp,
			pid,
			uid,
			event_kind,
			session_id: session_id.into(),
			prev_hash: Some(prev.hash),
			hash: [0u8; 32],
		};
		event.hash = event.compute_hash(key);
		event
	}

	pub fn compute_hash(&self, key: &[u8]) -> [u8; 32] {
		#[derive(Serialize)]
		struct HashInput<'a> {
			timestamp: &'a DateTime<Utc>,
			pid: u32,
			uid: u32,
			event_kind: &'a EventKind,
			session_id: &'a str,
			prev_hash: &'a Option<[u8; 32]>,
		}

		let input = HashInput {
			timestamp: &self.timestamp,
			pid: self.pid,
			uid: self.uid,
			event_kind: &self.event_kind,
			session_id: &self.session_id,
			prev_hash: &self.prev_hash,
		};

		let payload = serde_json::to_vec(&input).expect("hash input must serialize");

		let mut mac =
			HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
		mac.update(b"clauditor:event:v1:");
		mac.update(&payload);
		let digest = mac.finalize().into_bytes();

		let mut out = [0u8; 32];
		out.copy_from_slice(&digest);
		out
	}
}

pub fn verify_chain(events: &[Event], key: &[u8]) -> Result<(), VerifyError> {
	if events.is_empty() {
		return Ok(());
	}

	let first = &events[0];
	if first.prev_hash.is_some() {
		return Err(VerifyError::GenesisPrevHashMustBeNone {
			found: first.prev_hash,
		});
	}
	if first.compute_hash(key) != first.hash {
		return Err(VerifyError::HashMismatch { index: 0 });
	}

	for (idx, window) in events.windows(2).enumerate() {
		let prev = &window[0];
		let current = &window[1];
		let current_index = idx + 1;

		if current.prev_hash != Some(prev.hash) {
			return Err(VerifyError::Gap {
				index: current_index,
				expected_prev_hash: prev.hash,
				found_prev_hash: current.prev_hash,
			});
		}
		if current.compute_hash(key) != current.hash {
			return Err(VerifyError::HashMismatch {
				index: current_index,
			});
		}
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use chrono::TimeZone;

	const KEY: &[u8] = b"test-key";

	fn sample_chain() -> Vec<Event> {
		let session_id = "sess-1";
		let e0 = Event::new_genesis(
			KEY,
			Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
			123,
			1000,
			EventKind::Start,
			session_id,
		);
		let e1 = Event::new_next(
			KEY,
			&e0,
			Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 1).unwrap(),
			123,
			1000,
			EventKind::Message,
			session_id,
		);
		let e2 = Event::new_next(
			KEY,
			&e1,
			Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 2).unwrap(),
			123,
			1000,
			EventKind::Stop,
			session_id,
		);
		vec![e0, e1, e2]
	}

	#[test]
	fn serialization_round_trip() {
		let events = sample_chain();
		let json = serde_json::to_string(&events).unwrap();
		let decoded: Vec<Event> = serde_json::from_str(&json).unwrap();
		assert_eq!(events, decoded);
	}

	#[test]
	fn hash_chain_continuity() {
		let events = sample_chain();
		verify_chain(&events, KEY).unwrap();
	}

	#[test]
	fn tamper_detection() {
		let mut events = sample_chain();
		events[1].pid += 1;
		let err = verify_chain(&events, KEY).unwrap_err();
		assert_eq!(err, VerifyError::HashMismatch { index: 1 });
	}

	#[test]
	fn gap_detection() {
		let mut events = sample_chain();
		events.remove(1);
		let err = verify_chain(&events, KEY).unwrap_err();
		match err {
			VerifyError::Gap { index, .. } => assert_eq!(index, 1),
			other => panic!("expected Gap, got {other:?}"),
		}
	}
}

