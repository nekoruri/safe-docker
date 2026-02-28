//! OTLP (OpenTelemetry Protocol) type definitions for JSON serialization.
//!
//! These types replace the `opentelemetry-proto` crate dependency.
//! Only JSON serialization is supported (no gRPC/protobuf encoding).
//! Field naming follows protobuf JSON mapping (`camelCase`).

use serde::Serialize;
use serde::ser::{SerializeStruct, Serializer};

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// Top-level OTLP Logs export request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportLogsServiceRequest {
    pub resource_logs: Vec<ResourceLogs>,
}

/// A collection of ScopeLogs from a Resource.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceLogs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
    pub scope_logs: Vec<ScopeLogs>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub schema_url: String,
}

/// A collection of LogRecords from an InstrumentationScope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeLogs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<InstrumentationScope>,
    pub log_records: Vec<LogRecord>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub schema_url: String,
}

/// A single log entry.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogRecord {
    #[serde(serialize_with = "serialize_u64_as_string")]
    pub time_unix_nano: u64,
    #[serde(serialize_with = "serialize_u64_as_string")]
    pub observed_time_unix_nano: u64,
    pub severity_number: i32,
    pub severity_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<AnyValue>,
    pub attributes: Vec<KeyValue>,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub dropped_attributes_count: u32,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub flags: u32,
    #[serde(
        serialize_with = "serialize_bytes_as_hex",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub trace_id: Vec<u8>,
    #[serde(
        serialize_with = "serialize_bytes_as_hex",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub span_id: Vec<u8>,
}

/// Information about the entity producing telemetry.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub attributes: Vec<KeyValue>,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub dropped_attributes_count: u32,
}

/// Information about the instrumentation library.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstrumentationScope {
    pub name: String,
    pub version: String,
    pub attributes: Vec<KeyValue>,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub dropped_attributes_count: u32,
}

/// A key-value pair for attributes.
#[derive(Debug, Serialize)]
pub struct KeyValue {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<AnyValue>,
}

/// A value that can be a string, int, or array.
///
/// Custom `Serialize` implementation produces protobuf JSON format:
/// - String → `{"stringValue": "..."}`
/// - Int    → `{"intValue": "123"}` (as string per protobuf JSON mapping)
/// - Array  → `{"arrayValue": {"values": [...]}}`
#[derive(Debug)]
pub struct AnyValue {
    pub kind: AnyValueKind,
}

/// The kind of value stored in an `AnyValue`.
#[derive(Debug)]
pub enum AnyValueKind {
    String(String),
    Int(i64),
    Array(ArrayValue),
}

/// An array of `AnyValue`.
#[derive(Debug, Serialize)]
pub struct ArrayValue {
    pub values: Vec<AnyValue>,
}

impl Serialize for AnyValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.kind {
            AnyValueKind::String(s) => {
                let mut state = serializer.serialize_struct("AnyValue", 1)?;
                state.serialize_field("stringValue", s)?;
                state.end()
            }
            AnyValueKind::Int(i) => {
                let mut state = serializer.serialize_struct("AnyValue", 1)?;
                state.serialize_field("intValue", &i.to_string())?;
                state.end()
            }
            AnyValueKind::Array(arr) => {
                let mut state = serializer.serialize_struct("AnyValue", 1)?;
                state.serialize_field("arrayValue", arr)?;
                state.end()
            }
        }
    }
}

fn serialize_u64_as_string<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn serialize_bytes_as_hex<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use std::fmt::Write;
    let mut hex = String::with_capacity(value.len() * 2);
    for b in value {
        let _ = write!(hex, "{:02x}", b);
    }
    serializer.serialize_str(&hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_any_value_string() {
        let v = AnyValue {
            kind: AnyValueKind::String("hello".to_string()),
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json, serde_json::json!({"stringValue": "hello"}));
    }

    #[test]
    fn test_any_value_int() {
        let v = AnyValue {
            kind: AnyValueKind::Int(42),
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json, serde_json::json!({"intValue": "42"}));
    }

    #[test]
    fn test_any_value_array() {
        let v = AnyValue {
            kind: AnyValueKind::Array(ArrayValue {
                values: vec![
                    AnyValue {
                        kind: AnyValueKind::String("a".to_string()),
                    },
                    AnyValue {
                        kind: AnyValueKind::String("b".to_string()),
                    },
                ],
            }),
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "arrayValue": {
                    "values": [
                        {"stringValue": "a"},
                        {"stringValue": "b"}
                    ]
                }
            })
        );
    }

    #[test]
    fn test_key_value() {
        let kv = KeyValue {
            key: "test.key".to_string(),
            value: Some(AnyValue {
                kind: AnyValueKind::String("test_value".to_string()),
            }),
        };
        let json = serde_json::to_value(&kv).unwrap();
        assert_eq!(json["key"], "test.key");
        assert_eq!(json["value"]["stringValue"], "test_value");
    }

    #[test]
    fn test_log_record_u64_as_string() {
        let record = LogRecord {
            time_unix_nano: 1234567890,
            observed_time_unix_nano: 1234567890,
            severity_number: 9,
            severity_text: "INFO".to_string(),
            body: None,
            attributes: vec![],
            dropped_attributes_count: 0,
            flags: 0,
            trace_id: vec![],
            span_id: vec![],
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["timeUnixNano"], "1234567890");
        assert_eq!(json["observedTimeUnixNano"], "1234567890");
        assert_eq!(json["severityNumber"], 9);
        assert!(json.get("traceId").is_none());
        assert!(json.get("spanId").is_none());
    }

    #[test]
    fn test_bytes_as_hex() {
        let record = LogRecord {
            time_unix_nano: 0,
            observed_time_unix_nano: 0,
            severity_number: 0,
            severity_text: String::new(),
            body: None,
            attributes: vec![],
            dropped_attributes_count: 0,
            flags: 0,
            trace_id: vec![0x01, 0x23, 0xab, 0xff],
            span_id: vec![0xde, 0xad],
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["traceId"], "0123abff");
        assert_eq!(json["spanId"], "dead");
    }

    #[test]
    fn test_full_export_request() {
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            kind: AnyValueKind::String("test-service".to_string()),
                        }),
                    }],
                    dropped_attributes_count: 0,
                }),
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        let json = serde_json::to_value(&request).unwrap();
        assert!(json["resourceLogs"].is_array());
        let resource = &json["resourceLogs"][0]["resource"];
        let attrs = resource["attributes"].as_array().unwrap();
        let svc = attrs.iter().find(|kv| kv["key"] == "service.name").unwrap();
        assert_eq!(svc["value"]["stringValue"], "test-service");
    }
}
