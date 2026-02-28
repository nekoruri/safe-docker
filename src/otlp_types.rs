//! OTLP (OpenTelemetry Protocol) type definitions for JSON serialization.
//!
//! These types replace the `opentelemetry-proto` crate dependency.
//! Only JSON serialization is supported (no gRPC/protobuf encoding).
//!
//! # Proto3 JSON Mapping Rules
//!
//! このモジュールの構造体は [proto3 JSON mapping] に準拠する。
//! フィールドを追加・変更する際は以下のルールを守ること。
//!
//! ## フィールド名
//! - `snake_case` → `lowerCamelCase` (`#[serde(rename_all = "camelCase")]`)
//!
//! ## デフォルト値の省略
//! proto3 ではデフォルト値を持つフィールドは JSON 出力から**省略すべき (should)**。
//! **全フィールドに適切な `skip_serializing_if` を付与すること。**
//!
//! | 型 | デフォルト値 | skip 条件 |
//! |---|---|---|
//! | `String` | `""` | `String::is_empty` |
//! | `Vec<T>` | `[]` | `Vec::is_empty` |
//! | `u64` | `0` | `is_zero_u64` |
//! | `u32` | `0` | `is_zero_u32` |
//! | `i32` | `0` | `is_zero_i32` |
//! | `Option<T>` | `None` | `Option::is_none` |
//! | `Vec<u8>` (bytes) | `[]` | `Vec::is_empty` |
//!
//! 例外: 構造的に必須な repeated フィールド（`resource_logs`, `scope_logs`,
//! `log_records`）は空でも省略しない。
//!
//! ## 型別シリアライズ
//! | proto3 型 | JSON 表現 | 備考 |
//! |---|---|---|
//! | `uint64`/`fixed64` | 文字列 `"123"` | `serialize_u64_as_string` |
//! | `int64` (AnyValue) | 文字列 `"42"` | JSON の number は 53bit 精度のため |
//! | `int32`/`uint32` | 数値 `9` | |
//! | `enum` | 数値 `9` | **OTLP 固有**: 文字列名ではなく整数値 |
//! | `bytes` | hex 文字列 | **OTLP 固有**: base64 ではなく hex (trace_id/span_id) |
//! | `oneof` (AnyValue) | variant key のみ | `{"stringValue": "..."}` |
//! | message (`Option`) | 省略 or object | `null` は使わない |
//!
//! [proto3 JSON mapping]: https://protobuf.dev/programming-guides/proto3/#json

use serde::Serialize;
use serde::ser::{SerializeStruct, Serializer};

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

fn is_zero_u64(v: &u64) -> bool {
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
    #[serde(
        serialize_with = "serialize_u64_as_string",
        skip_serializing_if = "is_zero_u64"
    )]
    pub time_unix_nano: u64,
    #[serde(
        serialize_with = "serialize_u64_as_string",
        skip_serializing_if = "is_zero_u64"
    )]
    pub observed_time_unix_nano: u64,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub severity_number: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub severity_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<AnyValue>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<KeyValue>,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub dropped_attributes_count: u32,
}

/// Information about the instrumentation library.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstrumentationScope {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
        assert_eq!(json["severityText"], "INFO");
        // Default-valued fields are omitted per proto3 JSON mapping
        assert!(json.get("body").is_none());
        assert!(json.get("attributes").is_none());
        assert!(json.get("droppedAttributesCount").is_none());
        assert!(json.get("flags").is_none());
        assert!(json.get("traceId").is_none());
        assert!(json.get("spanId").is_none());
    }

    #[test]
    fn test_log_record_zero_severity_omitted() {
        let record = LogRecord {
            time_unix_nano: 0,
            observed_time_unix_nano: 0,
            severity_number: 0,
            severity_text: String::new(),
            body: None,
            attributes: vec![],
            dropped_attributes_count: 0,
            flags: 0,
            trace_id: vec![],
            span_id: vec![],
        };
        let json = serde_json::to_value(&record).unwrap();
        assert!(json.get("severityNumber").is_none());
        assert!(json.get("severityText").is_none());
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
