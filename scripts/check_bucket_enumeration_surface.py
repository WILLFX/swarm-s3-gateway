#!/usr/bin/env python3
from pathlib import Path

contract = Path("contracts/s3_bucket_contract/src/lib.rs").read_text()
abi = Path("gateway/src/contracts_abi.rs").read_text()
registry = Path("gateway/src/chain/registry.rs").read_text()
traits = Path("gateway/src/traits.rs").read_text()

required_contract = [
    "bucket_ids: Vec<[u8; 32]>",
    "bucket_index_plus_one: Mapping<[u8; 32], u64>",
    "owner_bucket_ids: Mapping<AccountId32, Vec<[u8; 32]>>",
    "owner_bucket_index_plus_one: Mapping<(AccountId32, [u8; 32]), u64>",
    "pub fn get_bucket_count",
    "pub fn list_bucket_ids",
    "pub fn get_owner_bucket_count",
    "pub fn list_owner_bucket_ids",
    "fn index_bucket",
    "fn unindex_bucket",
    "fn page_bucket_ids",
    "bucket_index_lists_created_buckets_with_pagination",
    "owner_bucket_index_is_scoped_by_owner",
    "delete_bucket_removes_ids_from_global_and_owner_indexes",
]

required_abi = [
    "BUCKET_GET_BUCKET_COUNT_SELECTOR",
    "BUCKET_LIST_BUCKET_IDS_SELECTOR",
    "BUCKET_GET_OWNER_BUCKET_COUNT_SELECTOR",
    "BUCKET_LIST_OWNER_BUCKET_IDS_SELECTOR",
    "pub fn encode_bucket_get_bucket_count",
    "pub fn encode_bucket_list_bucket_ids",
    "pub fn encode_bucket_get_owner_bucket_count",
    "pub fn encode_bucket_list_owner_bucket_ids",
    "encode_bucket_enumeration_reads_use_metadata_selectors",
]

required_registry = [
    "pub async fn get_bucket_count",
    "pub async fn list_bucket_ids",
    "pub async fn get_owner_bucket_count",
    "pub async fn list_owner_bucket_ids",
    "bucket::get_bucket_count",
    "bucket::list_bucket_ids",
    "bucket::get_owner_bucket_count",
    "bucket::list_owner_bucket_ids",
]

required_traits = [
    "async fn fetch_bucket_count",
    "async fn fetch_bucket_ids",
    "async fn fetch_owner_bucket_count",
    "async fn fetch_owner_bucket_ids",
]

for token in required_contract:
    if token not in contract:
        raise SystemExit(f"FAILED: missing bucket enumeration contract token: {token}")

for token in required_abi:
    if token not in abi:
        raise SystemExit(f"FAILED: missing bucket enumeration ABI token: {token}")

for token in required_registry:
    if token not in registry:
        raise SystemExit(f"FAILED: missing bucket enumeration registry token: {token}")

for token in required_traits:
    if token not in traits:
        raise SystemExit(f"FAILED: missing bucket enumeration trait token: {token}")

print("Bucket enumeration surface guard passed.")
