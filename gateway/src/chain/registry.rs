let feed = state
    .bee_client
    .put_object_and_update_pointer(&bucket, &key, body.clone())
    .await?;

state
    .anchor_client
    .submit_anchor_object(
        principal.owner,
        bucket_id,
        object_key_id,
        feed.soc_reference,
        bucket_manifest_root,
        body.len() as u64,
        etag,
    )
    .await?;
