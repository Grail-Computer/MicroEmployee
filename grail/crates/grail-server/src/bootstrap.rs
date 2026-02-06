use std::path::Path;

use anyhow::Context;

const DEFAULT_AGENTS_MD: &str = include_str!("../defaults/AGENTS.md");
const DEFAULT_INDEX_MD: &str = include_str!("../defaults/context/INDEX.md");

pub async fn ensure_defaults(data_dir: &Path) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(data_dir.join("context"))
        .await
        .with_context(|| format!("create {}", data_dir.join("context").display()))?;

    let agents_path = data_dir.join("AGENTS.md");
    if tokio::fs::metadata(&agents_path).await.is_err() {
        tokio::fs::write(&agents_path, DEFAULT_AGENTS_MD)
            .await
            .with_context(|| format!("write {}", agents_path.display()))?;
    }

    let index_path = data_dir.join("context").join("INDEX.md");
    if tokio::fs::metadata(&index_path).await.is_err() {
        tokio::fs::write(&index_path, DEFAULT_INDEX_MD)
            .await
            .with_context(|| format!("write {}", index_path.display()))?;
    }

    Ok(())
}

