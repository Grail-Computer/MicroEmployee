use std::path::Path;

use anyhow::Context;

const DEFAULT_AGENTS_MD: &str = include_str!("../defaults/AGENTS.md");
const DEFAULT_INDEX_MD: &str = include_str!("../defaults/context/INDEX.md");

pub async fn ensure_defaults(data_dir: &Path) -> anyhow::Result<()> {
    let context_dir = data_dir.join("context");
    tokio::fs::create_dir_all(&context_dir)
        .await
        .with_context(|| format!("create {}", context_dir.display()))?;

    // NOTE: Codex only searches for AGENTS.md in the current working directory
    // when no Git root is present. Our Codex cwd is `${GRAIL_DATA_DIR}/context`,
    // so place AGENTS.md there (not in `${GRAIL_DATA_DIR}`).
    let agents_path = context_dir.join("AGENTS.md");
    if tokio::fs::metadata(&agents_path).await.is_err() {
        tokio::fs::write(&agents_path, DEFAULT_AGENTS_MD)
            .await
            .with_context(|| format!("write {}", agents_path.display()))?;
    }

    let index_path = context_dir.join("INDEX.md");
    if tokio::fs::metadata(&index_path).await.is_err() {
        tokio::fs::write(&index_path, DEFAULT_INDEX_MD)
            .await
            .with_context(|| format!("write {}", index_path.display()))?;
    }

    Ok(())
}
