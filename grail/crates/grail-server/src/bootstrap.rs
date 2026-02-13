use std::path::Path;

use anyhow::Context;

const DEFAULT_AGENTS_MD: &str = include_str!("../defaults/AGENTS.md");
const DEFAULT_INDEX_MD: &str = include_str!("../defaults/context/INDEX.md");
const DEFAULT_FIND_SKILLS_SKILL_MD: &str = include_str!("../defaults/skills/find-skills/SKILL.md");

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

    // Seed default skills for first-time installs.
    let find_skills_dir = context_dir
        .join(".agents")
        .join("skills")
        .join("find-skills");
    tokio::fs::create_dir_all(&find_skills_dir)
        .await
        .with_context(|| format!("create {}", find_skills_dir.display()))?;
    let find_skills_path = find_skills_dir.join("SKILL.md");
    if tokio::fs::metadata(&find_skills_path).await.is_err() {
        tokio::fs::write(&find_skills_path, DEFAULT_FIND_SKILLS_SKILL_MD)
            .await
            .with_context(|| format!("write {}", find_skills_path.display()))?;
    }

    Ok(())
}
