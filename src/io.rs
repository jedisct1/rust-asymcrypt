use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

pub enum Input {
    Stdin(io::Stdin),
    File(BufReader<File>),
}

impl Input {
    pub fn open(path: Option<&Path>) -> Result<Self> {
        match path {
            None => Ok(Input::Stdin(io::stdin())),
            Some(p) if p.as_os_str() == "-" => Ok(Input::Stdin(io::stdin())),
            Some(p) => {
                let f = File::open(p).with_context(|| format!("opening {}", p.display()))?;
                Ok(Input::File(BufReader::new(f)))
            }
        }
    }
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Input::Stdin(s) => s.read(buf),
            Input::File(f) => f.read(buf),
        }
    }
}

pub enum Output {
    Stdout(BufWriter<io::Stdout>),
    Staged {
        writer: Option<BufWriter<NamedTempFile>>,
        dest: PathBuf,
        force: bool,
    },
}

impl Output {
    pub fn open(path: Option<&Path>, force: bool) -> Result<Self> {
        match path {
            None => Ok(Output::Stdout(BufWriter::new(io::stdout()))),
            Some(p) if p.as_os_str() == "-" => Ok(Output::Stdout(BufWriter::new(io::stdout()))),
            Some(dest) => {
                if dest.exists() && !force {
                    bail!("{} exists; pass --force to overwrite", dest.display());
                }
                let parent = parent_or_cwd(dest);
                let tmp = NamedTempFile::new_in(parent)
                    .with_context(|| format!("creating temp file in {}", parent.display()))?;
                Ok(Output::Staged {
                    writer: Some(BufWriter::new(tmp)),
                    dest: dest.to_path_buf(),
                    force,
                })
            }
        }
    }

    /// Finalise the output. On `Err`, the destination is untouched. On `Ok`,
    /// the rename succeeded; any post-rename directory-fsync error is
    /// reported via `CommitOutcome::dir_sync_warning` rather than `Err` so
    /// callers can continue with work that depends on a committed output.
    pub fn commit(self) -> Result<CommitOutcome> {
        match self {
            Output::Stdout(mut w) => {
                w.flush().context("flushing stdout")?;
                Ok(CommitOutcome {
                    dir_sync_warning: None,
                })
            }
            Output::Staged {
                mut writer,
                dest,
                force,
            } => {
                let writer = writer.take().expect("present until commit");
                let tmp = writer
                    .into_inner()
                    .map_err(|e| anyhow::anyhow!("flushing output: {}", e.into_error()))?;
                tmp.as_file().sync_all().context("syncing output")?;
                if force {
                    tmp.persist(&dest).map_err(|e| {
                        anyhow::anyhow!("renaming output to {}: {}", dest.display(), e.error)
                    })?;
                } else {
                    tmp.persist_noclobber(&dest).map_err(|e| {
                        anyhow::anyhow!("renaming output to {}: {}", dest.display(), e.error)
                    })?;
                }
                let dir_sync_warning = sync_dir(parent_or_cwd(&dest)).err();
                Ok(CommitOutcome { dir_sync_warning })
            }
        }
    }
}

#[must_use = "the post-commit warning should be reported even though commit succeeded"]
pub struct CommitOutcome {
    pub dir_sync_warning: Option<io::Error>,
}

impl CommitOutcome {
    pub fn warn(&self, what_committed: &str) {
        if let Some(e) = &self.dir_sync_warning {
            eprintln!(
                "asymcrypt: warning: {what_committed} but parent directory fsync failed: {e}"
            );
        }
    }
}

pub fn parent_or_cwd(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir).and_then(|d| d.sync_all())
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

impl Write for Output {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Output::Stdout(w) => w.write(buf),
            Output::Staged { writer, .. } => {
                writer.as_mut().expect("present until commit").write(buf)
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Output::Stdout(w) => w.flush(),
            Output::Staged { writer, .. } => writer.as_mut().expect("present until commit").flush(),
        }
    }
}

pub fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}
