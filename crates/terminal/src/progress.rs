//! Progress reports sent by programs running in the terminal.
//!
//! Programs report progress with the `OSC 9 ; 4 ; state ; value ST` sequence, a
//! ConEmu convention also understood by Windows Terminal, Ghostty and others.
//! `vte` does not parse it, so [`ProgressScanner`] watches the PTY output for it
//! alongside the regular parser.

/// The progress last reported by the program running in a terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalProgress {
    /// `state = 1`: work in progress, with a percentage.
    Normal(u8),
    /// `state = 2`: the work failed, with a percentage.
    Error(u8),
    /// `state = 3`: work in progress, with no known percentage.
    Indeterminate,
    /// `state = 4`: the work is paused, for example while waiting for input.
    Paused(u8),
}

impl TerminalProgress {
    /// Parses the parameters of an OSC sequence (the bytes between `ESC ]` and
    /// the terminator). Returns `None` when it is not a progress report, and
    /// `Some(None)` when it clears the progress.
    pub(crate) fn parse_osc(params: &[u8]) -> Option<Option<Self>> {
        let params = std::str::from_utf8(params).ok()?;
        let mut parts = params.split(';');
        if parts.next()? != "9" || parts.next()? != "4" {
            return None;
        }
        let state = parts.next().unwrap_or("0");
        let value = parts
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .map_or(0, |value| value.min(100) as u8);
        match state {
            "" | "0" => Some(None),
            "1" => Some(Some(Self::Normal(value))),
            "2" => Some(Some(Self::Error(value))),
            "3" => Some(Some(Self::Indeterminate)),
            "4" => Some(Some(Self::Paused(value))),
            _ => None,
        }
    }
}

/// Longest OSC we keep; `9;4;4;100` is nine bytes, so longer ones are not progress reports.
const MAX_PARAMS_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanState {
    Ground,
    Escape,
    Osc,
    OscEscape,
}

/// Incrementally finds `OSC 9 ; 4` progress reports in a byte stream, across
/// reads that may split a sequence anywhere.
#[derive(Debug)]
pub(crate) struct ProgressScanner {
    state: ScanState,
    params: Vec<u8>,
    overflowed: bool,
}

impl Default for ProgressScanner {
    fn default() -> Self {
        Self {
            state: ScanState::Ground,
            params: Vec::with_capacity(MAX_PARAMS_LEN),
            overflowed: false,
        }
    }
}

impl ProgressScanner {
    /// Feeds bytes and calls `on_progress` for every complete progress report.
    pub(crate) fn scan(
        &mut self,
        bytes: &[u8],
        mut on_progress: impl FnMut(Option<TerminalProgress>),
    ) {
        for &byte in bytes {
            match self.state {
                ScanState::Ground => {
                    if byte == 0x1b {
                        self.state = ScanState::Escape;
                    }
                }
                ScanState::Escape => match byte {
                    b']' => self.begin_osc(),
                    0x1b => {}
                    _ => self.state = ScanState::Ground,
                },
                ScanState::Osc => match byte {
                    0x07 => self.finish_osc(&mut on_progress),
                    0x1b => self.state = ScanState::OscEscape,
                    // CAN and SUB abort the sequence.
                    0x18 | 0x1a => self.state = ScanState::Ground,
                    _ => {
                        if self.params.len() < MAX_PARAMS_LEN {
                            self.params.push(byte);
                        } else {
                            self.overflowed = true;
                        }
                    }
                },
                ScanState::OscEscape => match byte {
                    b'\\' => self.finish_osc(&mut on_progress),
                    b']' => self.begin_osc(),
                    0x1b => self.state = ScanState::Escape,
                    _ => self.state = ScanState::Ground,
                },
            }
        }
    }

    fn begin_osc(&mut self) {
        self.state = ScanState::Osc;
        self.params.clear();
        self.overflowed = false;
    }

    fn finish_osc(&mut self, on_progress: &mut impl FnMut(Option<TerminalProgress>)) {
        self.state = ScanState::Ground;
        if !self.overflowed
            && let Some(progress) = TerminalProgress::parse_osc(&self.params)
        {
            on_progress(progress);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_all(chunks: &[&[u8]]) -> Vec<Option<TerminalProgress>> {
        let mut scanner = ProgressScanner::default();
        let mut reports = Vec::new();
        for chunk in chunks {
            scanner.scan(chunk, |progress| reports.push(progress));
        }
        reports
    }

    #[test]
    fn parses_every_state() {
        assert_eq!(
            scan_all(&[
                b"\x1b]9;4;1;42\x07\x1b]9;4;2\x07\x1b]9;4;3\x07\x1b]9;4;4;5\x07\x1b]9;4;0\x07"
            ]),
            vec![
                Some(TerminalProgress::Normal(42)),
                Some(TerminalProgress::Error(0)),
                Some(TerminalProgress::Indeterminate),
                Some(TerminalProgress::Paused(5)),
                None,
            ]
        );
    }

    #[test]
    fn accepts_string_terminator_and_clamps_value() {
        assert_eq!(
            scan_all(&[b"\x1b]9;4;1;250\x1b\\"]),
            vec![Some(TerminalProgress::Normal(100))]
        );
    }

    #[test]
    fn handles_sequences_split_across_reads() {
        assert_eq!(
            scan_all(&[b"text \x1b", b"]9;", b"4;3", b"\x1b", b"\\ more"]),
            vec![Some(TerminalProgress::Indeterminate)]
        );
    }

    #[test]
    fn ignores_other_sequences() {
        assert_eq!(
            scan_all(&[
                b"\x1b]0;\xf0\x9f\x9f\xa1 a long window title that overflows\x07",
                b"\x1b]9;a notification\x07",
                b"\x1b]9;4;7\x07",
                b"\x1b[31mred\x1b[0m",
            ]),
            vec![]
        );
    }

    #[test]
    fn recovers_after_an_aborted_sequence() {
        assert_eq!(
            scan_all(&[b"\x1b]9;4\x18\x1b]9;4;3\x07"]),
            vec![Some(TerminalProgress::Indeterminate)]
        );
    }
}
