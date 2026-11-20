//! Lossless, bounded NP ticket inspection and strict profile validation.
use crate::identity::{AccountId, OnlineId, SceNpId, ServiceId};
use alloc::vec::Vec;
use core::{fmt, ops::Range};

/// Version word shared by the two 2.1 profiles.
pub const VERSION_21: u32 = 0x2101_0000;
/// Version word for `Psn20`.
pub const VERSION_20: u32 = 0x2100_0000;
/// Version word for `Psn30`.
pub const VERSION_30: u32 = 0x3100_0000;
/// Entitlement extension section, retained opaque.
pub const ENTITLEMENT: u16 = 0x3001;
/// Age extension section.
pub const AGE: u16 = 0x3010;
/// Four-byte year/month/day field.
pub const DATE_OF_BIRTH: u16 = 0x3011;
/// Wire body section tag.
pub const BODY: u16 = 0x3000;
/// Wire footer section tag.
pub const FOOTER: u16 = 0x3002;

/// Explicit layout and footer-convention profile; never authenticates an issuer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Profile {
    /// `Rpcn21` layout and marker or exact unsigned-fallback footer,
    /// including its optional cookie.
    #[default]
    Rpcn21,
    /// `Psn20` layout with two empty tail fields, excluding RPCN footer conventions.
    Psn20,
    /// `Psn21` layout with empty/opaque entitlement tail, excluding RPCN footers.
    Psn21,
    /// `Psn30` layout with birthdate, status and age tail, excluding RPCN footers.
    /// Format conformance does not establish runtime compatibility.
    Psn30,
}
impl Profile {
    pub fn version(self) -> u32 {
        match self {
            Self::Rpcn21 | Self::Psn21 => VERSION_21,
            Self::Psn20 => VERSION_20,
            Self::Psn30 => VERSION_30,
        }
    }
}

/// Engineering ceilings, not platform protocol constants.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_ticket_bytes: usize,
    pub max_fields: usize,
    pub max_diagnostics: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_ticket_bytes: 65536,
            max_fields: 256,
            max_diagnostics: 32,
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub profile: Profile,
    /// Strict by default; Diagnostic retains partial matching-version fields.
    pub mode: ParseMode,
    pub limits: Limits,
}

/// Locations are absolute byte offsets in the original ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    start: usize,
    end: usize,
}
impl Span {
    pub fn range(self) -> Range<usize> {
        self.start..self.end
    }
    pub fn start(self) -> usize {
        self.start
    }
    pub fn end(self) -> usize {
        self.end
    }
    pub fn len(self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Code {
    TruncatedHeader,
    DeclaredLengthMismatch,
    UnsupportedVersion,
    /// The selected profile family contradicts the wire footer convention.
    ProfileMismatch,
    TruncatedField,
    MissingBody,
    DuplicateBody,
    MissingFooter,
    DuplicateFooter,
    UnexpectedSection,
    UnexpectedFieldType,
    InvalidWidth,
    InvalidText,
    InvalidPadding,
    MissingField,
    UnexpectedField,
    LimitExceeded,
}
/// Contains metadata only, never credential bytes or claim contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: Code,
    pub offset: usize,
    pub field_index: Option<usize>,
    pub expected: Option<usize>,
    pub actual: Option<usize>,
}
impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} at byte {}", self.code, self.offset)?;
        if self.code == Code::ProfileMismatch {
            write!(f, ": selected profile conflicts with footer convention")?;
        }
        if self.code == Code::UnsupportedVersion
            && let (Some(expected), Some(actual)) = (self.expected, self.actual)
        {
            write!(
                f,
                ": expected version {expected:#010x}, actual {actual:#010x}"
            )?;
        }
        Ok(())
    }
}
#[cfg(feature = "std")]
impl std::error::Error for Diagnostic {}

/// One complete TLV; bytes are borrowed and explicitly accessible.
#[derive(Clone)]
pub struct Field<'a> {
    tag: u16,
    span: Span,
    data: &'a [u8],
}
impl<'a> Field<'a> {
    pub fn tag(&self) -> u16 {
        self.tag
    }
    pub fn span(&self) -> Span {
        self.span
    }
    pub fn payload_span(&self) -> Span {
        Span {
            start: self.span.start + 4,
            end: self.span.end,
        }
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }
}
impl fmt::Debug for Field<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("tag", &self.tag)
            .field("span", &self.span)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug)]
pub struct Section<'a> {
    field: Field<'a>,
    fields: Vec<Field<'a>>,
}
impl<'a> Section<'a> {
    pub fn field(&self) -> &Field<'a> {
        &self.field
    }
    pub fn fields(&self) -> &[Field<'a>] {
        &self.fields
    }
}

/// Inspection result with original spans and unverified claims.
/// Diagnostic-mode results may be nonconformant; typed accessors reject them.
pub struct TicketReport<'a> {
    raw: &'a [u8],
    profile: Profile,
    version: Option<u32>,
    declared: Option<u32>,
    top: Vec<Field<'a>>,
    bodies: Vec<Section<'a>>,
    footers: Vec<Section<'a>>,
    diagnostics: Vec<Diagnostic>,
    first_error: Option<Diagnostic>,
    omitted: usize,
}
impl fmt::Debug for TicketReport<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketReport")
            .field("profile", &self.profile)
            .field("version", &self.version)
            .field("byte_length", &self.raw.len())
            .field("diagnostics", &self.diagnostics)
            .field("omitted_diagnostics", &self.omitted)
            .finish_non_exhaustive()
    }
}
impl<'a> TicketReport<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    /// Requested format profile; this is not an authenticated issuer.
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn version(&self) -> Option<u32> {
        self.version
    }
    pub fn declared_payload_length(&self) -> Option<u32> {
        self.declared
    }
    pub fn sections(&self) -> &[Field<'a>] {
        &self.top
    }
    pub fn bodies(&self) -> &[Section<'a>] {
        &self.bodies
    }
    pub fn footers(&self) -> &[Section<'a>] {
        &self.footers
    }
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
    pub fn omitted_diagnostics(&self) -> usize {
        self.omitted
    }
    pub fn first_error(&self) -> Option<Diagnostic> {
        self.first_error
    }
    /// Conforms to the requested profile, regardless of diagnostic retention cap.
    pub fn is_conformant(&self) -> bool {
        self.first_error.is_none()
    }
    fn issue(&mut self, limits: &Limits, d: Diagnostic) {
        self.first_error.get_or_insert(d);
        if self.diagnostics.len() < limits.max_diagnostics {
            self.diagnostics.push(d);
        } else {
            self.omitted += 1;
        }
    }
}
fn diagnostic(code: Code, offset: usize) -> Diagnostic {
    Diagnostic {
        code,
        offset,
        field_index: None,
        expected: None,
        actual: None,
    }
}
fn mismatch(code: Code, offset: usize, expected: usize, actual: usize) -> Diagnostic {
    Diagnostic {
        expected: Some(expected),
        actual: Some(actual),
        ..diagnostic(code, offset)
    }
}

// Walk complete TLVs only. No recursion or heuristic resynchronization.
fn walk<'a>(
    raw: &'a [u8],
    start: usize,
    end: usize,
    count: &mut usize,
    report: &mut TicketReport<'a>,
    limits: &Limits,
) -> Result<Vec<Field<'a>>, Diagnostic> {
    let mut fields = Vec::new();
    let mut pos = start;
    while pos < end {
        if end - pos < 4 {
            report.issue(limits, mismatch(Code::TruncatedField, pos, 4, end - pos));
            break;
        }
        if *count >= limits.max_fields {
            return Err(diagnostic(Code::LimitExceeded, pos));
        }
        *count += 1;
        let tag = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        let size = usize::from(u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]));
        // Subtraction establishes the parent bound before addition.
        if size > end - pos - 4 {
            report.issue(
                limits,
                mismatch(Code::TruncatedField, pos, size, end - pos - 4),
            );
            break;
        }
        let next = pos + 4 + size;
        fields.push(Field {
            tag,
            span: Span {
                start: pos,
                end: next,
            },
            data: &raw[pos + 4..next],
        });
        pos = next;
    }
    Ok(fields)
}

/// Inspect one explicitly selected profile. Incompatible versions return
/// UnsupportedVersion with expected/actual words before allocation or TLV work.
/// Opposite-family footer conventions return ProfileMismatch before TLV walking.
/// Strict (default): structural/profile defects return Err. Diagnostic mode in
/// Options retains partial matching-version fields; typed accessors reject
/// nonconformant reports. No result authenticates an issuer. Callers may retry
/// another allowed profile; this is the sole ticket parsing entry point.
pub fn inspect<'a>(raw: &'a [u8], options: &Options) -> Result<TicketReport<'a>, Diagnostic> {
    let report = inspect_diagnostic(raw, options)?;
    if options.mode == ParseMode::Strict
        && let Some(error) = report.first_error
    {
        return Err(error);
    }
    Ok(report)
}

// Existing diagnostic-mode decoding can recover partial matching-format fields.
// Version/family incompatibility is always terminal, even in diagnostic mode.
fn inspect_diagnostic<'a>(
    raw: &'a [u8],
    options: &Options,
) -> Result<TicketReport<'a>, Diagnostic> {
    let limits = &options.limits;
    if raw.len() > limits.max_ticket_bytes {
        return Err(diagnostic(Code::LimitExceeded, 0));
    }
    if raw.len() < 4 {
        return Err(mismatch(Code::TruncatedHeader, 0, 4, raw.len()));
    }
    let version = u32::from_be_bytes(raw[..4].try_into().expect("version checked"));
    if version != options.profile.version() {
        return Err(mismatch(
            Code::UnsupportedVersion,
            0,
            options.profile.version() as usize,
            version as usize,
        ));
    }
    if let Some(error) = footer_profile_mismatch(raw, options.profile) {
        return Err(error);
    }
    let mut report = TicketReport {
        raw,
        profile: options.profile,
        version: None,
        declared: None,
        top: Vec::new(),
        bodies: Vec::new(),
        footers: Vec::new(),
        diagnostics: Vec::new(),
        first_error: None,
        omitted: 0,
    };
    if raw.len() < 8 {
        report.issue(limits, mismatch(Code::TruncatedHeader, 0, 8, raw.len()));
        return Ok(report);
    }
    let version = u32::from_be_bytes(raw[0..4].try_into().expect("header checked"));
    let declared = u32::from_be_bytes(raw[4..8].try_into().expect("header checked"));
    report.version = Some(version);
    report.declared = Some(declared);
    if u64::from(declared) != (raw.len() - 8) as u64 {
        report.issue(limits, diagnostic(Code::DeclaredLengthMismatch, 4));
    }
    let mut count = 0;
    let top = walk(raw, 8, raw.len(), &mut count, &mut report, limits)?;
    for field in &top {
        if field.tag == BODY || field.tag == FOOTER {
            let fields = walk(
                raw,
                field.span.start + 4,
                field.span.end,
                &mut count,
                &mut report,
                limits,
            )?;
            let section = Section {
                field: field.clone(),
                fields,
            };
            if field.tag == BODY {
                report.bodies.push(section);
            } else {
                report.footers.push(section);
            }
        } else {
            report.issue(
                limits,
                diagnostic(Code::UnexpectedSection, field.span.start),
            );
        }
    }
    report.top = top;
    validate(&mut report, options);
    Ok(report)
}

// Skip the body using its bounded u16 length, not a scan or a TLV walk. Only
// classify an exact body/footer envelope with both complete footer fields;
// malformed/ambiguous envelopes continue to ordinary structural validation.
// The Rpcn21 convention is marker RPCN, or a zero marker together with
// exactly 56 zero signature bytes for its unsigned fallback.
fn footer_profile_mismatch(raw: &[u8], profile: Profile) -> Option<Diagnostic> {
    if raw.get(8..10)? != BODY.to_be_bytes() {
        return None;
    }
    let body_len = raw.get(10..12)?;
    let footer_at = 12 + usize::from(u16::from_be_bytes([body_len[0], body_len[1]]));
    let footer = raw.get(footer_at..)?;
    if footer.get(..2)? != FOOTER.to_be_bytes() {
        return None;
    }
    let len = footer.get(2..4)?;
    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
    if len + 4 != footer.len() || footer.get(4..8)? != [0, 8, 0, 4] {
        return None;
    }
    let marker = footer.get(8..12)?;
    if footer.get(12..14)? != [0, 8] {
        return None;
    }
    let len = footer.get(14..16)?;
    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
    let signature = footer.get(16..)?;
    if len != signature.len() {
        return None;
    }
    let rpcn_convention = marker == b"RPCN"
        || (marker == [0; 4] && signature.len() == 56 && signature.iter().all(|b| *b == 0));
    if rpcn_convention != (profile == Profile::Rpcn21) {
        Some(diagnostic(Code::ProfileMismatch, footer_at + 8))
    } else {
        None
    }
}

fn check_field(
    report: &mut TicketReport<'_>,
    limits: &Limits,
    field: &Field<'_>,
    index: usize,
    tag: u16,
    width: Option<usize>,
) {
    if field.tag != tag {
        let mut d = mismatch(
            Code::UnexpectedFieldType,
            field.span.start,
            usize::from(tag),
            usize::from(field.tag),
        );
        d.field_index = Some(index);
        report.issue(limits, d);
    }
    if let Some(width) = width
        && field.data.len() != width
    {
        let mut d = mismatch(
            Code::InvalidWidth,
            field.span.start + 2,
            width,
            field.data.len(),
        );
        d.field_index = Some(index);
        report.issue(limits, d);
    }
}
fn required_field(
    report: &mut TicketReport<'_>,
    limits: &Limits,
    body: &Section<'_>,
    index: usize,
    tag: u16,
    width: Option<usize>,
) {
    if let Some(field) = body.fields.get(index) {
        check_field(report, limits, field, index, tag, width);
    } else {
        let mut d = diagnostic(Code::MissingField, body.field.span.end);
        d.field_index = Some(index);
        report.issue(limits, d);
    }
}

fn padded_text(data: &[u8]) -> Result<&str, Code> {
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    if data[end..].iter().any(|b| *b != 0) {
        return Err(Code::InvalidPadding);
    }
    core::str::from_utf8(&data[..end]).map_err(|_| Code::InvalidText)
}
fn validate(report: &mut TicketReport<'_>, options: &Options) {
    let limits = &options.limits;
    for (n, missing, duplicate) in [
        (report.bodies.len(), Code::MissingBody, Code::DuplicateBody),
        (
            report.footers.len(),
            Code::MissingFooter,
            Code::DuplicateFooter,
        ),
    ] {
        if n != 1 {
            report.issue(
                limits,
                diagnostic(if n == 0 { missing } else { duplicate }, 8),
            );
        }
    }
    if report.top.len() != 2
        || report.top.first().map(|f| f.tag) != Some(BODY)
        || report.top.get(1).map(|f| f.tag) != Some(FOOTER)
    {
        report.issue(limits, diagnostic(Code::UnexpectedSection, 8));
    }
    // Only the explicitly selected version can reach schema validation.
    if report.version != Some(options.profile.version()) {
        return;
    }
    if report.bodies.len() == 1 {
        // Clone metadata/slices, never credential buffers; total fields are bounded.
        let body = report.bodies[0].clone();
        let schema = [
            (8, 20),
            (1, 4),
            (7, 8),
            (7, 8),
            (2, 8),
            (4, 32),
            (8, 4),
            (4, 4),
            (8, 24),
        ];
        for (i, (tag, width)) in schema.into_iter().enumerate() {
            if let Some(field) = body.fields.get(i) {
                check_field(report, limits, field, i, tag, Some(width));
                if matches!(i, 5 | 7 | 8)
                    && let Err(code) = padded_text(field.data)
                {
                    let mut d = diagnostic(code, field.span.start + 4);
                    d.field_index = Some(i);
                    report.issue(limits, d);
                }
            } else {
                let mut d = diagnostic(Code::MissingField, body.field.span.end);
                d.field_index = Some(i);
                report.issue(limits, d);
            }
        }
        if let Some(field) = body.fields.get(5)
            && let Ok(name) = padded_text(field.data)
            && name.len() > 16
        {
            let mut error = mismatch(Code::InvalidWidth, field.span.start + 4, 16, name.len());
            error.field_index = Some(5);
            report.issue(limits, error);
        }
        // Tail slots are version/profile-specific; no fallback between profiles.
        let status_index = if options.profile == Profile::Psn30 {
            10
        } else {
            9
        };
        required_field(report, limits, &body, status_index, 1, Some(4));
        match options.profile {
            Profile::Rpcn21 => {
                let len = body.fields.len();
                if len != 12 && len != 13 {
                    report.issue(
                        limits,
                        diagnostic(Code::UnexpectedField, body.field.span.end),
                    );
                }
                let empty_start = if len == 13 {
                    required_field(report, limits, &body, 10, 8, None);
                    if body.fields[10].data.is_empty() {
                        report.issue(
                            limits,
                            diagnostic(Code::InvalidWidth, body.fields[10].span.start),
                        );
                    }
                    11
                } else {
                    10
                };
                for i in empty_start..empty_start + 2 {
                    required_field(report, limits, &body, i, 0, Some(0));
                }
            }
            Profile::Psn20 | Profile::Psn21 => {
                if body.fields.len() != 12 {
                    report.issue(
                        limits,
                        diagnostic(Code::UnexpectedField, body.field.span.end),
                    );
                }
                if options.profile == Profile::Psn21
                    && body.fields.get(10).map(|f| f.tag) == Some(ENTITLEMENT)
                {
                    // Known extension container: preserve its payload as opaque bytes.
                    required_field(report, limits, &body, 10, ENTITLEMENT, None);
                } else {
                    required_field(report, limits, &body, 10, 0, Some(0));
                }
                required_field(report, limits, &body, 11, 0, Some(0));
            }
            Profile::Psn30 => {
                if body.fields.len() != 13 {
                    report.issue(
                        limits,
                        diagnostic(Code::UnexpectedField, body.field.span.end),
                    );
                }
                required_field(report, limits, &body, 9, DATE_OF_BIRTH, Some(4));
                required_field(report, limits, &body, 11, AGE, Some(0));
                required_field(report, limits, &body, 12, 0, Some(0));
            }
        }
    }
    if report.footers.len() == 1 {
        let footer = report.footers[0].clone();
        if footer.fields.len() != 2 {
            report.issue(
                limits,
                diagnostic(Code::UnexpectedField, footer.field.span.start),
            );
        }
        if let Some(marker) = footer.fields.first() {
            check_field(report, limits, marker, 0, 8, Some(4));
        }
        if let Some(signature) = footer.fields.get(1) {
            check_field(report, limits, signature, 1, 8, None);
            if signature.data.is_empty() {
                report.issue(limits, diagnostic(Code::InvalidWidth, signature.span.start));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixMillis(pub u64);
/// Unverified claims: identity values are owned Copy types; serial, region and
/// domain borrow the ticket. Debug never prints values.
#[derive(Clone, Copy)]
pub struct Claims<'a> {
    pub serial: &'a [u8],
    pub issuer_id: u32,
    pub issued: UnixMillis,
    pub expires: UnixMillis,
    /// Owned numeric account claim; extract with `u64::from(claims.account_id)`.
    pub account_id: AccountId,
    /// Logical identity from the ticket; original platform bytes are absent.
    pub np_id: SceNpId,
    pub region: &'a [u8],
    pub domain: &'a str,
    /// Owned exact 24-byte service claim, including original padding.
    pub service_id: ServiceId,
    /// Complete packed age/status word; interpretation is caller policy.
    pub status: u32,
    /// Present in the 3.0 layout; calendar validity is not asserted.
    pub date_of_birth: Option<BirthDate>,
}
/// Raw birthdate components. Debug redacts these personal values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BirthDate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}
impl fmt::Debug for BirthDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BirthDate([redacted])")
    }
}
impl fmt::Debug for Claims<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Claims([redacted, unverified])")
    }
}
impl<'a> TicketReport<'a> {
    fn require_conformant(&self) -> Result<(), Diagnostic> {
        match self.first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    /// Acquire typed, unverified claims from the already-parsed result.
    /// Copy out account_id/np_id/service_id to retain them independently of input;
    /// remaining raw views continue to borrow the original ticket.
    /// No second parse or allocation. Partial diagnostic results return Err.
    pub fn claims(&self) -> Result<Claims<'a>, Diagnostic> {
        self.require_conformant()?;
        let fields = &self.bodies[0].fields;
        let u64_at =
            |i: usize| u64::from_be_bytes(fields[i].data.try_into().expect("validated width"));
        let u32_at =
            |i: usize| u32::from_be_bytes(fields[i].data.try_into().expect("validated width"));
        Ok(Claims {
            serial: fields[0].data,
            issuer_id: u32_at(1),
            issued: UnixMillis(u64_at(2)),
            expires: UnixMillis(u64_at(3)),
            account_id: AccountId::from(u64_at(4)),
            np_id: SceNpId::from(
                OnlineId::try_from(padded_text(fields[5].data).expect("validated text"))
                    .expect("validated name width"),
            ),
            region: fields[6].data,
            domain: padded_text(fields[7].data).expect("validated text"),
            service_id: ServiceId::try_from(fields[8].data).expect("validated service width"),
            status: u32_at(if self.profile == Profile::Psn30 {
                10
            } else {
                9
            }),
            date_of_birth: if self.profile == Profile::Psn30 {
                let bytes = fields[9].data;
                Some(BirthDate {
                    year: u16::from_be_bytes([bytes[0], bytes[1]]),
                    month: bytes[2],
                    day: bytes[3],
                })
            } else {
                None
            },
        })
    }
    /// Original body including its TLV header, for the `Rpcn21` signing span.
    /// This method performs no cryptographic operation.
    pub fn rpcn_signed_bytes(&self) -> Result<&'a [u8], Diagnostic> {
        self.require_conformant()?;
        Ok(&self.raw[self.bodies[0].field.span.range()])
    }
    /// Original prefix ending before the signature payload.
    /// No algorithm/key selection or verification occurs.
    pub fn psn_signed_bytes(&self) -> Result<&'a [u8], Diagnostic> {
        self.require_conformant()?;
        Ok(&self.raw[..self.footers[0].fields[1].payload_span().start])
    }
    /// Opaque entitlement content in a conformant `Psn21` tail, if present.
    /// This validates its outer boundary only, not individual entitlement records.
    pub fn entitlement_bytes(&self) -> Result<Option<&'a [u8]>, Diagnostic> {
        self.require_conformant()?;
        let fields = &self.bodies[0].fields;
        Ok(
            if self.profile == Profile::Psn21 && fields[10].tag == ENTITLEMENT {
                Some(fields[10].data)
            } else {
                None
            },
        )
    }
    pub fn signature_bytes(&self) -> Result<&'a [u8], Diagnostic> {
        self.require_conformant()?;
        Ok(self.footers[0].fields[1].data)
    }
    pub fn key_marker(&self) -> Result<&'a [u8], Diagnostic> {
        self.require_conformant()?;
        Ok(self.footers[0].fields[0].data)
    }
}
/// Validity-window defect from [`Claims::check_time`]. Metadata only, never timestamps or claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeError {
    InvalidRange,
    NotYetValid,
    Expired,
}
impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for TimeError {}

impl Claims<'_> {
    /// Two's-complement signed 32-bit view of the raw wire `issuer_id`.
    /// Useful for signed range checks without `u32` wraparound; never authenticates an issuer.
    pub const fn issuer_id_i32(&self) -> i32 {
        self.issuer_id as i32
    }
    /// Pure validity-window check with caller-supplied clock and skew tolerance.
    /// Performs no clock access, replay check, or signature verification.
    pub const fn check_time(&self, now: UnixMillis, clock_skew_ms: u64) -> Result<(), TimeError> {
        if self.expires.0 <= self.issued.0 {
            return Err(TimeError::InvalidRange);
        }
        if self.issued.0.saturating_sub(clock_skew_ms) > now.0 {
            return Err(TimeError::NotYetValid);
        }
        if now.0 >= self.expires.0 && now.0 - self.expires.0 >= clock_skew_ms {
            return Err(TimeError::Expired);
        }
        Ok(())
    }
}

/// Inspection policy configured on Options; inspect is the only parser.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ParseMode {
    /// Reject every structural/profile defect (default).
    #[default]
    Strict,
    /// Recover bounded partial fields only within the selected version.
    /// This never turns a version mismatch into a successful report.
    Diagnostic,
}
