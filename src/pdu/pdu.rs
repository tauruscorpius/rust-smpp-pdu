use std::convert::TryFrom;
use std::io;
use std::io::Read;
use tokio::io::AsyncWriteExt;

use crate::pdu::formats::{Integer4, WriteStream};
use crate::pdu::validate_command_length::validate_command_length;
use crate::pdu::{
    check, BindReceiverPdu, BindReceiverRespPdu, BindTransceiverPdu,
    BindTransceiverRespPdu, BindTransmitterPdu, BindTransmitterRespPdu,
    CheckError, CheckOutcome, DeliverSmPdu, EnquireLinkPdu, EnquireLinkRespPdu,
    GenericNackPdu, PduParseError, PduParseErrorBody, SubmitSmPdu,
    SubmitSmRespPdu,
};

// It will be worth considering later whether the reading/writing code
// for the PDUs defined in the pdu::operations module could be generated using
// a derive macro rather than hand-coded as they are now.

#[derive(Debug, PartialEq)]
pub enum PduBody {
    BindReceiver(BindReceiverPdu),
    BindReceiverResp(BindReceiverRespPdu),
    BindTransceiver(BindTransceiverPdu),
    BindTransceiverResp(BindTransceiverRespPdu),
    BindTransmitter(BindTransmitterPdu),
    BindTransmitterResp(BindTransmitterRespPdu),
    DeliverSm(DeliverSmPdu),
    EnquireLink(EnquireLinkPdu),
    EnquireLinkResp(EnquireLinkRespPdu),
    GenericNack(GenericNackPdu),
    SubmitSm(SubmitSmPdu),
    SubmitSmResp(SubmitSmRespPdu),
}

impl PduBody {
    fn validate_command_status(
        self,
        command_status: u32,
    ) -> Result<Self, PduParseError> {
        self.do_validate_command_status(command_status)
            .map_err(|e| e.into_with_field_name("command_status"))
    }

    fn do_validate_command_status(
        self,
        command_status: u32,
    ) -> Result<Self, PduParseError> {
        Ok(match self {
            PduBody::BindReceiver(b) => {
                b.validate_command_status(command_status)?.into()
            }
            PduBody::BindReceiverResp(b) => {
                b.validate_command_status(command_status)?.into()
            }
            PduBody::BindTransceiver(b) => {
                b.validate_command_status(command_status)?.into()
            }
            PduBody::BindTransceiverResp(b) => {
                b.validate_command_status(command_status)?.into()
            }
            PduBody::BindTransmitter(b) => {
                b.validate_command_status(command_status)?.into()
            }
            PduBody::BindTransmitterResp(b) => {
                b.validate_command_status(command_status)?.into()
            }
            PduBody::DeliverSm(b) => {
                b.validate_command_status(command_status)?.into()
            }
            PduBody::EnquireLink(b) => {
                b.validate_command_status(command_status)?.into()
            }
            PduBody::EnquireLinkResp(b) => {
                b.validate_command_status(command_status)?.into()
            }
            PduBody::GenericNack(b) => {
                b.validate_command_status(command_status)?.into()
            }
            PduBody::SubmitSm(b) => {
                b.validate_command_status(command_status)?.into()
            }
            PduBody::SubmitSmResp(b) => {
                b.validate_command_status(command_status)?.into()
            }
        })
    }
}

impl From<BindReceiverPdu> for PduBody {
    fn from(body: BindReceiverPdu) -> PduBody {
        PduBody::BindReceiver(body)
    }
}

impl From<BindReceiverRespPdu> for PduBody {
    fn from(body: BindReceiverRespPdu) -> PduBody {
        PduBody::BindReceiverResp(body)
    }
}

impl From<BindTransceiverPdu> for PduBody {
    fn from(body: BindTransceiverPdu) -> PduBody {
        PduBody::BindTransceiver(body)
    }
}

impl From<BindTransceiverRespPdu> for PduBody {
    fn from(body: BindTransceiverRespPdu) -> PduBody {
        PduBody::BindTransceiverResp(body)
    }
}

impl From<BindTransmitterPdu> for PduBody {
    fn from(body: BindTransmitterPdu) -> PduBody {
        PduBody::BindTransmitter(body)
    }
}

impl From<BindTransmitterRespPdu> for PduBody {
    fn from(body: BindTransmitterRespPdu) -> PduBody {
        PduBody::BindTransmitterResp(body)
    }
}

impl From<DeliverSmPdu> for PduBody {
    fn from(body: DeliverSmPdu) -> PduBody {
        PduBody::DeliverSm(body)
    }
}

impl From<EnquireLinkPdu> for PduBody {
    fn from(body: EnquireLinkPdu) -> PduBody {
        PduBody::EnquireLink(body)
    }
}

impl From<EnquireLinkRespPdu> for PduBody {
    fn from(body: EnquireLinkRespPdu) -> PduBody {
        PduBody::EnquireLinkResp(body)
    }
}

impl From<GenericNackPdu> for PduBody {
    fn from(body: GenericNackPdu) -> PduBody {
        PduBody::GenericNack(body)
    }
}

impl From<SubmitSmPdu> for PduBody {
    fn from(body: SubmitSmPdu) -> PduBody {
        PduBody::SubmitSm(body)
    }
}

impl From<SubmitSmRespPdu> for PduBody {
    fn from(body: SubmitSmRespPdu) -> PduBody {
        PduBody::SubmitSmResp(body)
    }
}

#[derive(Debug, PartialEq)]
pub struct Pdu {
    pub command_status: Integer4,
    pub sequence_number: Integer4,
    body: PduBody,
}

impl Pdu {
    pub fn new(
        command_status: u32,
        sequence_number: u32,
        body: PduBody,
    ) -> Result<Self, PduParseError> {
        validate_sequence_number(sequence_number)?;
        Ok(Self {
            command_status: Integer4::new(command_status),
            sequence_number: Integer4::new(sequence_number),
            body: body.validate_command_status(command_status)?,
        })
    }

    pub fn parse(bytes: &mut dyn io::BufRead) -> Result<Pdu, PduParseError> {
        let command_length = Integer4::read(bytes)?;
        let mut bytes =
            bytes.take(u64::try_from(command_length.value - 4).unwrap_or(0));

        let command_id = hfld("command_id", &mut bytes, &command_length)?;
        let command_status =
            hfld("command_status", &mut bytes, &command_length).map_err(
                |e| e.into_with_header(Some(command_id.value), None, None),
            )?;
        let sequence_number =
            hfld("sequence_number", &mut bytes, &command_length).map_err(
                |e| {
                    e.into_with_header(
                        Some(command_id.value),
                        Some(command_status.value),
                        None,
                    )
                },
            )?;

        validate_command_length(&command_length).map_err(|e| {
            PduParseError::from(e).into_with_header(
                Some(command_id.value),
                Some(command_status.value),
                Some(sequence_number.value),
            )
        })?;

        validate_sequence_number(sequence_number.value).map_err(|e| {
            PduParseError::from(e).into_with_header(
                Some(command_id.value),
                Some(command_status.value),
                Some(sequence_number.value),
            )
        })?;

        let status = command_status.value;

        let body =
            parse_body(&mut bytes, command_id.value, command_status.value)
                .and_then(|ret| {
                    // There should be no bytes left over
                    let mut buf = [0; 1];
                    if bytes.read(&mut buf)? == 0 {
                        Ok(ret.validate_command_status(status)?)
                    } else {
                        Err(PduParseError::new(
                            PduParseErrorBody::LengthLongerThanPdu(
                                command_length.value,
                            ),
                        ))
                    }
                })
                .map_err(|e| {
                    e.into_with_header(
                        Some(command_id.value),
                        Some(command_status.value),
                        Some(sequence_number.value),
                    )
                })?;

        Ok(Pdu {
            command_status,
            sequence_number,
            body,
        })
    }

    pub fn check(
        bytes: &mut dyn io::BufRead,
    ) -> Result<CheckOutcome, CheckError> {
        check::check(bytes)
    }

    pub async fn write(&self, stream: &mut WriteStream) -> io::Result<()> {
        let mut buf = Vec::new();
        self.command_id().write(&mut buf).await?;
        self.command_status.write(&mut buf).await?;
        self.sequence_number.write(&mut buf).await?;
        match &self.body {
            PduBody::BindReceiver(body) => body.write(&mut buf).await?,
            PduBody::BindReceiverResp(body) => body.write(&mut buf).await?,
            PduBody::BindTransceiver(body) => body.write(&mut buf).await?,
            PduBody::BindTransceiverResp(body) => body.write(&mut buf).await?,
            PduBody::BindTransmitter(body) => body.write(&mut buf).await?,
            PduBody::BindTransmitterResp(body) => body.write(&mut buf).await?,
            PduBody::DeliverSm(body) => body.write(&mut buf).await?,
            PduBody::EnquireLink(body) => body.write(&mut buf).await?,
            PduBody::EnquireLinkResp(body) => body.write(&mut buf).await?,
            PduBody::GenericNack(body) => body.write(&mut buf).await?,
            PduBody::SubmitSm(body) => body.write(&mut buf).await?,
            PduBody::SubmitSmResp(body) => body.write(&mut buf).await?,
        }
        let command_length = Integer4::new((buf.len() + 4) as u32);
        command_length.write(stream).await?;
        stream.write(&buf).await?;
        Ok(())
    }

    pub fn command_id(&self) -> Integer4 {
        Integer4::new(match self.body {
            PduBody::BindReceiver(_) => 0x00000001,
            PduBody::BindReceiverResp(_) => 0x80000001,
            PduBody::BindTransmitter(_) => 0x00000002,
            PduBody::BindTransmitterResp(_) => 0x80000002,
            PduBody::SubmitSm(_) => 0x00000004,
            PduBody::SubmitSmResp(_) => 0x80000004,
            PduBody::DeliverSm(_) => 0x00000005,
            PduBody::BindTransceiver(_) => 0x00000009,
            PduBody::BindTransceiverResp(_) => 0x80000009,
            PduBody::EnquireLink(_) => 0x00000015,
            PduBody::EnquireLinkResp(_) => 0x80000015,
            PduBody::GenericNack(_) => 0x80000000,
        })
    }

    pub fn body(&self) -> &PduBody {
        &self.body
    }
}

pub fn parse_body(
    bytes: &mut dyn io::BufRead,
    command_id: u32,
    command_status: u32,
) -> Result<PduBody, PduParseError> {
    match command_id {
        0x00000001 => {
            BindReceiverPdu::parse(bytes, command_status).map(|p| p.into())
        }
        0x80000001 => {
            BindReceiverRespPdu::parse(bytes, command_status).map(|p| p.into())
        }
        0x00000002 => {
            BindTransmitterPdu::parse(bytes, command_status).map(|p| p.into())
        }
        0x80000002 => BindTransmitterRespPdu::parse(bytes, command_status)
            .map(|p| p.into()),
        0x00000004 => {
            SubmitSmPdu::parse(bytes, command_status).map(|p| p.into())
        }
        0x80000004 => {
            SubmitSmRespPdu::parse(bytes, command_status).map(|p| p.into())
        }
        0x00000005 => {
            DeliverSmPdu::parse(bytes, command_status).map(|p| p.into())
        }
        0x00000009 => {
            BindTransceiverPdu::parse(bytes, command_status).map(|p| p.into())
        }
        0x80000009 => BindTransceiverRespPdu::parse(bytes, command_status)
            .map(|p| p.into()),
        0x00000015 => {
            EnquireLinkPdu::parse(bytes, command_status).map(|p| p.into())
        }
        0x80000015 => {
            EnquireLinkRespPdu::parse(bytes, command_status).map(|p| p.into())
        }
        _ => Err(PduParseError::new(PduParseErrorBody::UnknownCommandId)),
    }
}

fn hfld(
    field_name: &str,
    mut bytes: &mut dyn io::BufRead,
    command_length: &Integer4,
) -> Result<Integer4, PduParseError> {
    Integer4::read(&mut bytes).map_err(|e| {
        if let Err(len_e) = validate_command_length(command_length) {
            PduParseError::from(len_e)
        } else {
            PduParseError::from(e).into_with_field_name(field_name)
        }
    })
}

fn validate_sequence_number(sequence_number: u32) -> Result<(), PduParseError> {
    if sequence_number < 0x00000001 || sequence_number > 0x7fffffff {
        Err(PduParseError::new(PduParseErrorBody::InvalidSequenceNumber))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::pdu::esm_class::{SubmitMessageMode, SubmitMessageType};
    use crate::pdu::tlvs::{KnownTlvTag, Tlv, Tlvs};
    use crate::pdu::SubmitEsmClass;

    const BIND_TRANSMITTER_RESP_PDU_PLUS_EXTRA: &[u8; 0x1b + 0xa] =
        b"\x00\x00\x00\x1b\x80\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x02\
        TestServer\0extrabytes";

    #[test]
    fn check_is_ok_if_more_bytes() {
        // Most tests for check are in the check module.  Here we do enough
        // to confirm that we are calling through it that from Pdu::check.
        let mut cursor = Cursor::new(&BIND_TRANSMITTER_RESP_PDU_PLUS_EXTRA[..]);
        assert_eq!(Pdu::check(&mut cursor).unwrap(), CheckOutcome::Ready);
    }

    #[test]
    fn check_is_incomplete_if_fewer_bytes() {
        let mut cursor =
            Cursor::new(&BIND_TRANSMITTER_RESP_PDU_PLUS_EXTRA[..0x1a]);
        assert_eq!(Pdu::check(&mut cursor).unwrap(), CheckOutcome::Incomplete);
    }

    #[test]
    fn parse_valid_bind_transmitter() {
        const BIND_TRANSMITTER_PDU_PLUS_EXTRA: &[u8; 0x2e + 0x6] =
            b"\x00\x00\x00\x2e\x00\x00\x00\x02\x00\x00\x00\x00\x01\x02\x03\x44\
            mysystem_ID\0pw$xx\0t_p_\0\x34\x13\x50rng\0foobar";

        let mut cursor = Cursor::new(&BIND_TRANSMITTER_PDU_PLUS_EXTRA[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000000,
                0x01020344,
                BindTransmitterPdu::new(
                    "mysystem_ID",
                    "pw$xx",
                    "t_p_",
                    0x34,
                    0x13,
                    0x50,
                    "rng"
                )
                .unwrap()
                .into()
            )
            .unwrap()
        );
    }

    #[test]
    fn parse_valid_bind_receiver() {
        const PDU: &[u8; 0x2e + 0x6] =
            b"\x00\x00\x00\x2e\x00\x00\x00\x01\x00\x00\x00\x00\x01\x02\x03\x45\
            mysystem_ID\0pw$xx\0t_p_\0\x34\x13\x50rng\0foobar";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000000,
                0x01020345,
                BindReceiverPdu::new(
                    "mysystem_ID",
                    "pw$xx",
                    "t_p_",
                    0x34,
                    0x13,
                    0x50,
                    "rng"
                )
                .unwrap()
                .into()
            )
            .unwrap()
        );
    }

    #[test]
    fn parse_valid_bind_transceiver() {
        const PDU: &[u8; 0x2e + 0x6] =
            b"\x00\x00\x00\x2e\x00\x00\x00\x09\x00\x00\x00\x00\x01\x02\x03\x45\
            mysystem_ID\0pw$xx\0t_p_\0\x34\x13\x50rng\0foobar";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000000,
                0x01020345,
                BindTransceiverPdu::new(
                    "mysystem_ID",
                    "pw$xx",
                    "t_p_",
                    0x34,
                    0x13,
                    0x50,
                    "rng"
                )
                .unwrap()
                .into()
            )
            .unwrap()
        );
    }

    #[test]
    fn parse_bind_transmitter_with_too_long_system_id() {
        const PDU: &[u8; 0x29] =
            b"\x00\x00\x00\x29\x00\x00\x00\x02\x00\x00\x00\x00\x01\x02\x03\x44\
            ABDEFABCDEFABCDEFA\0\0\0\x34\x13\x50\0";
        let mut cursor = Cursor::new(&PDU[..]);

        let res = Pdu::parse(&mut cursor).unwrap_err();
        assert_eq!(
            res.to_string(),
            "Error parsing PDU \
            (command_id=0x00000002, command_status=0x00000000, \
            sequence_number=0x01020344, field_name=system_id): \
            Octet String is too long.  Max length is 16, including final \
            zero byte.",
        );
    }

    #[test]
    fn parse_bind_transmitter_with_length_ending_within_string() {
        const PDU: &[u8; 0x29] =
            b"\x00\x00\x00\x12\x00\x00\x00\x02\x00\x00\x00\x00\x01\x02\x03\x44\
            ABDEFABCDEFABCDEFA\0\0\0\x34\x13\x50\0";
        let mut cursor = Cursor::new(&PDU[..]);

        let res = Pdu::parse(&mut cursor).unwrap_err();
        assert_eq!(
            res.to_string(),
            "Error parsing PDU \
            (command_id=0x00000002, command_status=0x00000000, \
            sequence_number=0x01020344, field_name=system_id): \
            C-Octet String does not end with the NULL character.",
        );
    }

    #[test]
    fn parse_bind_transmitter_ending_before_all_fields() {
        const PDU: &[u8; 0x13] =
            b"\x00\x00\x00\x13\x00\x00\x00\x02\x00\x00\x00\x00\x01\x02\x03\x44\
            \0\0\0";
        let mut cursor = Cursor::new(&PDU[..]);

        let res = Pdu::parse(&mut cursor).unwrap_err();
        assert_eq!(
            res.to_string(),
            "Error parsing PDU (\
            command_id=0x00000002, command_status=0x00000000, \
            sequence_number=0x01020344, field_name=interface_version): \
            Reached end of PDU length (or end of input) before finding all \
            fields of the PDU.",
        );
    }

    #[test]
    fn parse_bind_transmitter_hitting_eof_before_end_of_length() {
        const PDU: &[u8; 0x0b] =
            b"\x00\x00\x00\x2e\x00\x00\x00\x02\x00\x00\x00";
        let mut cursor = Cursor::new(&PDU[..]);

        let res = Pdu::parse(&mut cursor).unwrap_err();
        assert_eq!(
            res.to_string(),
            "Error parsing PDU (\
            command_id=0x00000002, command_status=UNKNOWN, \
            sequence_number=UNKNOWN, field_name=command_status): \
            Reached end of PDU length (or end of input) before finding all \
            fields of the PDU.",
        );
    }

    #[test]
    fn parse_bind_transmitter_with_short_length() {
        const PDU: &[u8; 4] = b"\x00\x00\x00\x04";
        let mut cursor = Cursor::new(&PDU);

        let res = Pdu::parse(&mut cursor).unwrap_err();
        assert_eq!(
            res.to_string(),
            "Error parsing PDU (\
            command_id=UNKNOWN, command_status=UNKNOWN, \
            sequence_number=UNKNOWN, field_name=UNKNOWN): \
            Length (4) too short.  Min allowed is 8 octets.",
        );
    }

    #[test]
    fn parse_bind_transmitter_with_massive_length() {
        const PDU: &[u8; 16] =
            b"\xff\xff\xff\xff\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00";
        let mut cursor = Cursor::new(&PDU);

        let res = Pdu::parse(&mut cursor).unwrap_err();
        assert_eq!(
            res.to_string(),
            "Error parsing PDU (\
            command_id=0x00000002, command_status=0x00000000, \
            sequence_number=0x00000000, field_name=UNKNOWN): \
            Length (4294967295) too long.  Max allowed is 70000 octets.",
        );
    }

    #[test]
    fn parse_bind_transmitter_containing_nonascii_characters() {
        const PDU: &[u8; 0x2e + 0x6] =
            b"\x00\x00\x00\x2e\x00\x00\x00\x02\x00\x00\x00\x00\x01\x02\x03\x44\
            mys\xf0\x9f\x92\xa9m_ID\0pw$xx\0t_p_\0\x34\x13\x50rng\0foobar";
        let mut cursor = Cursor::new(&PDU);

        let res = Pdu::parse(&mut cursor).unwrap_err();
        assert_eq!(
            res.to_string(),
            "Error parsing PDU (\
            command_id=0x00000002, command_status=0x00000000, \
            sequence_number=0x01020344, field_name=system_id): \
            Octet String is not ASCII (valid up to byte 3).",
        );
    }

    #[test]
    fn parse_bind_transmitter_with_nonzero_status() {
        const PDU: &[u8; 0x2e + 0x6] =
            b"\x00\x00\x00\x2e\x00\x00\x00\x02\x00\x00\x00\x77\x01\x02\x03\x44\
            mysystem_ID\0pw$xx\0t_p_\0\x34\x13\x50rng\0foobar";
        let mut cursor = Cursor::new(&PDU);

        let res = Pdu::parse(&mut cursor).unwrap_err();
        assert_eq!(
            res.to_string(),
            "Error parsing PDU (\
            command_id=0x00000002, command_status=0x00000077, \
            sequence_number=0x01020344, field_name=command_status): \
            command_status must be 0, but was 0x00000077.",
        );
    }

    #[test]
    fn parse_valid_bind_transmitter_resp() {
        let mut cursor = Cursor::new(&BIND_TRANSMITTER_RESP_PDU_PLUS_EXTRA[..]);
        b"\x00\x00\x00\x1b\x80\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x02\
        TestServer\0extrabytes";
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000000,
                0x00000002,
                PduBody::BindTransmitterResp(
                    BindTransmitterRespPdu::new("TestServer",).unwrap(),
                )
            )
            .unwrap()
        );
    }

    #[test]
    fn parse_valid_bind_transceiver_resp() {
        const PDU: &[u8; 0x1b + 0xa] =
            b"\x00\x00\x00\x1b\x80\x00\x00\x09\x00\x00\x00\x00\x00\x00\x02\x02\
            TestServer\0extrabytes";

        let mut cursor = Cursor::new(&PDU[..]);
        b"\x00\x00\x00\x1b\x80\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x02\
        TestServer\0extrabytes";
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000000,
                0x00000202,
                PduBody::BindTransceiverResp(
                    BindTransceiverRespPdu::new("TestServer",).unwrap(),
                )
            )
            .unwrap()
        );
    }

    #[test]
    fn parse_valid_bind_receiver_resp() {
        const PDU: &[u8; 0x1b + 0xa] =
            b"\x00\x00\x00\x1b\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00\x30\x02\
            TestServer\0extrabytes";

        let mut cursor = Cursor::new(&PDU[..]);
        b"\x00\x00\x00\x1b\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00\x30\x02\
        TestServer\0extrabytes";
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000000,
                0x00003002,
                PduBody::BindReceiverResp(
                    BindReceiverRespPdu::new("TestServer",).unwrap(),
                )
            )
            .unwrap()
        );
    }

    #[test]
    fn parse_valid_submit_sm_with_short_message_and_no_tlvs() {
        const PDU: &[u8; 0x3d] = b"\
            \x00\x00\x00\x3d\
            \x00\x00\x00\x04\
            \x00\x00\x00\x00\
            \x00\x00\x00\x03\
            \x00\
            \x00\x00447000123123\x00\
            \x00\x00447111222222\x00\
            \x00\x01\x01\x00\x00\x01\x00\x03\
            \x00\x04hihi";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000000,
                0x00000003,
                SubmitSmPdu::new(
                    "",
                    0x00,
                    0x00,
                    "447000123123",
                    0x00,
                    0x00,
                    "447111222222",
                    SubmitEsmClass::Default as u8,
                    0x01,
                    0x01,
                    "",
                    "",
                    0x01,
                    0x00,
                    0x03,
                    0x00,
                    b"hihi",
                    Tlvs::new(),
                )
                .unwrap()
                .into()
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn write_submit_sm_with_short_message_and_no_tlvs() {
        let pdu = Pdu::new(
            0x00000000,
            0x00000003,
            SubmitSmPdu::new(
                "",
                0x01,
                0x02,
                "447000123123",
                0x03,
                0x04,
                "447111222222",
                SubmitMessageMode::DatagramMode as u8
                    | SubmitMessageType::EsmeDeliveryAcknowledgement as u8,
                0x01,
                0x01,
                "",
                "",
                0x01,
                0x06,
                0x03,
                0x07,
                b"hihi\xfe",
                Tlvs::new(),
            )
            .unwrap()
            .into(),
        )
        .unwrap();

        let mut output = Vec::new();
        pdu.write(&mut output).await.unwrap();

        assert_eq!(output.len(), 0x3e);
        assert_eq!(
            output,
            b"\
                \x00\x00\x00\x3e\
                \x00\x00\x00\x04\
                \x00\x00\x00\x00\
                \x00\x00\x00\x03\
                \x00\
                \x01\x02447000123123\x00\
                \x03\x04447111222222\x00\
                \x09\x01\x01\x00\x00\x01\x06\x03\
                \x07\x05hihi\xfe"
        );
    }

    #[test]
    fn parse_valid_submit_sm_with_empty_short_message_and_no_tlvs() {
        const PDU: &[u8; 0x3e] = b"\
            \x00\x00\x00\x39\
            \x00\x00\x00\x04\
            \x00\x00\x00\x00\
            \x00\x00\x00\x03\
            \x00\
            \x00\x00447000123123\x00\
            \x00\x00447111222222\x00\
            \x00\x01\x01\x00\x00\x01\x00\x03\
            \x00\x00extra";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000000,
                0x00000003,
                SubmitSmPdu::new(
                    "",
                    0x00,
                    0x00,
                    "447000123123",
                    0x00,
                    0x00,
                    "447111222222",
                    SubmitEsmClass::Default as u8,
                    0x01,
                    0x01,
                    "",
                    "",
                    0x01,
                    0x00,
                    0x03,
                    0x00,
                    &[],
                    Tlvs::new(),
                )
                .unwrap()
                .into()
            )
            .unwrap()
        );
    }

    #[test]
    fn parse_valid_submit_sm_with_tlvs() {
        const PDU: &[u8; 0x3e] = b"\
            \x00\x00\x00\x3e\
            \x00\x00\x00\x04\
            \x00\x00\x00\x00\
            \x00\x00\x00\x03\
            \x00\
            \x00\x00447000123123\x00\
            \x00\x00447111222222\x00\
            \x00\x01\x01\x00\x00\x01\x00\x03\
            \x00\x00\
            \x00\x0e\
            \x00\x01\
            \x01\
            ";
        // 000e means tag=source_network_type
        // 0001 means length=1
        // 01   means value=GSM

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000000,
                0x00000003,
                SubmitSmPdu::new(
                    "",
                    0x00,
                    0x00,
                    "447000123123",
                    0x00,
                    0x00,
                    "447111222222",
                    SubmitEsmClass::Default as u8,
                    0x01,
                    0x01,
                    "",
                    "",
                    0x01,
                    0x00,
                    0x03,
                    0x00,
                    &[],
                    Tlvs::from(&[Tlv::new(
                        KnownTlvTag::source_network_type,
                        &[0x01]
                    )])
                )
                .unwrap()
                .into()
            )
            .unwrap()
        );
    }

    #[test]
    fn parse_submit_sm_with_too_long_message_length() {
        const PDU: &[u8; 0x3d] = b"\
            \x00\x00\x00\x3d\
            \x00\x00\x00\x04\
            \x00\x00\x00\x00\
            \x00\x00\x00\x03\
            \x00\
            \x00\x00447000123123\x00\
            \x00\x00447111222222\x00\
            \x00\x01\x01\x00\x00\x01\x00\x03\
            \x00\x08hihi";

        let mut cursor = Cursor::new(&PDU[..]);
        let err = Pdu::parse(&mut cursor).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Error parsing PDU \
            (command_id=0x00000004, command_status=0x00000000, \
            sequence_number=0x00000003, field_name=short_message): \
            IO error creating Octet String: failed to fill whole buffer"
        );
    }

    #[test]
    fn parse_submit_sm_resp_ok_with_message_id() {
        const PDU: &[u8; 0x3a] = b"\
            \x00\x00\x00\x35\
            \x80\x00\x00\x04\
            \x00\x00\x00\x00\
            \x00\x00\x00\x04\
            ea04b3d4-6a18-11eb-a387-c8f7507e3592\x00\
            extra";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000000,
                0x00000004,
                SubmitSmRespPdu::new("ea04b3d4-6a18-11eb-a387-c8f7507e3592",)
                    .unwrap()
                    .into()
            )
            .unwrap()
        );
    }

    #[test]
    fn parse_submit_sm_resp_ok_without_message_id_is_an_error() {
        const PDU: &[u8; 0x10] = b"\
            \x00\x00\x00\x10\
            \x80\x00\x00\x04\
            \x00\x00\x00\x00\
            \x00\x00\x00\x04";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap_err().to_string(),
            "Error parsing PDU (\
            command_id=0x80000004, command_status=0x00000000, \
            sequence_number=0x00000004, field_name=message_id): \
            C-Octet String does not end with the NULL character."
        );
        // Slightly unhelpful error message.  Better would be: submit_sm_resp
        // had command_status of zero but did not include a message_id.
    }

    #[test]
    fn parse_submit_sm_resp_error_without_message_id() {
        const PDU: &[u8; 0x10] = b"\
            \x00\x00\x00\x10\
            \x80\x00\x00\x04\
            \x00\x00\x00\x07\
            \x00\x00\x00\x04";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000007,
                0x00000004,
                SubmitSmRespPdu::new_error().into()
            )
            .unwrap()
        );
    }

    #[test]
    fn parse_submit_sm_resp_error_with_message_id_is_an_error() {
        const PDU: &[u8; 0x12] = b"\
            \x00\x00\x00\x12\
            \x80\x00\x00\x04\
            \x00\x00\x00\x07\
            \x00\x00\x00\x04\
            a\x00";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap_err().to_string(),
            "Error parsing PDU (\
            command_id=0x80000004, command_status=0x00000007, \
            sequence_number=0x00000004, field_name=UNKNOWN): \
            PDU body must not be supplied when status is not zero, but \
            command_status is 0x00000007.",
        );
    }

    #[test]
    fn parsepdu_resp_error_with_zero_sequence_number_is_an_error() {
        const PDU: &[u8; 0x10] = b"\
            \x00\x00\x00\x10\
            \x80\x00\x00\x00\
            \x00\x00\x00\x00\
            \x00\x00\x00\x00";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap_err().to_string(),
            "Error parsing PDU (\
            command_id=0x80000000, command_status=0x00000000, \
            sequence_number=0x00000000, field_name=UNKNOWN): \
            Sequence number 0x00000000 is not allowed: \
            must be 0x00000001 to 0x7FFFFFFF.",
        );
    }

    #[test]
    fn parsepdu_resp_error_with_too_large_sequence_number_is_an_error() {
        const PDU: &[u8; 0x10] = b"\
            \x00\x00\x00\x10\
            \x80\x00\x00\x00\
            \x00\x00\x00\x00\
            \xf0\x00\x00\x00";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap_err().to_string(),
            "Error parsing PDU (\
            command_id=0x80000000, command_status=0x00000000, \
            sequence_number=0xF0000000, field_name=UNKNOWN): \
            Sequence number 0xF0000000 is not allowed: \
            must be 0x00000001 to 0x7FFFFFFF.",
        );
    }

    #[test]
    fn parse_enquire_link() {
        const PDU: &[u8; 0x10] = b"\
            \x00\x00\x00\x10\
            \x00\x00\x00\x15\
            \x00\x00\x00\x00\
            \x00\x00\x00\x0A";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(0x00000000, 0x0000000A, EnquireLinkPdu::new().into())
                .unwrap()
        );
    }

    #[test]
    fn parse_enquire_link_resp() {
        const PDU: &[u8; 0x10] = b"\
            \x00\x00\x00\x10\
            \x80\x00\x00\x15\
            \x00\x00\x00\x00\
            \x00\x00\x00\x0A";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(0x00000000, 0x0000000A, EnquireLinkRespPdu::new().into())
                .unwrap()
        );
    }

    #[tokio::test]
    async fn write_deliver_sm_with_short_message_and_no_tlvs() {
        let pdu = Pdu::new(
            0x00000000,
            0x00000003,
            DeliverSmPdu::new(
                "",
                0x01,
                0x02,
                "447000123123",
                0x03,
                0x04,
                "447111222222",
                0x05,
                0x01,
                0x01,
                "",
                "",
                0x01,
                0x06,
                0x03,
                0x07,
                b"hihi\xfe",
                Tlvs::new(),
            )
            .unwrap()
            .into(),
        )
        .unwrap();

        let mut output = Vec::new();
        pdu.write(&mut output).await.unwrap();

        assert_eq!(output.len(), 0x3e);
        assert_eq!(
            output,
            b"\
                \x00\x00\x00\x3e\
                \x00\x00\x00\x05\
                \x00\x00\x00\x00\
                \x00\x00\x00\x03\
                \x00\
                \x01\x02447000123123\x00\
                \x03\x04447111222222\x00\
                \x05\x01\x01\x00\x00\x01\x06\x03\
                \x07\x05hihi\xfe"
        );
    }

    #[tokio::test]
    async fn write_submit_sm_with_message_in_tlvs() {
        let pdu = Pdu::new(
            0x00000000,
            0x00000003,
            SubmitSmPdu::new(
                "",
                0x01,
                0x02,
                "447000123123",
                0x03,
                0x04,
                "447111222222",
                0x05,
                0x01,
                0x01,
                "",
                "",
                0x01,
                0x06,
                0x03,
                0x07,
                b"",
                Tlvs::from(&[
                    Tlv::new(KnownTlvTag::message_payload, "hello".as_bytes()),
                    Tlv::new(KnownTlvTag::dest_bearer_type, &[0x0001]),
                ]),
            )
            .unwrap()
            .into(),
        )
        .unwrap();

        let mut output = Vec::new();
        pdu.write(&mut output).await.unwrap();

        assert_eq!(output.len(), 0x47);
        assert_eq!(
            output,
            b"\
                \x00\x00\x00\x47\
                \x00\x00\x00\x04\
                \x00\x00\x00\x00\
                \x00\x00\x00\x03\
                \x00\
                \x01\x02447000123123\x00\
                \x03\x04447111222222\x00\
                \x05\x01\x01\x00\x00\x01\x06\x03\
                \x07\x00\
                \x04\x24\
                \x00\x05\
                hello\
                \x00\x07\
                \x00\x01\
                \x01\
                "
        );
    }

    #[test]
    fn parse_valid_deliver_sm_with_empty_short_message_and_no_tlvs() {
        const PDU: &[u8; 0x3e] = b"\
            \x00\x00\x00\x39\
            \x00\x00\x00\x05\
            \x00\x00\x00\x00\
            \x00\x00\x00\x03\
            \x00\
            \x00\x00447000123123\x00\
            \x00\x00447111222222\x00\
            \x00\x01\x01\x00\x00\x01\x00\x03\
            \x00\x00extra";

        let mut cursor = Cursor::new(&PDU[..]);
        assert_eq!(
            Pdu::parse(&mut cursor).unwrap(),
            Pdu::new(
                0x00000000,
                0x00000003,
                DeliverSmPdu::new(
                    "",
                    0x00,
                    0x00,
                    "447000123123",
                    0x00,
                    0x00,
                    "447111222222",
                    0x00,
                    0x01,
                    0x01,
                    "",
                    "",
                    0x01,
                    0x00,
                    0x03,
                    0x00,
                    &[],
                    Tlvs::new(),
                )
                .unwrap()
                .into()
            )
            .unwrap()
        );
    }

    // Issue#2: submit_sm with message_payload TLV and no short_message
    // Issue#2: submit_sm with message_payload TLV AND short_message is an error
}
