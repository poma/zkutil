use byteorder::{ReadBytesExt, LittleEndian};
use std::io::{Read, Result, ErrorKind, Error};
use bellman_ce::pairing::{
    Engine,
    ff::{
        Field, PrimeField, PrimeFieldRepr,
    }
};

pub struct Header {
    pub field_size: u32,
    pub prime_size: Vec<u8>,
    pub witness_len: u32,
}

pub struct WTNSFile<E: Engine> {
    pub version: u32,
    pub header: Header,
    pub witness: Vec<E::Fr>,
}

fn read_field<R: Read, E: Engine>(mut reader: R) -> Result<E::Fr> {
    let mut repr = E::Fr::zero().into_repr();
    repr.read_le(&mut reader)?;
    let fr = E::Fr::from_repr(repr)
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    Ok(fr)
}

fn read_header<R: Read>(mut reader: R, size: u64) -> Result<Header> {
    let field_size = reader.read_u32::<LittleEndian>()?;
    let mut prime_size = vec![0u8; field_size as usize];
    reader.read_exact(&mut prime_size)?;
    //if size != 32 + field_size as u64 {
    if size != 4 + 32 + 4 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid header section size"))
    }

    Ok(Header {
        field_size,
        prime_size,
        witness_len: reader.read_u32::<LittleEndian>()?,
    })
}

fn read_witness<R: Read, E:Engine>(mut reader: R, size: u64, header: &Header) -> Result<Vec<E::Fr>> {
    if size != (header.witness_len * header.field_size) as u64 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid witness section size"));
    }
    let mut result = Vec::with_capacity(header.witness_len as usize);
    for _ in 0..header.witness_len {
        result.push(read_field::<&mut R, E>(&mut reader)?);
    }
    Ok(result)
}

pub fn read<E: Engine, R: Read>(mut reader: R) -> Result<WTNSFile<E>> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != [119, 116, 110, 115] { // magic = "wtns"
        return Err(Error::new(ErrorKind::InvalidData, "Invalid magic number"))
    }

    let version = reader.read_u32::<LittleEndian>()?;
    if version > 2 {
        return Err(Error::new(ErrorKind::InvalidData, "Unsupported version"))
    }

    let _num_sections = reader.read_u32::<LittleEndian>()?;

    // todo: rewrite this to support different section order and unknown sections
    // todo: handle sec_size correctly
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 1 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid section type"));
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    let header = read_header(&mut reader, sec_size)?;
    if header.field_size != 32 {
        return Err(Error::new(ErrorKind::InvalidData, "This parser only supports 32-byte fields"))
    }
    if header.prime_size != hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430") {
        return Err(Error::new(ErrorKind::InvalidData, "This parser only supports bn256"))
    }

    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 2 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid section type"));
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    let witness = read_witness::<&mut R, E>(&mut reader, sec_size, &header)?;

    Ok(WTNSFile { version, header, witness })
}
