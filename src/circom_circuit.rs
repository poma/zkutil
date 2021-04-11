#![allow(clippy::needless_range_loop)]
extern crate bellman_ce;
extern crate rand;

use anyhow::{bail};
use byteorder::{LittleEndian, ReadBytesExt};
use std::str;
use std::fs::{self, OpenOptions, File};
use std::io::{Read, BufReader};
use std::collections::BTreeMap;
use std::iter::repeat;
use std::sync::Arc;
use itertools::Itertools;
use rand::{Rng, OsRng};

use bellman_ce::{
    Circuit,
    SynthesisError,
    Variable,
    Index,
    ConstraintSystem,
    LinearCombination,
    source::QueryDensity,
    groth16::{
        Parameters,
        Proof,
        generate_random_parameters as generate_random_parameters2,
        prepare_verifying_key,
        create_random_proof,
        verify_proof,
        prepare_prover,
    },
    pairing::{
        Engine,
        CurveAffine,
        ff::Field,
        ff::PrimeField,
        ff::PrimeFieldRepr,
        ff::ScalarEngine,
        bn256::{
            Bn256,
            Fq,
            Fq2,
            G1Affine,
            G2Affine,
        }
    },
};

use crate::utils::{
    repr_to_big,
    proof_to_hex,
    p1_to_vec,
    p2_to_vec,
    pairing_to_vec,
};

#[derive(Serialize, Deserialize)]
struct CircuitJson {
    pub constraints: Vec<Vec<BTreeMap<String, String>>>,
    #[serde(rename = "nPubInputs")]
    pub num_inputs: usize,
    #[serde(rename = "nOutputs")]
    pub num_outputs: usize,
    #[serde(rename = "nVars")]
    pub num_variables: usize,
}

#[derive(Serialize, Deserialize)]
struct ProofJson {
    pub protocol: String,
    pub proof: Option<String>,
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct ProvingKeyJson {
    #[serde(rename = "polsA")]
    pub pols_a: Vec<BTreeMap<String, String>>,
    #[serde(rename = "polsB")]
    pub pols_b: Vec<BTreeMap<String, String>>,
    #[serde(rename = "polsC")]
    pub pols_c: Vec<BTreeMap<String, String>>,
    #[serde(rename = "A")]
    pub a: Vec<Vec<String>>,
    #[serde(rename = "B1")]
    pub b1: Vec<Vec<String>>,
    #[serde(rename = "B2")]
    pub b2: Vec<Vec<Vec<String>>>,
    #[serde(rename = "C")]
    pub c: Vec<Option<Vec<String>>>,
    pub vk_alfa_1: Vec<String>,
    pub vk_beta_1: Vec<String>,
    pub vk_delta_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "hExps")]
    pub h: Vec<Vec<String>>,
    pub protocol: String,
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    #[serde(rename = "nVars")]
    pub n_vars: usize,
    #[serde(rename = "domainBits")]
    pub domain_bits: usize,
    #[serde(rename = "domainSize")]
    pub domain_size: usize,
}

#[derive(Serialize, Deserialize)]
struct VerifyingKeyJson {
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
    pub vk_alfa_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    pub vk_alfabeta_12: Vec<Vec<Vec<String>>>,
    pub protocol: String,
    #[serde(rename = "nPublic")]
    pub inputs_count: usize,
}

pub type Constraint<E> = (
    Vec<(usize, <E as ScalarEngine>::Fr)>,
    Vec<(usize, <E as ScalarEngine>::Fr)>,
    Vec<(usize, <E as ScalarEngine>::Fr)>,
);

#[derive(Clone)]
pub struct R1CS<E: Engine> {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_variables: usize,
    pub constraints: Vec<Constraint<E>>,
}

#[derive(Clone)]
pub struct CircomCircuit<E: Engine> {
    pub r1cs: R1CS<E>,
    pub witness: Option<Vec<E::Fr>>,
    pub wire_mapping: Option<Vec<usize>>,
    // debug symbols
}

impl<'a, E: Engine> CircomCircuit<E> {
    pub fn get_public_inputs(&self) -> Option<Vec<E::Fr>> {
        match &self.witness {
            None => None,
            Some(w) => match &self.wire_mapping {
                None => Some(w[1..self.r1cs.num_inputs].to_vec()),
                Some(m) => Some(m[1..self.r1cs.num_inputs].iter().map(|i| w[*i]).collect_vec()),
            }
        }
    }

    pub fn get_public_inputs_json(&self) -> String {
        let inputs = self.get_public_inputs();
        let inputs = match inputs {
            None => return String::from("[]"),
            Some(inp) => inp.iter().map(|x| repr_to_big(x.into_repr())).collect_vec(),
        };
        serde_json::to_string_pretty(&inputs).unwrap()
    }
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for CircomCircuit<E> {
    //noinspection RsBorrowChecker
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let witness = &self.witness;
        let wire_mapping = &self.wire_mapping;
        for i in 1..self.r1cs.num_inputs {
            cs.alloc_input(
                || format!("variable {}", i),
                || {
                    Ok(match witness {
                        None => E::Fr::from_str("1").unwrap(),
                        Some(w) => match wire_mapping {
                            None => w[i],
                            Some(m) => w[m[i]],
                        }
                    })
                },
            )?;
        }

        for i in 0..self.r1cs.num_aux {
            cs.alloc(
                || format!("aux {}", i),
                || {
                    Ok(match witness {
                        None => E::Fr::from_str("1").unwrap(),
                        Some(w) => match wire_mapping {
                            None => w[i + self.r1cs.num_inputs],
                            Some(m) => w[m[i + self.r1cs.num_inputs]],
                        },
                    })
                },
            )?;
        }

        let make_index = |index|
            if index < self.r1cs.num_inputs {
                Index::Input(index)
            } else {
                Index::Aux(index - self.r1cs.num_inputs)
            };
        let make_lc = |lc_data: Vec<(usize, E::Fr)>|
            lc_data.iter().fold(
                LinearCombination::<E>::zero(),
                |lc: LinearCombination<E>, (index, coeff)| lc + (*coeff, Variable::new_unchecked(make_index(*index)))
            );
        for (i, constraint) in self.r1cs.constraints.iter().enumerate() {
            cs.enforce(|| format!("constraint {}", i),
                       |_| make_lc(constraint.0.clone()),
                       |_| make_lc(constraint.1.clone()),
                       |_| make_lc(constraint.2.clone()),
            );
        }
        Ok(())
    }
}

pub fn prove<E: Engine, R: Rng>(circuit: CircomCircuit<E>, params: &Parameters<E>, mut rng: R) -> Result<Proof<E>, SynthesisError> {
    let mut params2 = params.clone();
    filter_params(&mut params2);
    create_random_proof(circuit, &params2, &mut rng)
}

pub fn generate_random_parameters<E: Engine, R: Rng>(circuit: CircomCircuit<E>, mut rng: R) -> Result<Parameters<E>, SynthesisError> {
    generate_random_parameters2(circuit, &mut rng)
}

pub fn verify_circuit<E: Engine>(circuit: &CircomCircuit<E>, params: &Parameters<E>, proof: &Proof<E>) -> Result<bool, SynthesisError> {
    let inputs = match circuit.get_public_inputs() {
        None => return Err(SynthesisError::AssignmentMissing),
        Some(inp) => inp,
    };
    verify_proof(&prepare_verifying_key(&params.vk), proof, &inputs)
}

pub fn verify<E: Engine>(params: &Parameters<E>, proof: &Proof<E>, inputs: &[E::Fr]) -> Result<bool, SynthesisError> {
    verify_proof(&prepare_verifying_key(&params.vk), proof, &inputs)
}

pub fn create_verifier_sol(params: &Parameters<Bn256>) -> String {
    // TODO: use a simple template engine
    let bytes = include_bytes!("verifier_groth.sol");
    let template = String::from_utf8_lossy(bytes);

    let p1_to_str = |p: &<Bn256 as Engine>::G1Affine| {
        if p.is_zero() {
            // todo: throw instead
            return String::from("<POINT_AT_INFINITY>");
        }
        let xy = p.into_xy_unchecked();
        let x = repr_to_big(xy.0.into_repr());
        let y = repr_to_big(xy.1.into_repr());
        format!("uint256({}), uint256({})", x, y)
    };
    let p2_to_str = |p: &<Bn256 as Engine>::G2Affine| {
        if p.is_zero() {
            // todo: throw instead
            return String::from("<POINT_AT_INFINITY>");
        }
        let xy = p.into_xy_unchecked();
        let x_c0 = repr_to_big(xy.0.c0.into_repr());
        let x_c1 = repr_to_big(xy.0.c1.into_repr());
        let y_c0 = repr_to_big(xy.1.c0.into_repr());
        let y_c1 = repr_to_big(xy.1.c1.into_repr());
        format!("[uint256({}), uint256({})], [uint256({}), uint256({})]", x_c1, x_c0, y_c1, y_c0)
    };

    let template = template.replace("<%vk_alfa1%>", &*p1_to_str(&params.vk.alpha_g1));
    let template = template.replace("<%vk_beta2%>", &*p2_to_str(&params.vk.beta_g2));
    let template = template.replace("<%vk_gamma2%>", &*p2_to_str(&params.vk.gamma_g2));
    let template = template.replace("<%vk_delta2%>", &*p2_to_str(&params.vk.delta_g2));

    let template = template.replace("<%vk_ic_length%>", &*params.vk.ic.len().to_string());
    let template = template.replace("<%vk_input_length%>", &*(params.vk.ic.len() - 1).to_string());

    let mut vi = String::from("");
    for i in 0..params.vk.ic.len() {
        vi = format!("{}{}vk.IC[{}] = Pairing.G1Point({});\n", vi, if vi.is_empty() { "" } else { "        " }, i, &*p1_to_str(&params.vk.ic[i]));
    }
    template.replace("<%vk_ic_pts%>", &*vi)
}

pub fn create_verifier_sol_file(params: &Parameters<Bn256>, filename: &str) -> std::io::Result<()> {
    fs::write(filename, create_verifier_sol(params).as_bytes())
}

pub fn proof_to_json(proof: &Proof<Bn256>) -> Result<String, serde_json::error::Error> {
    serde_json::to_string_pretty(&ProofJson {
        protocol: "groth".to_string(),
        proof: Some(proof_to_hex(&proof)),
        pi_a: p1_to_vec(&proof.a),
        pi_b: p2_to_vec(&proof.b),
        pi_c: p1_to_vec(&proof.c),
    })
}

pub fn proof_to_json_file(proof: &Proof<Bn256>, filename: &str) -> std::io::Result<()> {
    let str = proof_to_json(proof).unwrap(); // TODO: proper error handling
    fs::write(filename, str.as_bytes())
}

pub fn load_params_file(filename: &str) -> Parameters<Bn256> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    load_params(reader)
}

pub fn load_params<R: Read>(reader: R) -> Parameters<Bn256> {
    Parameters::read(reader, true).expect("unable to read params")
}

pub fn load_inputs_json_file<E: Engine>(filename: &str) -> Vec<E::Fr> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    load_inputs_json::<E, BufReader<File>>(BufReader::new(reader))
}

pub fn load_inputs_json<E: Engine, R: Read>(reader: R) -> Vec<E::Fr> {
    let inputs: Vec<String> = serde_json::from_reader(reader).unwrap();
    inputs.into_iter().map(|x| E::Fr::from_str(&x).unwrap()).collect::<Vec<E::Fr>>()
}

pub fn load_proof_json_file<E: Engine>(filename: &str) -> Proof<Bn256> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    load_proof_json(BufReader::new(reader))
}

pub fn load_proof_json<R: Read>(reader: R) -> Proof<Bn256> {
    let proof: ProofJson = serde_json::from_reader(reader).unwrap();
    Proof {
        a: G1Affine::from_xy_checked(
            Fq::from_str(&proof.pi_a[0]).unwrap(),
            Fq::from_str(&proof.pi_a[1]).unwrap(),
        ).unwrap(),
        b: G2Affine::from_xy_checked(
            Fq2 {
                c0: Fq::from_str(&proof.pi_b[0][0]).unwrap(),
                c1: Fq::from_str(&proof.pi_b[0][1]).unwrap(),
            },
            Fq2 {
                c0: Fq::from_str(&proof.pi_b[1][0]).unwrap(),
                c1: Fq::from_str(&proof.pi_b[1][1]).unwrap(),
            },
        ).unwrap(),
        c: G1Affine::from_xy_checked(
            Fq::from_str(&proof.pi_c[0]).unwrap(),
            Fq::from_str(&proof.pi_c[1]).unwrap(),
        ).unwrap(),
    }
}

pub fn filter_params<E: Engine>(params: &mut Parameters<E>) {
    params.vk.ic = params.vk.ic.clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>();
    params.h = Arc::new((*params.h).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());
    params.a = Arc::new((*params.a).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());
    params.b_g1 = Arc::new((*params.b_g1).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());
    params.b_g2 = Arc::new((*params.b_g2).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());
}

pub fn proving_key_json(params: &Parameters<Bn256>, circuit: CircomCircuit<Bn256>) -> Result<String, serde_json::error::Error> {
    let mut pols_a: Vec<BTreeMap<String, String>> = vec![];
    let mut pols_b: Vec<BTreeMap<String, String>> = vec![];
    let mut pols_c: Vec<BTreeMap<String, String>> = vec![];
    for _ in 0..circuit.r1cs.num_aux + circuit.r1cs.num_inputs {
        pols_a.push(BTreeMap::new());
        pols_b.push(BTreeMap::new());
        pols_c.push(BTreeMap::new());
    }
    for c in 0..circuit.r1cs.constraints.len() {
        for item in circuit.r1cs.constraints[c].0.iter() {
            pols_a[item.0].insert(c.to_string(), repr_to_big(item.1.into_repr()));
        }
        for item in circuit.r1cs.constraints[c].1.iter() {
            pols_b[item.0].insert(c.to_string(), repr_to_big(item.1.into_repr()));
        }
        for item in circuit.r1cs.constraints[c].2.iter() {
            pols_c[item.0].insert(c.to_string(), repr_to_big(item.1.into_repr()));
        }
    }

    for i in 0..circuit.r1cs.num_inputs {
        pols_a[i].insert((circuit.r1cs.constraints.len() + i).to_string(), String::from("1"));
    }

    let domain_bits = log2_floor(circuit.r1cs.constraints.len() + circuit.r1cs.num_inputs) + 1;
    let n_public = circuit.r1cs.num_inputs - 1;
    let n_vars = circuit.r1cs.num_variables;

    let p = prepare_prover(circuit).unwrap().assignment;
    let mut a_iter = params.a.iter();
    let mut b1_iter = params.b_g1.iter();
    let mut b2_iter = params.b_g2.iter();
    let zero1 = G1Affine::zero();
    let zero2 = G2Affine::zero();
    let a = repeat(true).take(params.vk.ic.len())
        .chain(p.a_aux_density.iter())
        .map(|item| if item { a_iter.next().unwrap() } else { &zero1 })
        .map(|e| p1_to_vec(e))
        .collect_vec();
    let b1 = p.b_input_density.iter()
        .chain(p.b_aux_density.iter())
        .map(|item| if item { b1_iter.next().unwrap() } else { &zero1 })
        .map(|e| p1_to_vec(e))
        .collect_vec();
    let b2 = p.b_input_density.iter()
        .chain(p.b_aux_density.iter())
        .map(|item| if item { b2_iter.next().unwrap() } else { &zero2 })
        .map(|e| p2_to_vec(e))
        .collect_vec();
    let c = repeat(None).take(params.vk.ic.len())
        .chain(params.l.iter().map(|e| Some(p1_to_vec(e))))
        .collect_vec();

    let proving_key = ProvingKeyJson {
        pols_a,
        pols_b,
        pols_c,
        a,
        b1,
        b2,
        c,
        vk_alfa_1: p1_to_vec(&params.vk.alpha_g1),
        vk_beta_1: p1_to_vec(&params.vk.beta_g1),
        vk_delta_1: p1_to_vec(&params.vk.delta_g1),
        vk_beta_2: p2_to_vec(&params.vk.beta_g2),
        vk_delta_2: p2_to_vec(&params.vk.delta_g2),
        h: params.h.iter().map(|e| p1_to_vec(e)).collect_vec(),
        protocol: String::from("groth"),
        n_public,
        n_vars,
        domain_bits,
        domain_size: 1 << domain_bits,
    };

    serde_json::to_string(&proving_key)
}

fn log2_floor(num: usize) -> usize {
    assert!(num > 0);
    let mut pow = 0;
    while (1 << (pow + 1)) <= num {
        pow += 1;
    }
    pow
}

pub fn proving_key_json_file(params: &Parameters<Bn256>, circuit: CircomCircuit<Bn256>, filename: &str) -> std::io::Result<()> {
    let str = proving_key_json(params, circuit).unwrap(); // TODO: proper error handling
    fs::write(filename, str.as_bytes())
}

pub fn verification_key_json(params: &Parameters<Bn256>) -> Result<String, serde_json::error::Error> {
    let verification_key = VerifyingKeyJson {
        ic: params.vk.ic.iter().map(|e| p1_to_vec(e)).collect_vec(),
        vk_alfa_1: p1_to_vec(&params.vk.alpha_g1),
        vk_beta_2: p2_to_vec(&params.vk.beta_g2),
        vk_gamma_2: p2_to_vec(&params.vk.gamma_g2),
        vk_delta_2: p2_to_vec(&params.vk.delta_g2),
        vk_alfabeta_12: pairing_to_vec(&Bn256::pairing(params.vk.alpha_g1, params.vk.beta_g2)),
        inputs_count: params.vk.ic.len() - 1,
        protocol: String::from("groth"),
    };
    serde_json::to_string_pretty(&verification_key)
}

pub fn verification_key_json_file(params: &Parameters<Bn256>, filename: &str) -> std::io::Result<()> {
    let str = verification_key_json(params).unwrap(); // TODO: proper error handling
    fs::write(filename, str.as_bytes())
}

pub fn witness_from_file<E: Engine>(filename: &str) -> Vec<E::Fr> {
    if filename.ends_with("json") {
        witness_from_json_file::<E>(filename)
    } else {
        witness_from_bin_file::<E>(filename)
    }
}

pub fn witness_from_json_file<E: Engine>(filename: &str) -> Vec<E::Fr> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    witness_from_json::<E, BufReader<File>>(BufReader::new(reader))
}

pub fn witness_from_json<E: Engine, R: Read>(reader: R) -> Vec<E::Fr> {
    let witness: Vec<String> = serde_json::from_reader(reader).unwrap();
    witness.into_iter().map(|x| E::Fr::from_str(&x).unwrap()).collect::<Vec<E::Fr>>()
}

pub fn witness_from_bin_file<E: Engine>(filename: &str) -> Vec<E::Fr> {
    let reader = OpenOptions::new().read(true).open(filename).expect("unable to open.");
    load_witness_from_bin_reader::<E, BufReader<File>>(BufReader::new(reader)).expect("read witness failed")
}

pub fn r1cs_from_json_file<E: Engine>(filename: &str) -> R1CS<E> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    r1cs_from_json(BufReader::new(reader))
}

pub fn r1cs_from_json<E: Engine, R: Read>(reader: R) -> R1CS<E> {
    let circuit_json: CircuitJson = serde_json::from_reader(reader).unwrap();

    let num_inputs = circuit_json.num_inputs + circuit_json.num_outputs + 1;
    let num_aux = circuit_json.num_variables - num_inputs;

    let convert_constraint = |lc: &BTreeMap<String, String>| {
        lc.iter().map(|(index, coeff)| (index.parse().unwrap(), E::Fr::from_str(coeff).unwrap())).collect_vec()
    };

    let constraints = circuit_json.constraints.iter().map(
        |c| (convert_constraint(&c[0]), convert_constraint(&c[1]), convert_constraint(&c[2]))
    ).collect_vec();

    R1CS {
        num_inputs,
        num_aux,
        num_variables: circuit_json.num_variables,
        constraints,
    }
}

pub fn r1cs_from_bin<R: Read>(reader: R) -> Result<(R1CS<Bn256>, Vec<usize>), std::io::Error> {
    let file = crate::r1cs_reader::read(reader)?;
    let num_inputs = (1 + file.header.n_pub_in + file.header.n_pub_out) as usize;
    let num_variables = file.header.n_wires as usize;
    let num_aux = num_variables - num_inputs;
    Ok((
        R1CS { num_aux, num_inputs, num_variables, constraints: file.constraints, },
        file.wire_mapping.iter().map(|e| *e as usize).collect_vec()
    ))
}

pub fn r1cs_from_bin_file(filename: &str) -> Result<(R1CS<Bn256>, Vec<usize>), std::io::Error> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    r1cs_from_bin(BufReader::new(reader))
}

pub fn create_rng() -> Box<dyn Rng> {
    Box::new(OsRng::new().unwrap())
}

fn load_witness_from_bin_reader<E: Engine, R: Read>(mut reader: R) -> Result<Vec<E::Fr>, anyhow::Error> {
    let mut wtns_header = [0u8; 4];
    reader.read_exact(&mut wtns_header)?;
    if wtns_header != [119, 116, 110, 115] {
        // ruby -e 'p "wtns".bytes' => [119, 116, 110, 115]
        bail!("invalid file header");
    }
    let version = reader.read_u32::<LittleEndian>()?;
    println!("wtns version {}", version);
    if version > 2 {
        bail!("unsupported file version");
    }
    let num_sections = reader.read_u32::<LittleEndian>()?;
    if num_sections != 2 {
        bail!("invalid num sections");
    }
    // read the first section
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 1 {
        bail!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != 4 + 32 + 4 {
        bail!("invalid section len")
    }
    let field_size = reader.read_u32::<LittleEndian>()?;
    if field_size != 32 {
        bail!("invalid field byte size");
    }
    let mut prime = vec![0u8; field_size as usize];
    reader.read_exact(&mut prime)?;
    if prime != hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430") {
        bail!("invalid curve prime");
    }
    let witness_len = reader.read_u32::<LittleEndian>()?;
    println!("witness len {}", witness_len);
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 2 {
        bail!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != (witness_len * field_size) as u64 {
        bail!("invalid witness section size {}", sec_size);
    }
    let mut result = Vec::with_capacity(witness_len as usize);
    for _ in 0..witness_len {
        let mut repr = E::Fr::zero().into_repr();
        repr.read_le(&mut reader)?;
        result.push(E::Fr::from_repr(repr)?);
    }
    Ok(result)
}
